// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
    LABEL_SANDBOX_NAMESPACE, supervisor_cache_path_with_base,
};
use openshell_core::progress::{
    PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
    PROGRESS_COMPLETE_STEP_KEY, PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX,
    PROGRESS_STEP_STARTING_SANDBOX,
};
use openshell_core::proto::compute::v1::{
    DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate, GpuResourceRequirements,
    ResourceRequirements,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

fn test_sandbox() -> DriverSandbox {
    // Mirrors the gateway-supplied request: the public `Sandbox` API no
    // longer carries `namespace`, so the gateway elides the field and the
    // driver must source it from its own runtime config.
    DriverSandbox {
        id: "sbx-123".to_string(),
        name: "demo".to_string(),
        namespace: String::new(),
        spec: Some(DriverSandboxSpec {
            log_level: "debug".to_string(),
            environment: HashMap::from([("SPEC_ENV".to_string(), "spec".to_string())]),
            template: Some(DriverSandboxTemplate {
                image: "ghcr.io/nvidia/openshell/sandbox:dev".to_string(),
                agent_socket_path: String::new(),
                labels: HashMap::new(),
                environment: HashMap::from([("TEMPLATE_ENV".to_string(), "template".to_string())]),
                ..Default::default()
            }),
            resource_requirements: None,
            sandbox_token: String::new(),
            command: Vec::new(),
            tty: false,
        }),
        status: None,
        workspace: String::new(),
    }
}

fn cdi_devices_config(device_ids: &[&str]) -> prost_types::Struct {
    list_string_driver_config("cdi_devices", device_ids)
}

fn cdi_device_typo_config(device_ids: &[&str]) -> prost_types::Struct {
    list_string_driver_config("cdi_device", device_ids)
}

fn list_string_driver_config(field: &str, values: &[&str]) -> prost_types::Struct {
    prost_types::Struct {
        fields: std::iter::once((
            field.to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: values
                            .iter()
                            .map(|device_id| prost_types::Value {
                                kind: Some(prost_types::value::Kind::StringValue(
                                    (*device_id).to_string(),
                                )),
                            })
                            .collect(),
                    },
                )),
            },
        ))
        .collect(),
    }
}

fn gpu_resources(count: Option<u32>) -> ResourceRequirements {
    ResourceRequirements {
        gpu: Some(GpuResourceRequirements { count }),
    }
}

fn runtime_config() -> DockerDriverRuntimeConfig {
    DockerDriverRuntimeConfig {
        socket_path: PathBuf::from("/var/run/docker.sock"),
        default_image: "image:latest".to_string(),
        image_pull_policy: String::new(),
        sandbox_namespace: "default".to_string(),
        grpc_endpoint: "https://localhost:8443".to_string(),
        stop_timeout_secs: DEFAULT_STOP_TIMEOUT_SECS,
        log_level: "info".to_string(),
        supervisor_bin: PathBuf::from("/tmp/openshell-sandbox"),
        guest_tls: Some(DockerGuestTlsPaths {
            ca: PathBuf::from("/tmp/ca.crt"),
            cert: PathBuf::from("/tmp/tls.crt"),
            key: PathBuf::from("/tmp/tls.key"),
        }),
        daemon_version: "28.0.0".to_string(),
        supports_gpu: false,
        allow_all_default_gpu: false,
    }
}

fn test_driver_with_config(config: DockerDriverRuntimeConfig) -> DockerComputeDriver {
    let allow_all_default_gpu = config.allow_all_default_gpu;
    DockerComputeDriver {
        docker: Arc::new(
            Docker::connect_with_http("http://127.0.0.1:2375", 1, bollard::API_DEFAULT_VERSION)
                .expect("construct test Docker client"),
        ),
        config,
        events: broadcast::channel(WATCH_BUFFER).0,
        pending: Arc::new(Mutex::new(HashMap::new())),
        gpu_selector: Arc::new(CdiGpuDefaultSelector::new(
            CdiGpuInventory::default(),
            allow_all_default_gpu,
        )),
        lifecycle_event_fences: DockerLifecycleEventFences::default(),
        host_supervisors: Arc::new(Mutex::new(HashMap::new())),
    }
}

#[tokio::test]
async fn tracing_in_process_service_preserves_the_driver_rpc_server_boundary() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::{Instrument as _, instrument::WithSubscriber as _};
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let gateway_exporter = InMemorySpanExporterBuilder::new().build();
    let gateway_provider = SdkTracerProvider::builder()
        .with_simple_exporter(gateway_exporter.clone())
        .build();
    let driver_exporter = InMemorySpanExporterBuilder::new().build();
    let driver_provider = SdkTracerProvider::builder()
        .with_simple_exporter(driver_exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer_excluding_target_prefix(
            &gateway_provider,
            "gateway-test",
            Some(otel_tracing::IN_PROCESS_TARGET_PREFIX),
        ))
        .with(otel_tracing::in_process_layer(&driver_provider));
    let service = ComputeDriverService::new_in_process(test_driver_with_config(runtime_config()));

    async {
        let gateway_span = tracing::info_span!(
            target: "openshell_server::compute",
            "driver",
            otel.name = "driver.get_capabilities",
            otel.kind = "client"
        );
        ComputeDriver::get_capabilities(&service, Request::new(GetCapabilitiesRequest {}))
            .instrument(gateway_span)
            .await?;

        let unrelated = tracing::info_span!(
            target: "openshell_driver_kubernetes::compute",
            "kubernetes.operation"
        );
        drop(unrelated.enter());
        drop(unrelated);
        Ok::<_, Status>(())
    }
    .with_subscriber(subscriber)
    .await
    .expect("capabilities should succeed");
    async {
        let gateway_span = tracing::info_span!(
            target: "openshell_server::compute",
            "driver",
            otel.name = "driver.validate_sandbox_create",
            otel.kind = "client"
        );
        ComputeDriver::validate_sandbox_create(
            &service,
            Request::new(ValidateSandboxCreateRequest { sandbox: None }),
        )
        .instrument(gateway_span)
        .await
    }
    .with_subscriber(
        tracing_subscriber::registry()
            .with(openshell_otel::layer_excluding_target_prefix(
                &gateway_provider,
                "gateway-test",
                Some(otel_tracing::IN_PROCESS_TARGET_PREFIX),
            ))
            .with(otel_tracing::in_process_layer(&driver_provider)),
    )
    .await
    .expect_err("missing sandbox should fail");
    gateway_provider.force_flush().unwrap();
    driver_provider.force_flush().unwrap();

    let gateway_spans = gateway_exporter.get_finished_spans().unwrap();
    let driver_spans = driver_exporter.get_finished_spans().unwrap();
    let client = gateway_spans
        .iter()
        .find(|span| span.name == "driver.get_capabilities")
        .unwrap();
    let server = driver_spans
        .iter()
        .find(|span| span.name == "driver.get_capabilities")
        .expect("in-process server span");
    assert_eq!(
        server.span_context.trace_id(),
        client.span_context.trace_id()
    );
    assert_eq!(server.parent_span_id, client.span_context.span_id());
    assert_eq!(server.span_kind, opentelemetry::trace::SpanKind::Server);
    assert!(server.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.grpc.status_code"
            && attribute.value.to_string() == (tonic::Code::Ok as i32).to_string()
    }));
    assert!(
        gateway_spans
            .iter()
            .any(|span| span.name == "kubernetes.operation"),
        "unrelated driver targets must remain gateway spans"
    );
    assert!(
        driver_spans
            .iter()
            .all(|span| span.name != "kubernetes.operation"),
        "the Docker provider must not claim unrelated driver spans"
    );
    let failed = driver_spans
        .iter()
        .find(|span| span.name == "driver.validate_sandbox_create")
        .expect("failed in-process server span");
    assert!(matches!(
        failed.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    assert!(failed.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.grpc.status_code"
            && attribute.value.to_string() == (tonic::Code::InvalidArgument as i32).to_string()
    }));
    gateway_provider.shutdown().unwrap();
    driver_provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_lifecycle_rpc_failures_export_docker_operation_spans() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::layer(&provider));
    let driver = test_driver_with_config(runtime_config());

    async {
        ComputeDriver::create_sandbox(
            &driver,
            Request::new(CreateSandboxRequest { sandbox: None }),
        )
        .await
        .expect_err("missing sandbox should fail");
        ComputeDriver::start_sandbox(&driver, Request::new(StartSandboxRequest::default()))
            .await
            .expect_err("missing start identifier should fail");
        ComputeDriver::stop_sandbox(&driver, Request::new(StopSandboxRequest::default()))
            .await
            .expect_err("missing stop identifier should fail");
        ComputeDriver::delete_sandbox(&driver, Request::new(DeleteSandboxRequest::default()))
            .await
            .expect_err("missing delete identifier should fail");
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    for name in [
        "docker.schedule_sandbox",
        "docker.start_sandbox",
        "docker.stop_sandbox",
        "docker.delete_sandbox",
    ] {
        let span = spans
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("{name} should be exported"));
        assert!(
            matches!(span.status, opentelemetry::trace::Status::Error { .. }),
            "{name} should record the failed operation"
        );
    }
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_direct_start_exports_a_docker_start_span() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::layer(&provider));
    let driver = test_driver_with_config(runtime_config());

    DockerComputeDriver::start_sandbox(&driver, "", "")
        .with_subscriber(subscriber)
        .await
        .expect_err("missing identifier should fail");
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "docker.start_sandbox")
        .expect("direct startup operation should export docker.start_sandbox");
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_image_preparation_failure_exports_nested_failed_spans() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::layer(&provider));
    let mut config = runtime_config();
    config.image_pull_policy = "unsupported".to_string();
    let driver = test_driver_with_config(config);

    driver
        .provision_sandbox_inner(&test_sandbox())
        .with_subscriber(subscriber)
        .await
        .expect_err("unsupported image pull policy should fail provisioning");
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let provision = spans
        .iter()
        .find(|span| span.name == "docker.provision_sandbox")
        .expect("provisioning span should be exported");
    assert!(matches!(
        provision.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    let prepare_image = spans
        .iter()
        .find(|span| span.name == "docker.prepare_image")
        .expect("image preparation span should be exported");
    assert_eq!(
        prepare_image.parent_span_id,
        provision.span_context.span_id()
    );
    assert!(matches!(
        prepare_image.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn background_provisioning_does_not_extend_the_scheduling_span_lifetime() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::Instrument as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::layer(&provider));
    let dispatch = tracing::Dispatch::new(subscriber);
    let _dispatch = tracing::dispatcher::set_default(&dispatch);

    let scheduling = tracing::info_span!("docker.schedule_sandbox");
    let entered = scheduling.enter();
    let sandbox = test_sandbox();
    let provisioning = provisioning_span(&scheduling.context(), &sandbox, "test-image");
    let task = tokio::spawn(futures::future::pending::<()>().instrument(provisioning));
    drop(entered);
    drop(scheduling);
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    assert!(
        spans
            .iter()
            .any(|span| span.name == "docker.schedule_sandbox"),
        "the scheduling span should finish while background provisioning is pending"
    );
    assert!(
        spans.iter().all(|span| span.name != "docker.provision"),
        "the provisioning span should remain open with the background task"
    );

    task.abort();
    task.await
        .expect_err("the pending task should be cancelled");
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_in_process_stream_span_lives_until_stream_failure() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::in_process_layer(&provider));

    async {
        let span = tracing::info_span!(
            target: "openshell_driver_docker::otel_tracing",
            "driver_rpc",
            otel.name = "driver.watch_sandboxes",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.grpc.status_code = tracing::field::Empty,
        );
        let inner: WatchStream = Box::pin(futures::stream::iter([Err(Status::internal(
            "watch failed",
        ))]));
        let mut stream = TracedWatchStream {
            inner,
            span,
            finished: false,
        };

        provider.force_flush().unwrap();
        assert!(
            exporter.get_finished_spans().unwrap().is_empty(),
            "server span must remain open while the response stream is alive"
        );
        stream
            .next()
            .await
            .expect("stream item")
            .expect_err("stream should fail");
        drop(stream);
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "driver.watch_sandboxes")
        .expect("watch server span should be exported when the stream ends");
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_in_process_stream_records_ok_when_stream_completes() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::in_process_layer(&provider));

    async {
        let span = tracing::info_span!(
            target: "openshell_driver_docker::otel_tracing",
            "driver_rpc",
            otel.name = "driver.watch_sandboxes",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.grpc.status_code = tracing::field::Empty,
        );
        let inner: WatchStream = Box::pin(futures::stream::empty());
        let mut stream = TracedWatchStream {
            inner,
            span,
            finished: false,
        };

        assert!(stream.next().await.is_none());
        drop(stream);
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "driver.watch_sandboxes")
        .expect("watch server span should be exported when the stream completes");
    assert!(span.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.grpc.status_code"
            && attribute.value.to_string() == (tonic::Code::Ok as i32).to_string()
    }));
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn tracing_in_process_stream_records_cancelled_when_dropped() {
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let _tracing_lock = otel_tracing::test_lock().await;
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(otel_tracing::in_process_layer(&provider));

    async {
        let span = tracing::info_span!(
            target: "openshell_driver_docker::otel_tracing",
            "driver_rpc",
            otel.name = "driver.watch_sandboxes",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            rpc.grpc.status_code = tracing::field::Empty,
        );
        let inner: WatchStream = Box::pin(futures::stream::pending());
        let stream = TracedWatchStream {
            inner,
            span,
            finished: false,
        };

        drop(stream);
    }
    .with_subscriber(subscriber)
    .await;
    provider.force_flush().unwrap();

    let spans = exporter.get_finished_spans().unwrap();
    let span = spans
        .iter()
        .find(|span| span.name == "driver.watch_sandboxes")
        .expect("watch server span should be exported when the stream is cancelled");
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    assert!(span.attributes.iter().any(|attribute| {
        attribute.key.as_str() == "rpc.grpc.status_code"
            && attribute.value.to_string() == (tonic::Code::Cancelled as i32).to_string()
    }));
    provider.shutdown().unwrap();
}

#[test]
fn parse_cpu_limit_supports_cores_and_millicores() {
    assert_eq!(parse_cpu_limit("250m").unwrap(), Some(250_000_000));
    assert_eq!(parse_cpu_limit("2").unwrap(), Some(2_000_000_000));
    assert!(parse_cpu_limit("0").is_err());
}

#[test]
fn parse_memory_limit_supports_binary_quantities() {
    assert_eq!(parse_memory_limit("512Mi").unwrap(), Some(536_870_912));
    assert_eq!(parse_memory_limit("1G").unwrap(), Some(1_000_000_000));
    assert!(parse_memory_limit("12XB").is_err());
}

#[test]
fn docker_resource_limits_rejects_requests() {
    let template = DriverSandboxTemplate {
        image: "img".to_string(),
        agent_socket_path: String::new(),
        labels: HashMap::new(),
        environment: HashMap::new(),
        resources: Some(DriverResourceRequirements {
            cpu_request: "250m".to_string(),
            cpu_limit: String::new(),
            memory_request: String::new(),
            memory_limit: String::new(),
        }),
        ..Default::default()
    };

    let err = docker_resource_limits(&template).unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("resources.requests.cpu"));
}

#[test]
fn docker_resource_limits_applies_cpu_and_memory_limits() {
    let template = DriverSandboxTemplate {
        image: "img".to_string(),
        agent_socket_path: String::new(),
        labels: HashMap::new(),
        environment: HashMap::new(),
        resources: Some(DriverResourceRequirements {
            cpu_limit: "500m".to_string(),
            memory_limit: "2Gi".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };

    let limits = docker_resource_limits(&template).unwrap();
    assert_eq!(limits.nano_cpus, Some(500_000_000));
    assert_eq!(limits.memory_bytes, Some(2_147_483_648));
}

#[test]
fn managed_container_label_filters_include_gateway_namespace() {
    let filters =
        managed_container_label_filters("tenant-a", [format!("{LABEL_SANDBOX_ID}=sbx-123")]);
    let labels = filters.get("label").unwrap();

    assert!(labels.contains(&format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}")));
    assert!(labels.contains(&format!("{LABEL_SANDBOX_NAMESPACE}=tenant-a")));
    assert!(labels.contains(&format!("{LABEL_SANDBOX_ID}=sbx-123")));
}

#[test]
fn validate_sandbox_rejects_gpu_when_cdi_unavailable() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(None));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("Docker CDI"));
}

#[test]
fn validate_sandbox_rejects_missing_gpu_support_before_request_shape() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("Docker CDI"));
}

#[test]
fn validate_sandbox_rejects_invalid_cdi_devices_before_gpu_capability() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("invalid docker driver_config"));
    assert!(err.message().contains("non-empty list"));
}

#[test]
fn validate_sandbox_rejects_unknown_driver_config_fields() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config =
        Some(cdi_device_typo_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("unknown field"));
}

#[test]
fn validate_sandbox_accepts_gpu_count_request_shape() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().resource_requirements = Some(gpu_resources(Some(2)));

    DockerComputeDriver::validate_sandbox(&sandbox, &config)
        .expect("default GPU count shape should be accepted before inventory selection");
}

#[test]
fn validate_sandbox_accepts_gpu_count_matching_cdi_devices() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[
        "nvidia.com/gpu=0",
        "nvidia.com/gpu=1",
    ]));

    DockerComputeDriver::validate_sandbox(&sandbox, &config)
        .expect("matching explicit CDI device count should be accepted");
}

#[test]
fn validate_sandbox_accepts_single_cdi_device_without_gpu_count() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    DockerComputeDriver::validate_sandbox(&sandbox, &config)
        .expect("single exact CDI device should be compatible with a default GPU request");
}

#[test]
fn validate_sandbox_rejects_multiple_cdi_devices_without_gpu_count() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&[
        "nvidia.com/gpu=0",
        "nvidia.com/gpu=1",
    ]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("gpu count (1) must match driver_config.cdi_devices length (2)")
    );
}

#[test]
fn validate_sandbox_rejects_cdi_devices_without_gpu_request() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    sandbox
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("requires a gpu request"));
}

#[test]
fn validate_sandbox_rejects_gpu_count_mismatched_cdi_devices() {
    let mut config = runtime_config();
    config.supports_gpu = true;
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(Some(2)));
    spec.template.as_mut().unwrap().driver_config = Some(cdi_devices_config(&["nvidia.com/gpu=0"]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("gpu count (2) must match driver_config.cdi_devices length (1)")
    );
}

#[test]
fn validate_sandbox_rejects_template_errors_before_device_config() {
    let config = runtime_config();
    let mut sandbox = test_sandbox();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.resource_requirements = Some(gpu_resources(None));
    let template = spec.template.as_mut().unwrap();
    template.agent_socket_path = "/tmp/agent.sock".to_string();
    template.driver_config = Some(cdi_devices_config(&[]));

    let err = DockerComputeDriver::validate_sandbox(&sandbox, &config).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("agent_socket_path"));
}

#[test]
fn validate_sandbox_auth_requires_gateway_token() {
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().sandbox_token.clear();

    let err = DockerComputeDriver::validate_sandbox_auth(&sandbox).unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        err.message(),
        "docker sandboxes require gateway JWT auth; configure [openshell.gateway.gateway_jwt]"
    );
}

#[test]
fn validate_sandbox_auth_accepts_gateway_token() {
    let mut sandbox = test_sandbox();
    sandbox.spec.as_mut().unwrap().sandbox_token = "secret.jwt.value".to_string();

    DockerComputeDriver::validate_sandbox_auth(&sandbox).unwrap();
}

#[test]
fn docker_info_reports_wsl2_from_kernel_version() {
    let info = SystemInfo {
        kernel_version: Some("5.15.153.1-microsoft-standard-WSL2".to_string()),
        operating_system: Some("Docker Desktop".to_string()),
        ..Default::default()
    };

    assert!(docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_from_operating_system() {
    let info = SystemInfo {
        operating_system: Some("Ubuntu 24.04.4 LTS on WSL2".to_string()),
        ..Default::default()
    };

    assert!(docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_ignores_daemon_name_and_labels() {
    let info = SystemInfo {
        kernel_version: Some("6.8.0-60-generic".to_string()),
        operating_system: Some("Ubuntu 24.04.4 LTS".to_string()),
        name: Some("wsl-docker-daemon".to_string()),
        labels: Some(vec!["com.example.platform=wsl2".to_string()]),
        ..Default::default()
    };

    assert!(!docker_info_reports_wsl2(&info));
}

#[test]
fn docker_info_reports_wsl2_rejects_plain_linux() {
    let info = SystemInfo {
        kernel_version: Some("6.8.0-60-generic".to_string()),
        operating_system: Some("Ubuntu 24.04.4 LTS".to_string()),
        os_type: Some("linux".to_string()),
        architecture: Some("x86_64".to_string()),
        ..Default::default()
    };

    assert!(!docker_info_reports_wsl2(&info));
}

#[test]
fn require_sandbox_identifier_rejects_when_id_and_name_are_empty() {
    // Regression test: `delete_sandbox` (and the other identifier-keyed
    // RPCs) must refuse requests where both the id and the name are
    // empty. Otherwise the empty filters fed to
    // `find_managed_container_summary` match the first managed container
    // in the namespace, allowing an arbitrary sandbox to be deleted.
    let err = require_sandbox_identifier("", "").unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("sandbox_id or sandbox_name"));

    require_sandbox_identifier("sbx-1", "").expect("id-only is accepted");
    require_sandbox_identifier("", "demo").expect("name-only is accepted");
    require_sandbox_identifier("sbx-1", "demo").expect("id and name is accepted");
}

#[test]
fn driver_status_keeps_running_sandboxes_provisioning_with_stable_message() {
    let running = ContainerSummary {
        id: Some("cid".to_string()),
        names: Some(vec!["/openshell-demo".to_string()]),
        labels: Some(HashMap::from([
            (LABEL_SANDBOX_ID.to_string(), "sbx-1".to_string()),
            (LABEL_SANDBOX_NAME.to_string(), "demo".to_string()),
            (LABEL_SANDBOX_NAMESPACE.to_string(), "default".to_string()),
        ])),
        state: Some(ContainerSummaryStateEnum::RUNNING),
        status: Some("Up 2 seconds".to_string()),
        ..Default::default()
    };
    let exited = ContainerSummary {
        state: Some(ContainerSummaryStateEnum::EXITED),
        status: Some("Exited (1) 3 seconds ago".to_string()),
        ..running.clone()
    };
    let running_later = ContainerSummary {
        status: Some("Up 4 seconds".to_string()),
        ..running.clone()
    };

    // A running container always emits Ready=True with BackendReady. The gateway
    // composes this with supervisor-session presence to decide public SandboxPhase.
    let running_status = driver_status_from_summary(&running, "demo");
    let running_later_status = driver_status_from_summary(&running_later, "demo");
    assert_eq!(running_status.conditions[0].status, "True");
    assert_eq!(running_status.conditions[0].reason, "BackendReady");
    assert_eq!(running_status.conditions[0].message, "Container is running");
    assert_eq!(running_status.conditions, running_later_status.conditions);

    let exited_status = driver_status_from_summary(&exited, "demo");
    assert_eq!(exited_status.conditions[0].status, "False");
    assert_eq!(exited_status.conditions[0].reason, "ContainerExited");
    assert_eq!(exited_status.conditions[0].message, "Container exited");
}

#[test]
fn driver_status_marks_restarting_sandboxes_as_error() {
    let restarting = ContainerSummary {
        id: Some("cid".to_string()),
        names: Some(vec!["/openshell-demo".to_string()]),
        labels: Some(HashMap::from([
            (LABEL_SANDBOX_ID.to_string(), "sbx-1".to_string()),
            (LABEL_SANDBOX_NAME.to_string(), "demo".to_string()),
            (LABEL_SANDBOX_NAMESPACE.to_string(), "default".to_string()),
        ])),
        state: Some(ContainerSummaryStateEnum::RESTARTING),
        status: Some("Restarting (1) 2 seconds ago".to_string()),
        ..Default::default()
    };

    let status = driver_status_from_summary(&restarting, "demo");
    assert_eq!(status.conditions[0].status, "False");
    assert_eq!(status.conditions[0].reason, "ContainerRestarting");
    assert_eq!(
        status.conditions[0].message,
        "Container is restarting after a failure"
    );
}

#[test]
fn docker_scheduled_event_adds_progress_metadata() {
    let mut metadata = HashMap::from([(
        "image_ref".to_string(),
        "ghcr.io/acme/sandbox:latest".to_string(),
    )]);

    attach_docker_progress_metadata(
        &mut metadata,
        "Scheduled",
        "Docker sandbox accepted for image \"ghcr.io/acme/sandbox:latest\"",
    );

    assert_eq!(
        metadata.get(PROGRESS_COMPLETE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_REQUESTING_SANDBOX)
    );
    assert_eq!(
        metadata
            .get(PROGRESS_COMPLETE_LABEL_KEY)
            .map(String::as_str),
        Some("Sandbox allocated")
    );
    assert_eq!(
        metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_PULLING_IMAGE)
    );
    assert_eq!(
        metadata.get(PROGRESS_ACTIVE_DETAIL_KEY).map(String::as_str),
        Some("ghcr.io/acme/sandbox:latest")
    );
}

#[test]
fn docker_pulled_event_advances_to_starting_progress() {
    let mut metadata = HashMap::new();

    attach_docker_progress_metadata(
        &mut metadata,
        "Pulled",
        "Pulled Docker image \"ghcr.io/acme/sandbox:latest\"",
    );

    assert_eq!(
        metadata.get(PROGRESS_COMPLETE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_PULLING_IMAGE)
    );
    assert_eq!(
        metadata
            .get(PROGRESS_COMPLETE_LABEL_KEY)
            .map(String::as_str),
        Some("Image pulled")
    );
    assert_eq!(
        metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
        Some(PROGRESS_STEP_STARTING_SANDBOX)
    );
}

#[test]
fn docker_pull_progress_event_adds_layer_detail_metadata() {
    let event = docker_pull_progress_event(
        "ghcr.io/acme/sandbox:latest",
        &CreateImageInfo {
            id: Some("layer-1".to_string()),
            status: Some("Downloading".to_string()),
            progress_detail: Some(ProgressDetail {
                current: Some(42 * 1024 * 1024),
                total: Some(84 * 1024 * 1024),
            }),
            ..Default::default()
        },
    )
    .expect("pull progress event");

    assert_eq!(event.source, "docker");
    assert_eq!(event.reason, "PullingLayer");
    assert_eq!(
        event
            .metadata
            .get(PROGRESS_ACTIVE_STEP_KEY)
            .map(String::as_str),
        Some(PROGRESS_STEP_PULLING_IMAGE)
    );
    assert_eq!(
        event
            .metadata
            .get(PROGRESS_ACTIVE_DETAIL_KEY)
            .map(String::as_str),
        Some("Downloading layer-1 (42 MB/84 MB)")
    );
}

#[test]
fn pending_sandbox_snapshot_uses_docker_namespace_and_starting_condition() {
    let sandbox = test_sandbox();

    let snapshot =
        pending_sandbox_snapshot(&sandbox, "docker-dev", provisioning_condition(), false);

    assert_eq!(snapshot.id, "sbx-123");
    assert_eq!(snapshot.name, "demo");
    assert_eq!(snapshot.namespace, "docker-dev");
    assert!(snapshot.spec.is_none());
    assert!(pending_sandbox_matches(&snapshot, "sbx-123", ""));
    assert!(pending_sandbox_matches(&snapshot, "", "demo"));

    let status = snapshot.status.expect("status");
    assert!(!status.deleting);
    assert_eq!(status.sandbox_name, "demo");
    assert_eq!(status.conditions.len(), 1);
    assert_eq!(status.conditions[0].r#type, "Ready");
    assert_eq!(status.conditions[0].status, "False");
    assert_eq!(status.conditions[0].reason, "Starting");
    assert_eq!(status.conditions[0].message, "Docker container is starting");
}

#[test]
fn validate_linux_elf_binary_rejects_non_elf_files() {
    let tempdir = TempDir::new().unwrap();
    let path = tempdir.path().join("openshell-sandbox");
    fs::write(&path, b"not-elf").unwrap();

    let err = validate_linux_elf_binary(&path).unwrap_err();
    assert!(err.contains("Linux ELF executable"));
}

#[test]
fn docker_guest_tls_paths_require_all_files_for_https() {
    let tempdir = TempDir::new().unwrap();
    let ca = tempdir.path().join("ca.crt");
    fs::write(&ca, b"ca").unwrap();

    let err = docker_guest_tls_paths(&DockerComputeConfig {
        grpc_endpoint: "https://localhost:8443".to_string(),
        guest_tls_ca: Some(ca),
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("guest_tls_cert"));
}

#[test]
fn linux_supervisor_candidates_follow_daemon_arch() {
    assert_eq!(
        linux_supervisor_candidates("amd64"),
        vec![PathBuf::from(
            "target/x86_64-unknown-linux-gnu/release/openshell-sandbox",
        )]
    );
    assert_eq!(
        linux_supervisor_candidates("arm64"),
        vec![PathBuf::from(
            "target/aarch64-unknown-linux-gnu/release/openshell-sandbox",
        )]
    );
}

#[test]
fn container_name_preserves_id_suffix_for_long_names() {
    // Names up to 253 chars are permitted by the gRPC layer. The id
    // suffix is what makes the container name unique between sandboxes
    // sharing a prefix, so it must always appear in the final name.
    let long_name = "a".repeat(253);
    let first = DriverSandbox {
        id: "sbx-first-1234567890".to_string(),
        name: long_name,
        namespace: "default".to_string(),
        spec: None,
        status: None,
        workspace: "default".to_string(),
    };
    let second = DriverSandbox {
        id: "sbx-second-0987654321".to_string(),
        ..first.clone()
    };

    let first_container = container_name_for_sandbox(&first);
    let second_container = container_name_for_sandbox(&second);

    assert!(
        first_container.len() <= MAX_CONTAINER_NAME_LEN,
        "container name {} exceeded {MAX_CONTAINER_NAME_LEN} chars: {first_container}",
        first_container.len(),
    );
    assert!(
        first_container.ends_with(&first.id),
        "container name should end with sandbox id: {first_container}",
    );
    assert_ne!(
        first_container, second_container,
        "container names must differ for sandboxes with distinct ids",
    );
}

#[test]
fn container_name_empty_sandbox_name_uses_workspace_and_id() {
    let sandbox = DriverSandbox {
        id: "sbx-abc".to_string(),
        name: String::new(),
        namespace: "default".to_string(),
        spec: None,
        status: None,
        workspace: "default".to_string(),
    };
    assert_eq!(
        container_name_for_sandbox(&sandbox),
        "openshell-default---sbx-abc",
    );
}

#[test]
fn trim_container_name_tail_strips_separators() {
    assert_eq!(trim_container_name_tail("foo-".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo-.".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo_-.".to_string()), "foo");
    assert_eq!(trim_container_name_tail("foo".to_string()), "foo");
}

#[test]
fn docker_guest_tls_paths_rejects_tls_flags_without_https() {
    let tempdir = TempDir::new().unwrap();
    let ca = tempdir.path().join("ca.crt");
    fs::write(&ca, b"ca").unwrap();

    let err = docker_guest_tls_paths(&DockerComputeConfig {
        grpc_endpoint: "http://localhost:8080".to_string(),
        guest_tls_ca: Some(ca),
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.to_string().contains("https://"));
}

#[test]
fn docker_guest_tls_paths_allows_plain_http_without_tls_flags() {
    let result = docker_guest_tls_paths(&DockerComputeConfig {
        grpc_endpoint: "http://localhost:8080".to_string(),
        ..Default::default()
    })
    .unwrap();
    assert!(result.is_none());
}

#[test]
fn default_docker_supervisor_image_uses_nvidia_ghcr_repo() {
    let image = openshell_core::config::default_supervisor_image();
    assert!(
        image.starts_with("ghcr.io/nvidia/openshell/supervisor:"),
        "unexpected default image reference: {image}",
    );
}

#[test]
fn configured_supervisor_image_takes_precedence_over_local_binaries() {
    let tempdir = TempDir::new().unwrap();
    let bin_dir = tempdir.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let current_exe = bin_dir.join("openshell-gateway");
    let sibling = bin_dir.join("openshell-sandbox");
    fs::write(&current_exe, b"gateway").unwrap();
    fs::write(&sibling, b"\x7fELFsibling").unwrap();

    let local_build = tempdir.path().join("target/openshell-sandbox");
    fs::create_dir_all(local_build.parent().unwrap()).unwrap();
    fs::write(&local_build, b"\x7fELFlocal").unwrap();

    let source = resolve_supervisor_bin_source(
        &DockerComputeConfig {
            supervisor_image: Some("example.com/openshell/supervisor:test".to_string()),
            ..Default::default()
        },
        Some(&current_exe),
        &[local_build],
    )
    .unwrap();

    assert_eq!(
        source,
        SupervisorBinSource::Image("example.com/openshell/supervisor:test".to_string())
    );
}

#[test]
fn docker_supervisor_image_tag_prefers_explicit_build_tags() {
    use openshell_core::config::resolve_supervisor_image_tag;
    assert_eq!(
        resolve_supervisor_image_tag(&["1.2.3", "sha", "0.0.0"]),
        "1.2.3"
    );
    assert_eq!(resolve_supervisor_image_tag(&["", "sha", "0.0.0"]), "sha");
    assert_eq!(resolve_supervisor_image_tag(&["", "", "1.2.3"]), "1.2.3");
    assert_eq!(resolve_supervisor_image_tag(&["", "", "0.0.0"]), "dev");
}

#[test]
fn docker_supervisor_image_tag_sanitizes_build_metadata_for_docker() {
    use openshell_core::config::resolve_supervisor_image_tag;
    assert_eq!(
        resolve_supervisor_image_tag(&["", "", "0.0.37-dev.156+g1d3b741ee"]),
        "0.0.37-dev.156-g1d3b741ee",
    );
    assert_eq!(
        resolve_supervisor_image_tag(&["0.0.37-dev.156+g1d3b741ee", "", "0.0.0"]),
        "0.0.37-dev.156-g1d3b741ee",
    );
}

#[test]
fn docker_supervisor_image_refreshes_mutable_tags_only() {
    assert!(supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor:dev"
    ));
    assert!(supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor:latest"
    ));
    assert!(supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor"
    ));
    assert!(!supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor:0.0.47-dev.13-g57b71c68f"
    ));
    assert!(!supervisor_image_should_refresh(
        "ghcr.io/nvidia/openshell/supervisor@sha256:abc123"
    ));
}

#[test]
fn supervisor_cache_path_namespaces_by_digest_under_openshell_data_dir() {
    let base = PathBuf::from("/var/cache/share");
    let path = supervisor_cache_path_with_base(
        &base,
        "docker-supervisor",
        "sha256:abc123deadbeef0123456789cafe0123456789fe",
    );

    assert_eq!(
        path,
        PathBuf::from(
            "/var/cache/share/openshell/docker-supervisor/sha256-abc123deadbeef0123456789cafe0123456789fe/openshell-sandbox",
        ),
    );
}

#[test]
fn supervisor_cache_path_isolates_different_digests() {
    let base = PathBuf::from("/data");
    let left = supervisor_cache_path_with_base(&base, "docker-supervisor", "sha256:aaaaaaaa");
    let right = supervisor_cache_path_with_base(&base, "docker-supervisor", "sha256:bbbbbbbb");
    assert_ne!(
        left.parent().unwrap(),
        right.parent().unwrap(),
        "digest-keyed directories must differ so rollouts are isolated",
    );
}

#[test]
fn write_cache_binary_atomic_materializes_file_with_executable_mode() {
    let tempdir = TempDir::new().unwrap();
    let target = tempdir.path().join("nested").join("openshell-sandbox");
    fs::create_dir_all(target.parent().unwrap()).unwrap();

    write_cache_binary_atomic(&target, b"\x7fELFpayload").unwrap();

    assert!(target.is_file());
    assert_eq!(fs::read(&target).unwrap(), b"\x7fELFpayload");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0755, got {mode:04o}");
    }
}

#[test]
fn write_cache_binary_atomic_overwrites_existing_file() {
    let tempdir = TempDir::new().unwrap();
    let target = tempdir.path().join("openshell-sandbox");
    fs::write(&target, b"stale").unwrap();

    write_cache_binary_atomic(&target, b"\x7fELFfresh").unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"\x7fELFfresh");
}

#[test]
fn temp_extract_container_names_are_unique_per_call() {
    let first = temp_extract_container_name();
    let second = temp_extract_container_name();
    assert_ne!(first, second);
    assert!(first.starts_with("openshell-supervisor-extract-"));
}

#[test]
fn extract_first_tar_entry_returns_payload_of_single_file_archive() {
    // Build a tar archive with the same shape Docker returns from
    // `/containers/<id>/archive` for a single file.
    let payload = b"\x7fELFtest-binary-bytes";
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        header.set_path("openshell-sandbox").unwrap();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, payload.as_slice()).unwrap();
        builder.finish().unwrap();
    }

    let extracted = extract_first_tar_entry(&tar_buf).unwrap();
    assert_eq!(extracted, payload);
}

#[test]
fn extract_first_tar_entry_rejects_empty_archive() {
    let mut tar_buf = Vec::new();
    tar::Builder::new(&mut tar_buf).finish().unwrap();
    let err = extract_first_tar_entry(&tar_buf).unwrap_err();
    assert!(err.contains("empty"), "unexpected error message: {err}");
}

#[test]
fn container_state_needs_start_matches_startable_states() {
    for state in [
        ContainerSummaryStateEnum::EXITED,
        ContainerSummaryStateEnum::CREATED,
    ] {
        assert!(
            container_state_needs_start(state),
            "{state:?} should be started with Docker start",
        );
    }

    for state in [
        ContainerSummaryStateEnum::RUNNING,
        ContainerSummaryStateEnum::RESTARTING,
        ContainerSummaryStateEnum::PAUSED,
        ContainerSummaryStateEnum::DEAD,
        ContainerSummaryStateEnum::REMOVING,
        ContainerSummaryStateEnum::EMPTY,
    ] {
        assert!(
            !container_state_needs_start(state),
            "{state:?} should not be started with Docker start",
        );
    }
}

#[test]
fn lifecycle_fence_rejects_polled_exit_from_before_restart() {
    let fences = DockerLifecycleEventFences::default();
    fences.begin_start("sandbox-1");
    assert!(fences.start_in_progress("sandbox-1"));
    fences.finish_start("sandbox-1");
    assert!(!fences.start_in_progress("sandbox-1"));

    fences.record_previous_exit("sandbox-1", Some("2026-08-12T16:39:13Z"));
    assert_eq!(
        fences.previous_exit("sandbox-1").as_deref(),
        Some("2026-08-12T16:39:13Z")
    );

    let previous_exit = ContainerState {
        status: Some(ContainerStateStatusEnum::EXITED),
        finished_at: Some("2026-08-12T16:39:13Z".to_string()),
        ..Default::default()
    };
    assert!(docker_polled_exit_is_stale(
        "2026-08-12T16:39:13Z",
        Some(&previous_exit),
    ));

    let running = ContainerState {
        status: Some(ContainerStateStatusEnum::RUNNING),
        ..previous_exit.clone()
    };
    assert!(docker_polled_exit_is_stale(
        "2026-08-12T16:39:13Z",
        Some(&running),
    ));

    let new_exit = ContainerState {
        finished_at: Some("2026-08-12T16:40:00Z".to_string()),
        ..previous_exit
    };
    assert!(!docker_polled_exit_is_stale(
        "2026-08-12T16:39:13Z",
        Some(&new_exit),
    ));

    fences.remove("sandbox-1");
    assert!(fences.previous_exit("sandbox-1").is_none());
}
