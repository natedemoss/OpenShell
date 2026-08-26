// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-created Docker isolation boundary.
//!
//! The workload has no Docker network. OCI seccomp user notification injects
//! supervisor-owned sockets and transports DNS and transparent TCP through the
//! RFC 0012 mediation sources without an in-container `OpenShell` process.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{IoSliceMut, Read as _, Write as _};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::errors::Error as BollardError;
use bollard::exec::{CreateExecOptions, ResizeExecOptions, StartExecOptions, StartExecResults};
use bollard::models::{
    ContainerCreateBody, ContainerStateStatusEnum, ContainerWaitResponse, HostConfig,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, KillContainerOptionsBuilder, RemoveContainerOptionsBuilder,
};
use futures::StreamExt as _;
use nix::cmsg_space;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use openshell_core::driver_utils::{LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID};
use openshell_isolation::contract::{
    BackendError, BinaryIdentity, BoundBoundary, BoundaryDuplexStream, BoundaryExec,
    BoundaryExitStatus, BoundaryInput, BoundaryOutput, BoundaryPortForward, BoundaryProcess,
    BoundarySignal, BoundaryTerminal, CreatedBoundary, DnsMediationSource, DnsTransport,
    ExecSession, ExecSpec, INTERFACE_VERSION, IsolationBackend, LoopbackTarget, MediatedConnection,
    MediatedDnsQuery, NetworkMediationSource, ReadyBoundary, ResolveError, RunningBoundary,
    SandboxContext, TopologyDescriptor, VerifiedBoundaryCreatePlan, VerifiedTopologyDescriptor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{Mutex, mpsc, oneshot};

const BACKEND_NAME: &str = "docker";
pub const DOCKER_SOCKET_ENV: &str = "OPENSHELL_DOCKER_SOCKET_PATH";
pub const DOCKER_LISTENER_DIR_ENV: &str = "OPENSHELL_DOCKER_LISTENER_DIR";
const CONTAINER_TLS_DIR: &str = "/etc/openshell-tls";
const LISTENER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OCI_STATE_BYTES: usize = 128 * 1024;
const LABEL_LAUNCH_GENERATION: &str = "ai.openshell.prototype.launch-generation";
const LABEL_EXPERIMENTAL: &str = "ai.openshell.prototype.isolation";
const LABEL_PLAN_FINGERPRINT: &str = "ai.openshell.prototype.create-plan";
const MIN_LISTENER_TOKEN_BYTES: usize = 32;

/// Prepared inputs for the Docker creation path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerBoundaryCreatePlan {
    /// Resolved image ID or immutable image reference.
    pub image: String,
    /// Stable generation used with sandbox ID as the create idempotency key.
    pub launch_generation: String,
    /// Driver-generated secret stable for idempotent retries of this launch.
    pub listener_token: String,
    /// Stable compute-driver-selected container name.
    pub container_name: String,
    /// Trusted labels used by compute-driver discovery and ownership checks.
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Environment passed directly to the admitted agent.
    #[serde(default)]
    pub env: Vec<String>,
    /// Optional container user. The image default is used when absent.
    pub user: Option<String>,
}

impl fmt::Debug for DockerBoundaryCreatePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerBoundaryCreatePlan")
            .field("image", &self.image)
            .field("launch_generation", &self.launch_generation)
            .field("listener_token", &"<redacted>")
            .field("env", &self.env)
            .field("user", &self.user)
            .finish()
    }
}

impl DockerBoundaryCreatePlan {
    /// Encode this backend-private plan into the common RFC envelope.
    pub fn into_boundary_plan(
        self,
    ) -> Result<openshell_isolation::contract::BoundaryCreatePlan, BackendError> {
        let payload = serde_json::to_vec(&self).map_err(|error| {
            BackendError::Descriptor(format!("encode Docker create plan: {error}"))
        })?;
        Ok(openshell_isolation::contract::BoundaryCreatePlan {
            version: INTERFACE_VERSION,
            backend_name: BACKEND_NAME.to_string(),
            payload,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DockerTopology {
    sandbox_id: String,
    launch_generation: String,
    container_id: String,
    container_name: String,
    listener_path: PathBuf,
    listener_metadata: String,
    plan_fingerprint: String,
}

/// Linux Docker backend driven by a native host supervisor.
#[derive(Clone)]
pub struct DockerIsolationBackend {
    docker: Arc<Docker>,
    listener_dir: PathBuf,
    provider_env: HashMap<String, String>,
    proxy_tls_dir: Option<PathBuf>,
}

impl DockerIsolationBackend {
    /// Construct a backend for a Docker daemon on this host.
    ///
    /// `listener_dir` must be visible in the Docker daemon/runc host mount
    /// namespace. A remote Docker daemon therefore requires a colocated
    /// backend rather than a client-local path.
    #[must_use]
    pub fn new(docker: Arc<Docker>, listener_dir: PathBuf) -> Self {
        Self {
            docker,
            listener_dir,
            provider_env: HashMap::new(),
            proxy_tls_dir: None,
        }
    }

    /// Connect to the Docker daemon selected by the compute driver and use a
    /// per-sandbox listener directory owned by this host supervisor process.
    pub fn from_host_environment(
        provider_env: HashMap<String, String>,
    ) -> Result<Self, BackendError> {
        let socket_path = std::env::var_os(DOCKER_SOCKET_ENV)
            .map(PathBuf::from)
            .or_else(openshell_core::config::detect_docker_socket)
            .unwrap_or_else(|| PathBuf::from("/var/run/docker.sock"));
        let socket = socket_path.to_str().ok_or_else(|| {
            BackendError::Descriptor(format!(
                "Docker socket path is not valid UTF-8: {}",
                socket_path.display()
            ))
        })?;
        let listener_dir = std::env::var_os(DOCKER_LISTENER_DIR_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| {
                BackendError::Descriptor(format!("{DOCKER_LISTENER_DIR_ENV} is required"))
            })?;
        let proxy_tls_dir =
            std::env::var_os(openshell_core::sandbox_env::PROXY_TLS_DIR).map(PathBuf::from);
        let docker = Docker::connect_with_socket(socket, 120, bollard::API_DEFAULT_VERSION)
            .map_err(|error| docker_error("connect to Docker daemon", error))?;
        Ok(Self {
            docker: Arc::new(docker),
            listener_dir,
            provider_env,
            proxy_tls_dir,
        })
    }
}

#[async_trait]
impl IsolationBackend for DockerIsolationBackend {
    fn backend_name(&self) -> &str {
        BACKEND_NAME
    }

    fn version(&self) -> u32 {
        INTERFACE_VERSION
    }

    async fn create(
        &self,
        plan: VerifiedBoundaryCreatePlan,
        sandbox: SandboxContext,
    ) -> Result<CreatedBoundary, BackendError> {
        let mut plan: DockerBoundaryCreatePlan =
            serde_json::from_slice(plan.payload()).map_err(|error| {
                BackendError::Descriptor(format!("decode Docker create plan: {error}"))
            })?;
        validate_create_plan(&plan)?;
        for (name, value) in &self.provider_env {
            plan.env.push(format!("{name}={value}"));
        }
        if self.proxy_tls_dir.is_some() {
            plan.env.extend([
                format!("SSL_CERT_FILE={CONTAINER_TLS_DIR}/ca-bundle.pem"),
                format!("REQUESTS_CA_BUNDLE={CONTAINER_TLS_DIR}/ca-bundle.pem"),
                format!("CURL_CA_BUNDLE={CONTAINER_TLS_DIR}/ca-bundle.pem"),
                format!("NODE_EXTRA_CA_CERTS={CONTAINER_TLS_DIR}/openshell-ca.pem"),
            ]);
        }

        let resource_key = resource_key(&sandbox.sandbox_id, &plan.launch_generation);
        let container_name = plan.container_name.clone();
        let listener_path = self.listener_dir.join(format!("{resource_key}.sock"));
        let listener_metadata = format!(
            "openshell:{}:{}:{}",
            sandbox.sandbox_id, plan.launch_generation, plan.listener_token
        );
        let plan_fingerprint = plan_fingerprint(&plan)?;
        let (listener, listener_guard) = bind_private_listener(&listener_path)?;

        let mut labels = plan.labels.clone();
        labels.extend([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_SANDBOX_ID.to_string(), sandbox.sandbox_id.clone()),
            (
                LABEL_LAUNCH_GENERATION.to_string(),
                plan.launch_generation.clone(),
            ),
            (LABEL_EXPERIMENTAL.to_string(), "docker-create".to_string()),
            (LABEL_PLAN_FINGERPRINT.to_string(), plan_fingerprint.clone()),
        ]);
        let create_body = build_create_body(
            &plan,
            &sandbox,
            &listener_path,
            &listener_metadata,
            labels,
            self.proxy_tls_dir.as_deref(),
        )?;

        let container_id = match self
            .docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::default()
                        .name(&container_name)
                        .build(),
                ),
                create_body,
            )
            .await
        {
            Ok(response) => response.id,
            Err(BollardError::DockerResponseServerError {
                status_code: 409, ..
            }) => {
                let existing = self
                    .docker
                    .inspect_container(&container_name, None)
                    .await
                    .map_err(|error| docker_error("inspect idempotent Docker boundary", error))?;
                validate_existing_container(
                    &existing,
                    &sandbox.sandbox_id,
                    &plan.launch_generation,
                    &plan_fingerprint,
                )?;
                existing.id.ok_or_else(|| {
                    BackendError::Attach("existing Docker boundary has no container ID".to_string())
                })?
            }
            Err(error) => return Err(docker_error("create Docker boundary", error)),
        };

        let topology = DockerTopology {
            sandbox_id: sandbox.sandbox_id.clone(),
            launch_generation: plan.launch_generation,
            container_id,
            container_name,
            listener_path,
            listener_metadata,
            plan_fingerprint,
        };
        let descriptor = topology_descriptor(&topology)?;
        let mediation = Arc::new(DockerMediation::new());
        let bound = DockerBound {
            docker: self.docker.clone(),
            topology,
            listener,
            listener_guard,
            mediation,
        };
        Ok(CreatedBoundary::new(descriptor, Box::new(bound)))
    }

    async fn destroy(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox_id: &str,
    ) -> Result<(), BackendError> {
        let topology = decode_topology(&descriptor)?;
        validate_topology_identity(&topology, sandbox_id, &self.listener_dir)?;

        let inspected = match self
            .docker
            .inspect_container(&topology.container_id, None)
            .await
        {
            Ok(inspected) => Some(inspected),
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => None,
            Err(error) => return Err(docker_error("inspect Docker boundary for destroy", error)),
        };
        if let Some(inspected) = inspected {
            validate_container_labels(
                &inspected,
                &topology.sandbox_id,
                &topology.launch_generation,
                &topology.plan_fingerprint,
            )?;
            remove_container(&self.docker, &topology.container_id).await?;
        }
        remove_listener_artifacts(&topology.listener_path)?;
        Ok(())
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let topology = decode_topology(&descriptor)?;
        validate_topology_identity(&topology, &sandbox.sandbox_id, &self.listener_dir)?;
        let inspected = self
            .docker
            .inspect_container(&topology.container_id, None)
            .await
            .map_err(|error| docker_error("inspect Docker boundary for attach", error))?;
        validate_existing_container(
            &inspected,
            &topology.sandbox_id,
            &topology.launch_generation,
            &topology.plan_fingerprint,
        )?;
        let (listener, listener_guard) = bind_private_listener(&topology.listener_path)?;
        Ok(Box::new(DockerBound {
            docker: self.docker.clone(),
            topology,
            listener,
            listener_guard,
            mediation: Arc::new(DockerMediation::new()),
        }))
    }
}

fn validate_create_plan(plan: &DockerBoundaryCreatePlan) -> Result<(), BackendError> {
    if plan.image.trim().is_empty() {
        return Err(BackendError::Descriptor(
            "Docker create plan image must not be empty".to_string(),
        ));
    }
    if plan.launch_generation.trim().is_empty() {
        return Err(BackendError::Descriptor(
            "Docker create plan launch generation must not be empty".to_string(),
        ));
    }
    if plan.container_name.trim().is_empty() {
        return Err(BackendError::Descriptor(
            "Docker create plan container name must not be empty".to_string(),
        ));
    }
    if plan.listener_token.len() < MIN_LISTENER_TOKEN_BYTES {
        return Err(BackendError::Descriptor(format!(
            "Docker create plan listener token must be at least {MIN_LISTENER_TOKEN_BYTES} bytes"
        )));
    }
    Ok(())
}

fn plan_fingerprint(plan: &DockerBoundaryCreatePlan) -> Result<String, BackendError> {
    let bytes = serde_json::to_vec(plan).map_err(|error| {
        BackendError::Descriptor(format!("encode Docker plan fingerprint: {error}"))
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn resource_key(sandbox_id: &str, launch_generation: &str) -> String {
    let mut hasher = DefaultHasher::new();
    sandbox_id.hash(&mut hasher);
    launch_generation.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn build_create_body(
    plan: &DockerBoundaryCreatePlan,
    sandbox: &SandboxContext,
    listener_path: &Path,
    listener_metadata: &str,
    labels: HashMap<String, String>,
    proxy_tls_dir: Option<&Path>,
) -> Result<ContainerCreateBody, BackendError> {
    let seccomp = serde_json::json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "listenerPath": listener_path,
        "listenerMetadata": listener_metadata,
        "syscalls": [{
            "names": ["socket", "connect", "sendto", "bpf"],
            "action": "SCMP_ACT_NOTIFY"
        }]
    });
    let seccomp = serde_json::to_string(&seccomp).map_err(|error| {
        BackendError::Descriptor(format!("encode Docker seccomp profile: {error}"))
    })?;

    Ok(ContainerCreateBody {
        image: Some(plan.image.clone()),
        user: plan.user.clone(),
        working_dir: sandbox.agent.workdir.clone(),
        env: Some(plan.env.clone()),
        entrypoint: Some(vec![sandbox.agent.program.clone()]),
        cmd: Some(sandbox.agent.args.clone()),
        tty: Some(sandbox.agent.interactive),
        open_stdin: Some(sandbox.agent.interactive),
        network_disabled: Some(true),
        labels: Some(labels),
        host_config: Some(HostConfig {
            network_mode: Some("none".to_string()),
            cap_drop: Some(vec!["ALL".to_string()]),
            security_opt: Some(vec![
                "no-new-privileges=true".to_string(),
                format!("seccomp={seccomp}"),
            ]),
            restart_policy: None,
            binds: proxy_tls_dir
                .map(|path| vec![format!("{}:{CONTAINER_TLS_DIR}:ro", path.display())]),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn topology_descriptor(topology: &DockerTopology) -> Result<TopologyDescriptor, BackendError> {
    Ok(TopologyDescriptor {
        version: INTERFACE_VERSION,
        backend_name: BACKEND_NAME.to_string(),
        payload: serde_json::to_vec(topology).map_err(|error| {
            BackendError::Descriptor(format!("encode Docker topology: {error}"))
        })?,
    })
}

fn decode_topology(
    descriptor: &VerifiedTopologyDescriptor,
) -> Result<DockerTopology, BackendError> {
    serde_json::from_slice(descriptor.payload())
        .map_err(|error| BackendError::Descriptor(format!("decode Docker topology: {error}")))
}

fn validate_topology_identity(
    topology: &DockerTopology,
    sandbox_id: &str,
    listener_dir: &Path,
) -> Result<(), BackendError> {
    if topology.sandbox_id != sandbox_id {
        return Err(BackendError::Denied(format!(
            "Docker boundary sandbox {:?} does not match admitted sandbox {sandbox_id:?}",
            topology.sandbox_id
        )));
    }
    let key = resource_key(&topology.sandbox_id, &topology.launch_generation);
    let expected_listener = listener_dir.join(format!("{key}.sock"));
    let expected_metadata_prefix = format!(
        "openshell:{}:{}:",
        topology.sandbox_id, topology.launch_generation
    );
    if topology.container_id.is_empty()
        || topology.container_name.is_empty()
        || topology.listener_path != expected_listener
        || !topology
            .listener_metadata
            .starts_with(&expected_metadata_prefix)
        || topology.listener_metadata.len()
            < expected_metadata_prefix.len() + MIN_LISTENER_TOKEN_BYTES
    {
        return Err(BackendError::Denied(
            "Docker topology identity does not match its trusted resource key".to_string(),
        ));
    }
    Ok(())
}

fn validate_existing_container(
    inspected: &bollard::models::ContainerInspectResponse,
    sandbox_id: &str,
    launch_generation: &str,
    plan_fingerprint: &str,
) -> Result<(), BackendError> {
    validate_container_labels(inspected, sandbox_id, launch_generation, plan_fingerprint)?;
    let status = inspected.state.as_ref().and_then(|state| state.status);
    if status != Some(ContainerStateStatusEnum::CREATED) {
        return Err(BackendError::Denied(format!(
            "Docker create/attach prototype requires a non-running container, found {status:?}"
        )));
    }
    Ok(())
}

fn validate_container_labels(
    inspected: &bollard::models::ContainerInspectResponse,
    sandbox_id: &str,
    launch_generation: &str,
    plan_fingerprint: &str,
) -> Result<(), BackendError> {
    let labels = inspected
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .ok_or_else(|| BackendError::Denied("Docker boundary has no trusted labels".to_string()))?;
    if labels.get(LABEL_SANDBOX_ID).map(String::as_str) != Some(sandbox_id)
        || labels.get(LABEL_LAUNCH_GENERATION).map(String::as_str) != Some(launch_generation)
        || labels.get(LABEL_EXPERIMENTAL).map(String::as_str) != Some("docker-create")
        || labels.get(LABEL_PLAN_FINGERPRINT).map(String::as_str) != Some(plan_fingerprint)
    {
        return Err(BackendError::Denied(
            "existing Docker boundary does not match sandbox launch generation".to_string(),
        ));
    }
    Ok(())
}

async fn remove_container(docker: &Docker, container_id: &str) -> Result<(), BackendError> {
    if let Err(error) = docker
        .remove_container(
            container_id,
            Some(RemoveContainerOptionsBuilder::default().force(true).build()),
        )
        .await
        && !matches!(
            error,
            BollardError::DockerResponseServerError {
                status_code: 404,
                ..
            }
        )
    {
        return Err(docker_error("remove Docker boundary", error));
    }
    Ok(())
}

fn remove_listener_artifacts(listener_path: &Path) -> Result<(), BackendError> {
    for path in [
        listener_path.to_path_buf(),
        listener_path.with_extension("lock"),
    ] {
        if let Err(error) = std::fs::remove_file(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(BackendError::Attach(format!(
                "remove Docker listener artifact {}: {error}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn bind_private_listener(
    path: &Path,
) -> Result<(UnixListener, Arc<ListenerPathGuard>), BackendError> {
    let parent = path.parent().ok_or_else(|| {
        BackendError::Descriptor(format!(
            "Docker listener path has no parent: {}",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        BackendError::Attach(format!("create Docker listener directory: {error}"))
    })?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        BackendError::Attach(format!("protect Docker listener directory: {error}"))
    })?;
    if path.as_os_str().as_encoded_bytes().len() >= 104 {
        return Err(BackendError::Descriptor(format!(
            "Docker listener path is too long for AF_UNIX: {}",
            path.display()
        )));
    }
    let lock_path = path.with_extension("lock");
    let lock = acquire_listener_lock(&lock_path)?;
    if path.exists() {
        std::fs::remove_file(path).map_err(|error| {
            BackendError::Attach(format!("remove stale Docker seccomp listener: {error}"))
        })?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| BackendError::Attach(format!("bind Docker seccomp listener: {error}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
        BackendError::Attach(format!("protect Docker seccomp listener: {error}"))
    })?;
    Ok((
        listener,
        Arc::new(ListenerPathGuard {
            socket_path: path.to_path_buf(),
            lock_path,
            _lock: lock,
        }),
    ))
}

fn acquire_listener_lock(path: &Path) -> Result<File, BackendError> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| BackendError::Attach(format!("open Docker listener lock: {error}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| BackendError::Attach(format!("protect Docker listener lock: {error}")))?;
    // SAFETY: flock operates on the live lock-file descriptor and does not
    // access memory. The open file is retained by ListenerPathGuard.
    let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        return Err(BackendError::Denied(format!(
            "Docker seccomp listener is already owned by an active supervisor: {}",
            path.display()
        )));
    }
    Ok(lock)
}

struct ListenerPathGuard {
    socket_path: PathBuf,
    lock_path: PathBuf,
    _lock: File,
}

impl Drop for ListenerPathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

struct DockerBound {
    docker: Arc<Docker>,
    topology: DockerTopology,
    listener: UnixListener,
    listener_guard: Arc<ListenerPathGuard>,
    mediation: Arc<DockerMediation>,
}

#[async_trait]
impl BoundBoundary for DockerBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.mediation.clone()
    }

    fn dns_mediation_source(&self) -> Option<Arc<dyn DnsMediationSource>> {
        Some(self.mediation.clone())
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        let inspected = self
            .docker
            .inspect_container(&self.topology.container_id, None)
            .await
            .map_err(|error| docker_error("confirm Docker boundary", error))?;
        validate_existing_container(
            &inspected,
            &self.topology.sandbox_id,
            &self.topology.launch_generation,
            &self.topology.plan_fingerprint,
        )?;
        Ok(Box::new(DockerReady {
            docker: self.docker,
            topology: self.topology,
            listener: self.listener,
            listener_guard: self.listener_guard,
            mediation: self.mediation,
        }))
    }
}

struct DockerReady {
    docker: Arc<Docker>,
    topology: DockerTopology,
    listener: UnixListener,
    listener_guard: Arc<ListenerPathGuard>,
    mediation: Arc<DockerMediation>,
}

#[async_trait]
impl ReadyBoundary for DockerReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let Self {
            docker,
            topology,
            listener,
            listener_guard,
            mediation,
        } = *self;
        let expected_metadata = topology.listener_metadata.clone();
        let expected_container = topology.container_id.clone();
        let accept_task = tokio::task::spawn_blocking(move || {
            let (stream, _) = listener.accept().map_err(|error| {
                BackendError::Process(format!("accept Docker seccomp listener: {error}"))
            })?;
            receive_listener_fd(stream, &expected_metadata, &expected_container)
        });

        if let Err(error) = docker.start_container(&topology.container_id, None).await {
            accept_task.abort();
            return Err(docker_error("start Docker boundary", error));
        }

        let listener_fd = tokio::time::timeout(LISTENER_ACCEPT_TIMEOUT, accept_task)
            .await
            .map_err(|_| {
                BackendError::Process(
                    "timed out waiting for Docker seccomp listener FD".to_string(),
                )
            })?
            .map_err(|error| {
                BackendError::Process(format!("Docker seccomp listener task failed: {error}"))
            })??;
        let mediation_for_worker = mediation.clone();
        tokio::task::spawn_blocking(move || {
            run_notification_worker(listener_fd, mediation_for_worker);
        });

        let process = Arc::new(DockerProcess {
            docker: docker.clone(),
            container_id: topology.container_id.clone(),
            exit: Mutex::new(None),
        });
        Ok(Box::new(DockerRunning {
            process,
            exec: Arc::new(DockerExec {
                docker,
                container_id: topology.container_id,
            }),
            port_forward: Arc::new(UnsupportedDockerPortForward),
            _listener_guard: listener_guard,
        }))
    }
}

struct DockerRunning {
    process: Arc<DockerProcess>,
    exec: Arc<DockerExec>,
    port_forward: Arc<UnsupportedDockerPortForward>,
    _listener_guard: Arc<ListenerPathGuard>,
}

impl RunningBoundary for DockerRunning {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.process.clone()
    }

    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }

    fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }
}

struct NetworkItem {
    stream: std::net::TcpStream,
    binary_identity: Result<BinaryIdentity, ResolveError>,
    destination: SocketAddr,
}

struct DockerMediation {
    network_tx: mpsc::UnboundedSender<NetworkItem>,
    network_rx: Mutex<mpsc::UnboundedReceiver<NetworkItem>>,
    dns_tx: mpsc::UnboundedSender<MediatedDnsQuery>,
    dns_rx: Mutex<mpsc::UnboundedReceiver<MediatedDnsQuery>>,
}

impl DockerMediation {
    fn new() -> Self {
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let (dns_tx, dns_rx) = mpsc::unbounded_channel();
        Self {
            network_tx,
            network_rx: Mutex::new(network_rx),
            dns_tx,
            dns_rx: Mutex::new(dns_rx),
        }
    }
}

#[async_trait]
impl NetworkMediationSource for DockerMediation {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        let item = self.network_rx.lock().await.recv().await.ok_or_else(|| {
            BackendError::Unavailable("Docker network mediation stopped".to_string())
        })?;
        item.stream
            .set_nonblocking(true)
            .map_err(|error| BackendError::Process(format!("prepare mediated socket: {error}")))?;
        let stream = tokio::net::TcpStream::from_std(item.stream)
            .map_err(|error| BackendError::Process(format!("adopt mediated socket: {error}")))?;
        Ok(MediatedConnection {
            stream: Box::new(stream),
            binary_identity: item.binary_identity,
            destination: Some(item.destination),
        })
    }
}

#[async_trait]
impl DnsMediationSource for DockerMediation {
    async fn accept(&self) -> Result<MediatedDnsQuery, BackendError> {
        self.dns_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| BackendError::Unavailable("Docker DNS mediation stopped".to_string()))
    }
}

struct DockerProcess {
    docker: Arc<Docker>,
    container_id: String,
    exit: Mutex<Option<BoundaryExitStatus>>,
}

#[async_trait]
impl BoundaryProcess for DockerProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let mut exit = self.exit.lock().await;
        if let Some(status) = *exit {
            return Ok(status);
        }
        let next = self
            .docker
            .wait_container(&self.container_id, None)
            .next()
            .await;
        let status = match next {
            Some(Ok(ContainerWaitResponse { status_code, .. })) => {
                BoundaryExitStatus::Exited(i32::try_from(status_code).unwrap_or(i32::MAX))
            }
            Some(Err(BollardError::DockerContainerWaitError { code, .. })) => {
                BoundaryExitStatus::Exited(i32::try_from(code).unwrap_or(i32::MAX))
            }
            Some(Err(error)) => return Err(docker_error("wait for Docker boundary", error)),
            None => {
                return Err(BackendError::Terminated(
                    "Docker wait stream ended without an exit status".to_string(),
                ));
            }
        };
        *exit = Some(status);
        Ok(status)
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let signal = match signal {
            BoundarySignal::Term => "SIGTERM",
            BoundarySignal::Kill => "SIGKILL",
            BoundarySignal::Int => "SIGINT",
            BoundarySignal::Hup => "SIGHUP",
        };
        self.docker
            .kill_container(
                &self.container_id,
                Some(
                    KillContainerOptionsBuilder::default()
                        .signal(signal)
                        .build(),
                ),
            )
            .await
            .map_err(|error| docker_error("signal Docker boundary", error))
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        remove_container(&self.docker, &self.container_id).await
    }
}

struct DockerExec {
    docker: Arc<Docker>,
    container_id: String,
}

#[async_trait]
impl BoundaryExec for DockerExec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let mut command = Vec::with_capacity(spec.args.len() + 1);
        command.push(spec.program);
        command.extend(spec.args);
        let created = self
            .docker
            .create_exec(
                &self.container_id,
                CreateExecOptions {
                    attach_stdin: Some(true),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    tty: Some(spec.pty),
                    env: Some(
                        spec.env
                            .into_iter()
                            .map(|(name, value)| format!("{name}={value}"))
                            .collect(),
                    ),
                    cmd: Some(command),
                    working_dir: spec.workdir,
                    privileged: Some(false),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| docker_error("create Docker exec", error))?;
        let started = self
            .docker
            .start_exec(
                &created.id,
                Some(StartExecOptions {
                    detach: false,
                    tty: spec.pty,
                    output_capacity: Some(64 * 1024),
                }),
            )
            .await
            .map_err(|error| docker_error("start Docker exec", error))?;
        let StartExecResults::Attached { output, input } = started else {
            return Err(BackendError::Process(
                "Docker exec unexpectedly started detached".to_string(),
            ));
        };

        let (stdin, stdin_pump) = tokio::io::duplex(64 * 1024);
        let (stdout, stdout_pump) = tokio::io::duplex(64 * 1024);
        let (stderr, stderr_pump) = tokio::io::duplex(64 * 1024);
        tokio::spawn(pump_docker_exec_input(stdin_pump, input));
        tokio::spawn(pump_docker_exec_output(output, stdout_pump, stderr_pump));

        let process: Arc<dyn BoundaryProcess> = Arc::new(DockerExecProcess {
            docker: self.docker.clone(),
            exec_id: created.id.clone(),
            exit: Mutex::new(None),
        });
        let terminal: Option<Arc<dyn BoundaryTerminal>> = if spec.pty {
            let terminal: Arc<dyn BoundaryTerminal> = Arc::new(DockerTerminal {
                docker: self.docker.clone(),
                exec_id: created.id,
            });
            Some(terminal)
        } else {
            None
        };
        let stdin: BoundaryInput = Box::new(stdin);
        let stdout: BoundaryOutput = Box::new(stdout);
        let stderr: Option<BoundaryOutput> = if spec.pty {
            None
        } else {
            let stderr: BoundaryOutput = Box::new(stderr);
            Some(stderr)
        };
        Ok(ExecSession {
            process,
            stdin: Some(stdin),
            stdout,
            stderr,
            terminal,
        })
    }
}

struct DockerExecProcess {
    docker: Arc<Docker>,
    exec_id: String,
    exit: Mutex<Option<BoundaryExitStatus>>,
}

#[async_trait]
impl BoundaryProcess for DockerExecProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let mut exit = self.exit.lock().await;
        if let Some(status) = *exit {
            return Ok(status);
        }
        loop {
            let inspected = self
                .docker
                .inspect_exec(&self.exec_id)
                .await
                .map_err(|error| docker_error("inspect Docker exec", error))?;
            if inspected.running == Some(false) {
                let code = inspected
                    .exit_code
                    .and_then(|code| i32::try_from(code).ok())
                    .unwrap_or(i32::MAX);
                let status = BoundaryExitStatus::Exited(code);
                *exit = Some(status);
                return Ok(status);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn signal(&self, _signal: BoundarySignal) -> Result<(), BackendError> {
        Err(BackendError::Unsupported(
            "Docker exec signaling is not implemented".to_string(),
        ))
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.signal(BoundarySignal::Kill).await
    }
}

struct DockerTerminal {
    docker: Arc<Docker>,
    exec_id: String,
}

#[async_trait]
impl BoundaryTerminal for DockerTerminal {
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
        self.docker
            .resize_exec(
                &self.exec_id,
                ResizeExecOptions {
                    width: cols,
                    height: rows,
                },
            )
            .await
            .map_err(|error| docker_error("resize Docker exec terminal", error))
    }
}

async fn pump_docker_exec_input(
    mut source: tokio::io::DuplexStream,
    mut destination: std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
) {
    let _ = tokio::io::copy(&mut source, &mut destination).await;
    let _ = destination.shutdown().await;
}

async fn pump_docker_exec_output(
    mut output: std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<LogOutput, BollardError>> + Send>,
    >,
    mut stdout: tokio::io::DuplexStream,
    mut stderr: tokio::io::DuplexStream,
) {
    while let Some(item) = output.next().await {
        let Ok(item) = item else {
            break;
        };
        match item {
            LogOutput::StdErr { message } => {
                if stderr.write_all(&message).await.is_err() {
                    break;
                }
            }
            LogOutput::StdOut { message }
            | LogOutput::StdIn { message }
            | LogOutput::Console { message } => {
                if stdout.write_all(&message).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = stdout.shutdown().await;
    let _ = stderr.shutdown().await;
}

struct UnsupportedDockerPortForward;

#[async_trait]
impl BoundaryPortForward for UnsupportedDockerPortForward {
    async fn connect(&self, _target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        Err(BackendError::Unsupported(
            "Docker create proof does not implement port forwarding".to_string(),
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciContainerProcessState {
    fds: Vec<String>,
    pid: i32,
    metadata: String,
    state: OciState,
}

#[derive(Deserialize)]
struct OciState {
    id: String,
}

fn receive_listener_fd(
    mut stream: UnixStream,
    expected_metadata: &str,
    expected_container: &str,
) -> Result<OwnedFd, BackendError> {
    let mut first = vec![0_u8; MAX_OCI_STATE_BYTES];
    let mut iov = [IoSliceMut::new(&mut first)];
    let mut control = cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .map_err(|error| BackendError::Process(format!("receive OCI seccomp state: {error}")))?;
    let bytes = message.bytes;
    if message.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Err(BackendError::Process(
            "OCI seccomp ancillary data was truncated".to_string(),
        ));
    }
    let mut received_fds = Vec::new();
    for control_message in message.cmsgs().map_err(|error| {
        BackendError::Process(format!("decode OCI seccomp control message: {error}"))
    })? {
        if let ControlMessageOwned::ScmRights(fds) = control_message {
            received_fds.extend(fds.into_iter().map(|fd| {
                // SAFETY: each SCM_RIGHTS entry is a new descriptor owned by
                // this process and has not been wrapped or closed elsewhere.
                unsafe { OwnedFd::from_raw_fd(fd) }
            }));
        }
    }
    first.truncate(bytes);
    stream
        .read_to_end(&mut first)
        .map_err(|error| BackendError::Process(format!("read OCI seccomp state: {error}")))?;
    if first.len() > MAX_OCI_STATE_BYTES {
        return Err(BackendError::Process(
            "OCI seccomp process state exceeds size limit".to_string(),
        ));
    }

    let state: OciContainerProcessState = serde_json::from_slice(&first).map_err(|error| {
        BackendError::Process(format!("decode OCI seccomp process state: {error}"))
    })?;
    if state.metadata != expected_metadata
        || state.state.id != expected_container
        || state.fds.as_slice() != ["seccompFd"]
        || state.pid <= 0
        || received_fds.len() != 1
    {
        return Err(BackendError::Denied(
            "OCI seccomp listener identity or FD shape did not match the created boundary"
                .to_string(),
        ));
    }

    Ok(received_fds.pop().expect("descriptor count checked"))
}

#[repr(C)]
#[derive(Default)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

// Linux reserves IOC_SIZEBITS for the payload size. Both fixed seccomp
// notification structs are far smaller than u32::MAX on supported targets.
#[allow(clippy::cast_possible_truncation)]
const fn ioctl_read_write<T>(kind: u8, number: u8) -> libc::c_ulong {
    ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT
        | (kind as u32) << IOC_TYPESHIFT
        | (number as u32) << IOC_NRSHIFT
        | (size_of::<T>() as u32) << IOC_SIZESHIFT) as libc::c_ulong
}

#[allow(clippy::cast_possible_truncation)]
const fn ioctl_write<T>(kind: u8, number: u8) -> libc::c_ulong {
    (IOC_WRITE << IOC_DIRSHIFT
        | (kind as u32) << IOC_TYPESHIFT
        | (number as u32) << IOC_NRSHIFT
        | (size_of::<T>() as u32) << IOC_SIZESHIFT) as libc::c_ulong
}

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = ioctl_read_write::<SeccompNotif>(b'!', 0);
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = ioctl_read_write::<SeccompNotifResp>(b'!', 1);
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = ioctl_write::<SeccompNotifAddfd>(b'!', 3);
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

enum PendingSocket {
    Tcp(std::net::TcpStream),
    Dns {
        injected: UnixDatagram,
        peer: Option<UnixDatagram>,
    },
}

fn run_notification_worker(listener_fd: OwnedFd, mediation: Arc<DockerMediation>) {
    let mut pending = HashMap::<(u32, i32), PendingSocket>::new();
    loop {
        let mut notification = SeccompNotif::default();
        // SAFETY: the request code and C layout match linux/seccomp.h, and the
        // kernel writes only into the live notification value.
        let received = unsafe {
            libc::ioctl(
                listener_fd.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_RECV,
                &mut notification,
            )
        };
        if received != 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::EINTR | libc::ENOENT)) {
                continue;
            }
            break;
        }
        let result = match i64::from(notification.data.nr) {
            libc::SYS_socket => {
                handle_socket_notification(&listener_fd, &notification, &mut pending)
            }
            libc::SYS_connect => {
                handle_connect_notification(&listener_fd, &notification, &mut pending, &mediation)
            }
            libc::SYS_sendto => {
                handle_sendto_notification(&listener_fd, &notification, &mut pending, &mediation)
            }
            libc::SYS_bpf => {
                send_notification_response(&listener_fd, notification.id, 0, libc::EPERM, 0)
            }
            _ => send_notification_response(
                &listener_fd,
                notification.id,
                0,
                0,
                SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            ),
        };
        if result.is_err() {
            let _ = send_notification_response(&listener_fd, notification.id, 0, libc::EPERM, 0);
        }
    }
}

fn handle_socket_notification(
    listener_fd: &OwnedFd,
    notification: &SeccompNotif,
    pending: &mut HashMap<(u32, i32), PendingSocket>,
) -> Result<(), BackendError> {
    let domain = i32::try_from(notification.data.args[0]).unwrap_or_default();
    let socket_type = i32::try_from(notification.data.args[1]).unwrap_or_default();
    let base_type = socket_type & 0xf;
    if !matches!(domain, libc::AF_INET | libc::AF_INET6)
        || !matches!(base_type, libc::SOCK_STREAM | libc::SOCK_DGRAM)
    {
        return send_notification_response(
            listener_fd,
            notification.id,
            0,
            0,
            SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        );
    }

    let cloexec = if socket_type & libc::SOCK_CLOEXEC != 0 {
        libc::O_CLOEXEC
    } else {
        0
    };
    let (remote_fd, socket) = if base_type == libc::SOCK_STREAM {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| {
            BackendError::Process(format!("create mediated TCP listener: {error}"))
        })?;
        let address = listener.local_addr().map_err(|error| {
            BackendError::Process(format!("read mediated TCP address: {error}"))
        })?;
        let injected = std::net::TcpStream::connect(address).map_err(|error| {
            BackendError::Process(format!("create mediated TCP endpoint: {error}"))
        })?;
        let (peer, _) = listener.accept().map_err(|error| {
            BackendError::Process(format!("accept mediated TCP endpoint: {error}"))
        })?;
        if socket_type & libc::SOCK_NONBLOCK != 0 {
            injected.set_nonblocking(true).map_err(|error| {
                BackendError::Process(format!("configure mediated TCP endpoint: {error}"))
            })?;
        }
        let remote_fd =
            inject_fd_and_respond(listener_fd, notification.id, injected.as_raw_fd(), cloexec)?;
        (remote_fd, PendingSocket::Tcp(peer))
    } else {
        let (injected, peer) = UnixDatagram::pair().map_err(|error| {
            BackendError::Process(format!("create mediated DNS datagram pair: {error}"))
        })?;
        let retained = injected.try_clone().map_err(|error| {
            BackendError::Process(format!("retain mediated DNS endpoint: {error}"))
        })?;
        if socket_type & libc::SOCK_NONBLOCK != 0 {
            injected.set_nonblocking(true).map_err(|error| {
                BackendError::Process(format!("configure mediated DNS endpoint: {error}"))
            })?;
        }
        let remote_fd =
            inject_fd_and_respond(listener_fd, notification.id, injected.as_raw_fd(), cloexec)?;
        (
            remote_fd,
            PendingSocket::Dns {
                injected: retained,
                peer: Some(peer),
            },
        )
    };
    pending.insert((notification.pid, remote_fd), socket);
    Ok(())
}

fn handle_connect_notification(
    listener_fd: &OwnedFd,
    notification: &SeccompNotif,
    pending: &mut HashMap<(u32, i32), PendingSocket>,
    mediation: &DockerMediation,
) -> Result<(), BackendError> {
    let remote_fd = i32::try_from(notification.data.args[0]).unwrap_or(-1);
    let key = (notification.pid, remote_fd);
    let Some(socket) = pending.get_mut(&key) else {
        return send_notification_response(
            listener_fd,
            notification.id,
            0,
            0,
            SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        );
    };
    let destination = read_remote_sockaddr(
        notification.pid,
        notification.data.args[1],
        notification.data.args[2],
    )?;
    let identity = resolve_process_identity(notification.pid);
    match socket {
        PendingSocket::Tcp(_) => {
            let PendingSocket::Tcp(stream) = pending.remove(&key).expect("pending socket exists")
            else {
                unreachable!();
            };
            if destination.port() == 53 {
                spawn_dns_tcp_session(stream, identity, mediation.dns_tx.clone());
            } else {
                mediation
                    .network_tx
                    .send(NetworkItem {
                        stream,
                        binary_identity: identity,
                        destination,
                    })
                    .map_err(|_| {
                        BackendError::Unavailable("Docker network source closed".to_string())
                    })?;
            }
        }
        PendingSocket::Dns { peer, .. } => {
            if destination.port() != 53 {
                return send_notification_response(listener_fd, notification.id, 0, libc::EPERM, 0);
            }
            if let Some(peer) = peer.take() {
                spawn_dns_udp_session(peer, identity, mediation.dns_tx.clone());
            }
        }
    }
    send_notification_response(listener_fd, notification.id, 0, 0, 0)
}

fn handle_sendto_notification(
    listener_fd: &OwnedFd,
    notification: &SeccompNotif,
    pending: &mut HashMap<(u32, i32), PendingSocket>,
    mediation: &DockerMediation,
) -> Result<(), BackendError> {
    let remote_fd = i32::try_from(notification.data.args[0]).unwrap_or(-1);
    let Some(PendingSocket::Dns { injected, peer }) =
        pending.get_mut(&(notification.pid, remote_fd))
    else {
        return send_notification_response(
            listener_fd,
            notification.id,
            0,
            0,
            SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        );
    };
    if notification.data.args[4] != 0 && notification.data.args[5] != 0 {
        let destination = read_remote_sockaddr(
            notification.pid,
            notification.data.args[4],
            notification.data.args[5],
        )?;
        if destination.port() != 53 {
            return send_notification_response(listener_fd, notification.id, 0, libc::EPERM, 0);
        }
    } else if peer.is_some() {
        return send_notification_response(listener_fd, notification.id, 0, libc::ENOTCONN, 0);
    }
    if let Some(peer) = peer.take() {
        spawn_dns_udp_session(
            peer,
            resolve_process_identity(notification.pid),
            mediation.dns_tx.clone(),
        );
    }
    let length = usize::try_from(notification.data.args[2])
        .unwrap_or(usize::MAX)
        .min(8 * 1024);
    let request = read_remote_bytes(notification.pid, notification.data.args[1], length)?;
    let written = injected
        .send(&request)
        .map_err(|error| BackendError::Process(format!("submit mediated DNS datagram: {error}")))?;
    send_notification_response(
        listener_fd,
        notification.id,
        i64::try_from(written).unwrap_or(i64::MAX),
        0,
        0,
    )
}

fn inject_fd_and_respond(
    listener_fd: &OwnedFd,
    notification_id: u64,
    source_fd: RawFd,
    newfd_flags: i32,
) -> Result<i32, BackendError> {
    let mut request = SeccompNotifAddfd {
        id: notification_id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: u32::try_from(source_fd).map_err(|_| {
            BackendError::Process("mediated source descriptor was negative".to_string())
        })?,
        newfd: 0,
        newfd_flags: u32::try_from(newfd_flags).unwrap_or_default(),
    };
    // SAFETY: request layout and ioctl number match linux/seccomp.h; srcfd is
    // live for the duration of the call and the kernel copies the descriptor.
    let remote_fd = unsafe {
        libc::ioctl(
            listener_fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_ADDFD,
            &mut request,
        )
    };
    if remote_fd < 0 {
        return Err(BackendError::Process(format!(
            "inject mediated socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(remote_fd)
}

fn send_notification_response(
    listener_fd: &OwnedFd,
    id: u64,
    value: i64,
    errno: i32,
    flags: u32,
) -> Result<(), BackendError> {
    let response = SeccompNotifResp {
        id,
        val: value,
        error: -errno,
        flags,
    };
    // SAFETY: response layout and ioctl number match linux/seccomp.h.
    let sent = unsafe { libc::ioctl(listener_fd.as_raw_fd(), SECCOMP_IOCTL_NOTIF_SEND, &response) };
    if sent != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(BackendError::Process(format!(
            "respond to seccomp notification: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn read_remote_bytes(pid: u32, address: u64, length: usize) -> Result<Vec<u8>, BackendError> {
    let mut bytes = vec![0_u8; length];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: usize::try_from(address).unwrap_or_default() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: process_vm_readv copies from the stopped notification task into
    // the owned byte buffer. Both iovec arrays live through the call.
    let read = unsafe {
        libc::process_vm_readv(
            i32::try_from(pid).unwrap_or(i32::MAX),
            &raw const local,
            1,
            &raw const remote,
            1,
            0,
        )
    };
    if read < 0 || usize::try_from(read).ok() != Some(length) {
        return Err(BackendError::Denied(format!(
            "read mediated syscall arguments for pid {pid}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(bytes)
}

fn read_remote_sockaddr(pid: u32, address: u64, length: u64) -> Result<SocketAddr, BackendError> {
    let length = usize::try_from(length).unwrap_or(usize::MAX).min(128);
    let bytes = read_remote_bytes(pid, address, length)?;
    if bytes.len() < 2 {
        return Err(BackendError::Denied(
            "mediated socket address is truncated".to_string(),
        ));
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    let port = bytes
        .get(2..4)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
        .ok_or_else(|| BackendError::Denied("mediated socket port is truncated".to_string()))?;
    match i32::from(family) {
        libc::AF_INET if bytes.len() >= 8 => Ok(SocketAddr::new(
            Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]).into(),
            port,
        )),
        libc::AF_INET6 if bytes.len() >= 28 => {
            let mut address = [0_u8; 16];
            address.copy_from_slice(&bytes[8..24]);
            let scope_id = u32::from_ne_bytes(bytes[24..28].try_into().expect("length checked"));
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(address),
                port,
                0,
                scope_id,
            )))
        }
        _ => Err(BackendError::Denied(format!(
            "unsupported mediated socket family {family}"
        ))),
    }
}

fn resolve_process_identity(pid: u32) -> Result<BinaryIdentity, ResolveError> {
    let exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let binary_path = std::fs::read_link(&exe)
        .map_err(|error| ResolveError::Failed(format!("read {}: {error}", exe.display())))?;
    let binary = std::fs::read(&exe)
        .map_err(|error| ResolveError::Failed(format!("hash {}: {error}", exe.display())))?;
    let binary_digest = format!("{:x}", Sha256::digest(binary))
        .parse()
        .map_err(|error: ResolveError| error)?;
    let mut ancestors = Vec::new();
    let mut parent = process_parent_pid(pid);
    for _ in 0..32 {
        let Some(parent_pid) = parent.filter(|parent_pid| *parent_pid > 1) else {
            break;
        };
        let Ok(path) = std::fs::read_link(format!("/proc/{parent_pid}/exe")) else {
            break;
        };
        ancestors.push(path);
        parent = process_parent_pid(parent_pid);
    }
    let cmdline_paths = std::fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .filter_map(|argument| std::str::from_utf8(argument).ok())
        .filter(|argument| argument.starts_with('/'))
        .map(PathBuf::from)
        .collect();
    Ok(BinaryIdentity {
        binary_path,
        binary_digest: Some(binary_digest),
        ancestors,
        cmdline_paths,
    })
}

fn process_parent_pid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

fn clone_identity(
    identity: &Result<BinaryIdentity, ResolveError>,
) -> Result<BinaryIdentity, ResolveError> {
    match identity {
        Ok(identity) => Ok(identity.clone()),
        Err(ResolveError::NotFound) => Err(ResolveError::NotFound),
        Err(ResolveError::Failed(message)) => Err(ResolveError::Failed(message.clone())),
    }
}

fn spawn_dns_udp_session(
    socket: UnixDatagram,
    identity: Result<BinaryIdentity, ResolveError>,
    sender: mpsc::UnboundedSender<MediatedDnsQuery>,
) {
    std::thread::spawn(move || {
        let mut request = vec![0_u8; 8 * 1024];
        while let Ok(length) = socket.recv(&mut request) {
            let (response_tx, response_rx) = oneshot::channel();
            if sender
                .send(MediatedDnsQuery {
                    request: request[..length].to_vec(),
                    transport: DnsTransport::Udp,
                    binary_identity: clone_identity(&identity),
                    response: response_tx,
                })
                .is_err()
            {
                return;
            }
            let Ok(Ok(response)) = response_rx.blocking_recv() else {
                return;
            };
            if socket.send(&response).is_err() {
                return;
            }
        }
    });
}

fn spawn_dns_tcp_session(
    mut stream: std::net::TcpStream,
    identity: Result<BinaryIdentity, ResolveError>,
    sender: mpsc::UnboundedSender<MediatedDnsQuery>,
) {
    std::thread::spawn(move || {
        loop {
            let mut prefix = [0_u8; 2];
            if stream.read_exact(&mut prefix).is_err() {
                return;
            }
            let length = usize::from(u16::from_be_bytes(prefix));
            if length > 8 * 1024 {
                return;
            }
            let mut request = vec![0_u8; length + 2];
            request[..2].copy_from_slice(&prefix);
            if stream.read_exact(&mut request[2..]).is_err() {
                return;
            }
            let (response_tx, response_rx) = oneshot::channel();
            if sender
                .send(MediatedDnsQuery {
                    request,
                    transport: DnsTransport::Tcp,
                    binary_identity: clone_identity(&identity),
                    response: response_tx,
                })
                .is_err()
            {
                return;
            }
            let Ok(Ok(response)) = response_rx.blocking_recv() else {
                return;
            };
            if stream.write_all(&response).is_err() {
                return;
            }
        }
    });
}

fn docker_error(operation: &str, error: BollardError) -> BackendError {
    BackendError::Attach(format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::SandboxPolicy;
    use openshell_isolation::AgentSpec;
    use openshell_isolation::contract::{BackendRegistry, BoundaryOrigin, BoundaryProvisioning};
    use uuid::Uuid;

    fn context() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sandbox-1".to_string(),
            policy: SandboxPolicy {
                version: 1,
                filesystem: openshell_core::policy::FilesystemPolicy::default(),
                network: openshell_core::policy::NetworkPolicy::default(),
                landlock: openshell_core::policy::LandlockPolicy::default(),
                process: openshell_core::policy::ProcessPolicy::default(),
            },
            agent: AgentSpec {
                program: "/usr/bin/uname".to_string(),
                args: vec!["-a".to_string()],
                workdir: Some("/workspace".to_string()),
                timeout_secs: 10,
                interactive: false,
            },
        }
    }

    fn plan() -> DockerBoundaryCreatePlan {
        DockerBoundaryCreatePlan {
            image: "example@sha256:deadbeef".to_string(),
            launch_generation: "generation-1".to_string(),
            listener_token: "0".repeat(MIN_LISTENER_TOKEN_BYTES),
            container_name: "openshell-sandbox-1".to_string(),
            labels: HashMap::new(),
            env: vec!["A=B".to_string()],
            user: Some("1000:1000".to_string()),
        }
    }

    #[tokio::test]
    async fn mediation_sources_deliver_destination_and_dns_response_channels() {
        let mediation = Arc::new(DockerMediation::new());
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let destination: SocketAddr = "198.18.0.8:443".parse().unwrap();
        mediation
            .network_tx
            .send(NetworkItem {
                stream: server,
                binary_identity: Err(ResolveError::NotFound),
                destination,
            })
            .unwrap();
        let connection = NetworkMediationSource::accept(mediation.as_ref())
            .await
            .unwrap();
        assert_eq!(connection.destination, Some(destination));
        drop(client);

        let (response_tx, response_rx) = oneshot::channel();
        mediation
            .dns_tx
            .send(MediatedDnsQuery {
                request: vec![1, 2, 3],
                transport: DnsTransport::Udp,
                binary_identity: Err(ResolveError::NotFound),
                response: response_tx,
            })
            .unwrap();
        let query = DnsMediationSource::accept(mediation.as_ref())
            .await
            .unwrap();
        assert_eq!(query.request, vec![1, 2, 3]);
        query.response.send(Ok(vec![4, 5])).unwrap();
        assert_eq!(response_rx.await.unwrap().unwrap(), vec![4, 5]);
    }

    #[test]
    fn create_body_runs_agent_without_an_in_container_supervisor() {
        let body = build_create_body(
            &plan(),
            &context(),
            Path::new("/run/openshell/seccomp/test.sock"),
            "authenticated-metadata",
            HashMap::new(),
            None,
        )
        .expect("create body");
        assert_eq!(body.entrypoint, Some(vec!["/usr/bin/uname".to_string()]));
        assert_eq!(body.cmd, Some(vec!["-a".to_string()]));
        assert_eq!(body.network_disabled, Some(true));
        let host = body.host_config.expect("host config");
        assert_eq!(host.network_mode.as_deref(), Some("none"));
        assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
    }

    #[test]
    fn create_body_carries_oci_notify_listener_fields() {
        let body = build_create_body(
            &plan(),
            &context(),
            Path::new("/run/openshell/seccomp/test.sock"),
            "authenticated-metadata",
            HashMap::new(),
            None,
        )
        .expect("create body");
        let seccomp = body
            .host_config
            .expect("host config")
            .security_opt
            .expect("security opts")
            .into_iter()
            .find_map(|value| value.strip_prefix("seccomp=").map(str::to_string))
            .expect("seccomp profile");
        let profile: serde_json::Value = serde_json::from_str(&seccomp).expect("profile JSON");
        assert_eq!(profile["listenerPath"], "/run/openshell/seccomp/test.sock");
        assert_eq!(profile["listenerMetadata"], "authenticated-metadata");
        assert_eq!(profile["syscalls"][0]["action"], "SCMP_ACT_NOTIFY");
        assert_eq!(profile["syscalls"][0]["names"][0], "socket");
    }

    #[test]
    fn attach_only_contract_plan_names_the_experimental_backend_exactly() {
        let envelope = plan().into_boundary_plan().expect("encode plan");
        assert_eq!(envelope.backend_name, BACKEND_NAME);
        assert_eq!(envelope.version, INTERFACE_VERSION);
    }

    #[test]
    fn listener_lock_rejects_an_active_owner_and_recovers_after_drop() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("seccomp.lock");
        let guard = acquire_listener_lock(&path).expect("first listener lock");
        let second = acquire_listener_lock(&path).expect_err("active listener must be denied");
        assert!(matches!(second, BackendError::Denied(_)));
        drop(guard);
        let _recovered_guard =
            acquire_listener_lock(&path).expect("released listener lock may be recovered");
    }

    #[test]
    fn create_plan_fingerprint_detects_changed_prepared_inputs() {
        let original = plan_fingerprint(&plan()).expect("fingerprint");
        let mut changed = plan();
        changed.image = "different@sha256:cafebabe".to_string();
        assert_ne!(
            original,
            plan_fingerprint(&changed).expect("changed fingerprint")
        );
    }

    #[test]
    fn topology_identity_pins_cleanup_to_the_backend_listener_directory() {
        let listener_dir = tempfile::tempdir().expect("listener tempdir");
        let key = resource_key("sandbox-1", "generation-1");
        let topology = DockerTopology {
            sandbox_id: "sandbox-1".to_string(),
            launch_generation: "generation-1".to_string(),
            container_id: "container-id".to_string(),
            container_name: format!("openshell-boundary-{key}"),
            listener_path: listener_dir.path().join(format!("{key}.sock")),
            listener_metadata: format!(
                "openshell:sandbox-1:generation-1:{}",
                "0".repeat(MIN_LISTENER_TOKEN_BYTES)
            ),
            plan_fingerprint: "fingerprint".to_string(),
        };
        validate_topology_identity(&topology, "sandbox-1", listener_dir.path())
            .expect("matching topology");

        let mut escaped = topology;
        escaped.listener_path = listener_dir.path().join("../outside.sock");
        assert!(validate_topology_identity(&escaped, "sandbox-1", listener_dir.path()).is_err());
    }

    #[tokio::test]
    #[ignore = "requires a local Linux Docker daemon, runc seccomp-notify support, and a pre-pulled image"]
    async fn local_docker_runs_without_an_in_container_supervisor() {
        let docker =
            Arc::new(Docker::connect_with_unix_defaults().expect("connect to local Docker daemon"));
        let image = std::env::var("OPENSHELL_DOCKER_TEST_IMAGE")
            .unwrap_or_else(|_| "alpine:latest".to_string());
        let uname = std::env::var("OPENSHELL_DOCKER_TEST_UNAME")
            .unwrap_or_else(|_| "/bin/uname".to_string());
        docker
            .inspect_image(&image)
            .await
            .expect("proof image must already be present");
        let listener_dir = tempfile::tempdir().expect("listener tempdir");
        let backend = Arc::new(DockerIsolationBackend::new(
            docker,
            listener_dir.path().to_path_buf(),
        ));
        let mut registry = BackendRegistry::new();
        registry.register(backend).expect("register Docker backend");

        let mut create = plan();
        create.image = image;
        create.launch_generation = Uuid::new_v4().to_string();
        let envelope = create.into_boundary_plan().expect("encode create plan");
        let mut sandbox = context();
        sandbox.agent.program = uname;
        let provisioned = registry
            .provision(
                BoundaryProvisioning::Create(envelope),
                BACKEND_NAME,
                sandbox,
            )
            .await
            .expect("create stopped Docker boundary");
        let (descriptor, origin, bound) = provisioned.into_parts();
        assert_eq!(descriptor.backend_name, BACKEND_NAME);
        assert_eq!(origin, BoundaryOrigin::SupervisorCreated);
        let ready = bound.confirm().await.expect("confirm Docker boundary");
        let running = ready.start_agent().await.expect("start Docker boundary");
        let process = running.agent();
        let status = tokio::time::timeout(Duration::from_secs(15), process.wait())
            .await
            .expect("uname should not remain blocked")
            .expect("observe uname exit");
        assert_eq!(status, BoundaryExitStatus::Exited(0));
        drop(process);
        drop(running);
        registry
            .destroy_created(descriptor, origin, BACKEND_NAME, "sandbox-1")
            .await
            .expect("destroy supervisor-created Docker boundary");
    }
}
