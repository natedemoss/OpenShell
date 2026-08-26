// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental supervisor-created Docker isolation boundary.
//!
//! This module proves the RFC 0012 `create` ordering and OCI seccomp listener
//! handoff. It deliberately disables container networking and does not claim
//! full RFC conformance: mediated networking, binary identity, exec, port
//! forwarding, durable ownership records, and running-boundary recovery remain
//! to be implemented before this can replace the Docker compute-driver path.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::pending;
use std::hash::{Hash, Hasher};
use std::io::{IoSliceMut, Read as _};
use std::mem::size_of;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bollard::Docker;
use bollard::errors::Error as BollardError;
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
    BackendError, BoundBoundary, BoundaryDuplexStream, BoundaryExec, BoundaryExitStatus,
    BoundaryPortForward, BoundaryProcess, BoundarySignal, CreatedBoundary, ExecSession, ExecSpec,
    INTERFACE_VERSION, IsolationBackend, LoopbackTarget, MediatedConnection,
    NetworkMediationSource, ReadyBoundary, RunningBoundary, SandboxContext, TopologyDescriptor,
    VerifiedBoundaryCreatePlan, VerifiedTopologyDescriptor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

const BACKEND_NAME: &str = "docker-poc";
const LISTENER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OCI_STATE_BYTES: usize = 128 * 1024;
const LABEL_LAUNCH_GENERATION: &str = "ai.openshell.prototype.launch-generation";
const LABEL_EXPERIMENTAL: &str = "ai.openshell.prototype.isolation";
const LABEL_PLAN_FINGERPRINT: &str = "ai.openshell.prototype.create-plan";
const MIN_LISTENER_TOKEN_BYTES: usize = 32;

/// Prepared inputs for the experimental Docker creation path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerBoundaryCreatePlan {
    /// Resolved image ID or immutable image reference.
    pub image: String,
    /// Stable generation used with sandbox ID as the create idempotency key.
    pub launch_generation: String,
    /// Driver-generated secret stable for idempotent retries of this launch.
    pub listener_token: String,
    /// Environment passed directly to the admitted agent.
    #[serde(default)]
    pub env: Vec<String>,
    /// Optional container user. The image default is used when absent.
    pub user: Option<String>,
    /// Syscalls delegated to the host notification loop. The prototype denies
    /// each notification with `EPERM`.
    #[serde(default = "default_notify_syscalls")]
    pub notify_syscalls: Vec<String>,
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
            .field("notify_syscalls", &self.notify_syscalls)
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

fn default_notify_syscalls() -> Vec<String> {
    vec!["uname".to_string()]
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

/// Linux-only proof backend supplied by the Docker compute driver or a focused
/// host-side harness.
#[derive(Clone)]
pub struct DockerIsolationBackend {
    docker: Arc<Docker>,
    listener_dir: PathBuf,
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
        }
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
        let plan: DockerBoundaryCreatePlan =
            serde_json::from_slice(plan.payload()).map_err(|error| {
                BackendError::Descriptor(format!("decode Docker create plan: {error}"))
            })?;
        validate_create_plan(&plan)?;

        let resource_key = resource_key(&sandbox.sandbox_id, &plan.launch_generation);
        let container_name = format!("openshell-boundary-{resource_key}");
        let listener_path = self.listener_dir.join(format!("{resource_key}.sock"));
        let listener_metadata = format!(
            "openshell:{}:{}:{}",
            sandbox.sandbox_id, plan.launch_generation, plan.listener_token
        );
        let plan_fingerprint = plan_fingerprint(&plan)?;
        let (listener, listener_guard) = bind_private_listener(&listener_path)?;

        let labels = HashMap::from([
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
        let create_body =
            build_create_body(&plan, &sandbox, &listener_path, &listener_metadata, labels)?;

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
        let bound = DockerBound {
            docker: self.docker.clone(),
            topology,
            listener,
            listener_guard,
        };
        Ok(CreatedBoundary::new(descriptor, Box::new(bound)))
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let topology: DockerTopology =
            serde_json::from_slice(descriptor.payload()).map_err(|error| {
                BackendError::Descriptor(format!("decode Docker topology: {error}"))
            })?;
        if topology.sandbox_id != sandbox.sandbox_id {
            return Err(BackendError::Denied(format!(
                "Docker boundary sandbox {:?} does not match admitted sandbox {:?}",
                topology.sandbox_id, sandbox.sandbox_id
            )));
        }
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
    if plan.listener_token.len() < MIN_LISTENER_TOKEN_BYTES {
        return Err(BackendError::Descriptor(format!(
            "Docker create plan listener token must be at least {MIN_LISTENER_TOKEN_BYTES} bytes"
        )));
    }
    if plan.notify_syscalls.is_empty()
        || plan.notify_syscalls.iter().any(|name| {
            name.is_empty() || matches!(name.as_str(), "write" | "sendmsg" | "recvmsg" | "close")
        })
    {
        return Err(BackendError::Descriptor(
            "Docker notify syscalls must be non-empty and must not contain runc bootstrap syscalls"
                .to_string(),
        ));
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
) -> Result<ContainerCreateBody, BackendError> {
    let seccomp = serde_json::json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "listenerPath": listener_path,
        "listenerMetadata": listener_metadata,
        "syscalls": [{
            "names": plan.notify_syscalls,
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

fn validate_existing_container(
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
    let status = inspected.state.as_ref().and_then(|state| state.status);
    if status != Some(ContainerStateStatusEnum::CREATED) {
        return Err(BackendError::Denied(format!(
            "Docker create/attach prototype requires a non-running container, found {status:?}"
        )));
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
}

#[async_trait]
impl BoundBoundary for DockerBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        Arc::new(NetworkDisabledSource)
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
        }))
    }
}

struct DockerReady {
    docker: Arc<Docker>,
    topology: DockerTopology,
    listener: UnixListener,
    listener_guard: Arc<ListenerPathGuard>,
}

#[async_trait]
impl ReadyBoundary for DockerReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let Self {
            docker,
            topology,
            listener,
            listener_guard,
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
        tokio::task::spawn_blocking(move || deny_notifications(listener_fd));

        let process = Arc::new(DockerProcess {
            docker: docker.clone(),
            container_id: topology.container_id,
            exit: Mutex::new(None),
        });
        Ok(Box::new(DockerRunning {
            process,
            exec: Arc::new(UnsupportedDockerExec),
            port_forward: Arc::new(UnsupportedDockerPortForward),
            _listener_guard: listener_guard,
        }))
    }
}

struct DockerRunning {
    process: Arc<DockerProcess>,
    exec: Arc<UnsupportedDockerExec>,
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

struct NetworkDisabledSource;

#[async_trait]
impl NetworkMediationSource for NetworkDisabledSource {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        pending::<Result<MediatedConnection, BackendError>>().await
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
        if let Err(error) = self
            .docker
            .remove_container(
                &self.container_id,
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
}

struct UnsupportedDockerExec;

#[async_trait]
impl BoundaryExec for UnsupportedDockerExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Err(BackendError::Unsupported(
            "Docker create proof does not implement exec".to_string(),
        ))
    }
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

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioctl_read_write<T>(kind: u8, number: u8) -> libc::c_ulong {
    ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT
        | (kind as u32) << IOC_TYPESHIFT
        | (number as u32) << IOC_NRSHIFT
        | (size_of::<T>() as u32) << IOC_SIZESHIFT) as libc::c_ulong
}

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = ioctl_read_write::<SeccompNotif>(b'!', 0);
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = ioctl_read_write::<SeccompNotifResp>(b'!', 1);

fn deny_notifications(listener_fd: OwnedFd) {
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
            if matches!(error.raw_os_error(), Some(libc::EINTR) | Some(libc::ENOENT)) {
                continue;
            }
            break;
        }
        let response = SeccompNotifResp {
            id: notification.id,
            val: 0,
            error: -libc::EPERM,
            flags: 0,
        };
        // SAFETY: the response carries the cookie returned for this listener
        // and the kernel reads from the live C-compatible value.
        let sent =
            unsafe { libc::ioctl(listener_fd.as_raw_fd(), SECCOMP_IOCTL_NOTIF_SEND, &response) };
        if sent != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            break;
        }
    }
}

fn docker_error(operation: &str, error: BollardError) -> BackendError {
    BackendError::Attach(format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::SandboxPolicy;
    use openshell_isolation::AgentSpec;
    use openshell_isolation::contract::BackendRegistry;
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
            env: vec!["A=B".to_string()],
            user: Some("1000:1000".to_string()),
            notify_syscalls: vec!["uname".to_string()],
        }
    }

    #[test]
    fn create_body_runs_agent_without_an_in_container_supervisor() {
        let body = build_create_body(
            &plan(),
            &context(),
            Path::new("/run/openshell/seccomp/test.sock"),
            "authenticated-metadata",
            HashMap::new(),
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
        assert_eq!(profile["syscalls"][0]["names"][0], "uname");
    }

    #[test]
    fn attach_only_contract_plan_names_the_experimental_backend_exactly() {
        let envelope = plan().into_boundary_plan().expect("encode plan");
        assert_eq!(envelope.backend_name, BACKEND_NAME);
        assert_eq!(envelope.version, INTERFACE_VERSION);
    }

    #[test]
    fn rejects_runc_bootstrap_syscalls() {
        let mut invalid = plan();
        invalid.notify_syscalls = vec!["sendmsg".to_string()];
        assert!(validate_create_plan(&invalid).is_err());
    }

    #[test]
    fn listener_lock_rejects_an_active_owner_and_recovers_after_drop() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("seccomp.lock");
        let guard = acquire_listener_lock(&path).expect("first listener lock");
        let second = acquire_listener_lock(&path)
            .err()
            .expect("active listener must be denied");
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

    #[tokio::test]
    #[ignore = "requires a local Linux Docker daemon, runc seccomp-notify support, and a pre-pulled image"]
    async fn local_docker_denies_notified_uname_without_in_container_supervisor() {
        let docker =
            Arc::new(Docker::connect_with_unix_defaults().expect("connect to local Docker daemon"));
        let image = std::env::var("OPENSHELL_DOCKER_POC_IMAGE")
            .unwrap_or_else(|_| "alpine:latest".to_string());
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
        let (backend, verified) = registry
            .resolve_create(envelope, BACKEND_NAME)
            .expect("resolve Docker create backend");
        let created = backend
            .create(verified, context())
            .await
            .expect("create stopped Docker boundary");
        let (descriptor, bound) = created.into_parts();
        assert_eq!(descriptor.backend_name, BACKEND_NAME);
        let ready = bound.confirm().await.expect("confirm Docker boundary");
        let running = ready.start_agent().await.expect("start Docker boundary");
        let process = running.agent();
        let status = tokio::time::timeout(Duration::from_secs(15), process.wait())
            .await
            .expect("uname should not remain blocked")
            .expect("observe uname exit");
        assert!(matches!(status, BoundaryExitStatus::Exited(code) if code != 0));
        process.terminate().await.expect("remove Docker boundary");
    }
}
