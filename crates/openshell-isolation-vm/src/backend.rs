// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side RFC 0012 backend for an already-provisioned VM.

#![allow(unsafe_code)]

use std::fmt;
use std::mem::size_of;
use std::os::fd::{FromRawFd as _, IntoRawFd as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use openshell_isolation::AgentSpec;
use openshell_isolation::contract::{
    BackendError, BoundBoundary, BoundaryDuplexStream, BoundaryExec, BoundaryExitStatus,
    BoundaryInput, BoundaryOutput, BoundaryPortForward, BoundaryProcess, BoundarySignal,
    BoundaryTerminal, ExecSession, ExecSpec, INTERFACE_VERSION, IsolationBackend, LoopbackTarget,
    MediatedConnection, NetworkMediationSource, ReadyBoundary, RunningBoundary, SandboxContext,
    VerifiedTopologyDescriptor,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;

use crate::protocol::{
    AgentSpecWire, ExecSpecWire, ExitStatusWire, MAX_CONTROL_FRAME_BYTES, Request, RequestEnvelope,
    Response, ResponseEnvelope, STREAM_EXIT, STREAM_STDERR, STREAM_STDIN, STREAM_STDIN_CLOSED,
    STREAM_STDOUT, SandboxPolicyWire, SignalWire, decode_frame, encode_frame, read_stream_frame,
    write_stream_frame,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_BOOTSTRAP_TOKEN_BYTES: usize = 32;

/// Hypervisor-specific host-to-guest control transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VmTransport {
    /// A raw Unix stream mapped to a guest vsock port by libkrun.
    MappedUnix { socket_path: PathBuf },
    /// A Linux host `AF_VSOCK` connection to a QEMU guest.
    HostVsock { guest_cid: u32, control_port: u32 },
}

/// Backend-private provisioned topology payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmTopology {
    pub boundary_id: String,
    pub transport: VmTransport,
    pub bootstrap_token: String,
}

impl fmt::Debug for VmTopology {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VmTopology")
            .field("boundary_id", &self.boundary_id)
            .field("transport", &self.transport)
            .field("bootstrap_token", &"<redacted>")
            .finish()
    }
}

impl VmTopology {
    pub fn encode(&self) -> Result<Vec<u8>, BackendError> {
        serde_json::to_vec(self)
            .map_err(|error| BackendError::Descriptor(format!("encode topology: {error}")))
    }
}

/// Host-side VM implementation registered with the supervisor.
#[derive(Debug)]
pub struct VmHostBackend {
    backend_name: String,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_env: std::collections::HashMap<String, String>,
}

impl VmHostBackend {
    pub fn new(
        backend_name: impl Into<String>,
        ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
        provider_env: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            backend_name: backend_name.into(),
            ca_file_paths,
            provider_env,
        }
    }
}

#[async_trait]
impl IsolationBackend for VmHostBackend {
    fn backend_name(&self) -> &str {
        &self.backend_name
    }

    fn version(&self) -> u32 {
        INTERFACE_VERSION
    }

    async fn attach(
        &self,
        descriptor: VerifiedTopologyDescriptor,
        sandbox: SandboxContext,
    ) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let topology: VmTopology = serde_json::from_slice(descriptor.payload())
            .map_err(|error| BackendError::Descriptor(format!("decode topology: {error}")))?;
        validate_topology(&topology, &sandbox)?;
        let client = Arc::new(GuestClient::new(topology));
        expect_response(
            client
                .call_idempotent(Request::Attach {
                    policy: Box::new(SandboxPolicyWire::from(sandbox.policy.clone())),
                })
                .await?,
            "attached",
        )?;
        Ok(Box::new(VmBound {
            client: client.clone(),
            agent: sandbox.agent,
            policy: sandbox.policy,
            sandbox_id: sandbox.sandbox_id,
            mediation: Arc::new(VmNetworkMediation { client }),
            ca_file_paths: self.ca_file_paths.clone(),
            provider_env: self.provider_env.clone(),
        }))
    }
}

fn validate_topology(topology: &VmTopology, sandbox: &SandboxContext) -> Result<(), BackendError> {
    if topology.boundary_id != sandbox.sandbox_id {
        return Err(BackendError::Descriptor(format!(
            "VM boundary {:?} does not match sandbox {:?}",
            topology.boundary_id, sandbox.sandbox_id
        )));
    }
    if topology.bootstrap_token.len() < MIN_BOOTSTRAP_TOKEN_BYTES {
        return Err(BackendError::Descriptor(format!(
            "VM bootstrap token must be at least {MIN_BOOTSTRAP_TOKEN_BYTES} bytes"
        )));
    }
    match &topology.transport {
        VmTransport::MappedUnix { socket_path } => validate_socket_path(socket_path)?,
        VmTransport::HostVsock {
            guest_cid,
            control_port,
        } => {
            if *guest_cid < 3 {
                return Err(BackendError::Descriptor(
                    "VM guest CID must be at least 3".to_string(),
                ));
            }
            validate_control_port(*control_port)?;
        }
    }
    Ok(())
}

fn validate_socket_path(path: &std::path::Path) -> Result<(), BackendError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(BackendError::Descriptor(
            "VM control Unix socket path must be absolute".to_string(),
        ))
    }
}

fn validate_control_port(port: u32) -> Result<(), BackendError> {
    if port == 0 {
        Err(BackendError::Descriptor(
            "VM guest control port must be nonzero".to_string(),
        ))
    } else {
        Ok(())
    }
}

struct VmBound {
    client: Arc<GuestClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    mediation: Arc<VmNetworkMediation>,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_env: std::collections::HashMap<String, String>,
}

#[async_trait]
impl BoundBoundary for VmBound {
    fn network_mediation_source(&self) -> Arc<dyn NetworkMediationSource> {
        self.mediation.clone()
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        expect_response(
            self.client.call_idempotent(Request::Confirm).await?,
            "confirmed",
        )?;
        Ok(Box::new(VmReady {
            client: self.client,
            agent: self.agent,
            policy: self.policy,
            sandbox_id: self.sandbox_id,
            ca_file_paths: self.ca_file_paths,
            provider_env: self.provider_env,
        }))
    }
}

struct VmReady {
    client: Arc<GuestClient>,
    agent: AgentSpec,
    policy: openshell_core::policy::SandboxPolicy,
    sandbox_id: String,
    ca_file_paths: Arc<std::sync::Mutex<Option<(PathBuf, PathBuf)>>>,
    provider_env: std::collections::HashMap<String, String>,
}

#[async_trait]
impl ReadyBoundary for VmReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let ca_paths = self
            .ca_file_paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (ca_cert, ca_bundle) = if let Some((ca_cert, ca_bundle)) = ca_paths {
            let ca_cert = tokio::fs::read(&ca_cert).await.map_err(|error| {
                BackendError::Process(format!("read host proxy CA {}: {error}", ca_cert.display()))
            })?;
            let ca_bundle = tokio::fs::read(&ca_bundle).await.map_err(|error| {
                BackendError::Process(format!(
                    "read host proxy CA bundle {}: {error}",
                    ca_bundle.display()
                ))
            })?;
            (Some(ca_cert), Some(ca_bundle))
        } else {
            (None, None)
        };
        let response = self
            .client
            .call(Request::StartAgent {
                sandbox_id: self.sandbox_id,
                spec: AgentSpecWire::from(self.agent),
                policy: Box::new(SandboxPolicyWire::from(self.policy)),
                ca_cert,
                ca_bundle,
                provider_env: self.provider_env,
            })
            .await?;
        let Response::Started { process_id } = response else {
            return Err(unexpected_response("started", &response));
        };
        let process = Arc::new(VmProcess {
            client: self.client.clone(),
            process_id,
        });
        Ok(Box::new(VmRunning {
            process,
            exec: Arc::new(VmExec {
                client: self.client.clone(),
            }),
            port_forward: Arc::new(VmPortForward {
                client: self.client,
            }),
        }))
    }
}

struct VmRunning {
    process: Arc<VmProcess>,
    exec: Arc<VmExec>,
    port_forward: Arc<VmPortForward>,
}

impl RunningBoundary for VmRunning {
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

struct VmProcess {
    client: Arc<GuestClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryProcess for VmProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        let response = self
            .client
            .call_wait(Request::Wait {
                process_id: self.process_id.clone(),
            })
            .await?;
        let Response::Exited { status } = response else {
            return Err(unexpected_response("exited", &response));
        };
        Ok(status.into())
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let response = self
            .client
            .call(Request::Signal {
                process_id: self.process_id.clone(),
                signal: SignalWire::from(signal),
            })
            .await?;
        expect_response(response, "signaled")
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        let response = self
            .client
            .call(Request::Terminate {
                process_id: self.process_id.clone(),
            })
            .await?;
        expect_response(response, "terminated")
    }
}

struct VmExec {
    client: Arc<GuestClient>,
}

#[async_trait]
impl BoundaryExec for VmExec {
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError> {
        open_exec_session(self.client.clone(), spec).await
    }
}

struct VmPortForward {
    client: Arc<GuestClient>,
}

#[async_trait]
impl BoundaryPortForward for VmPortForward {
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError> {
        let (stream, response) = self
            .client
            .call_stream(Request::PortForward {
                host: target.host(),
                port: target.port(),
            })
            .await?;
        match response {
            Response::PortConnected => Ok(stream),
            response => Err(unexpected_response("port_connected", &response)),
        }
    }
}

struct RemoteExecProcess {
    client: Arc<GuestClient>,
    process_id: String,
    exit: Arc<RemoteExit>,
}

struct RemoteExit {
    result: std::sync::Mutex<Option<Result<BoundaryExitStatus, String>>>,
    changed: Notify,
}

impl RemoteExit {
    fn new() -> Self {
        Self {
            result: std::sync::Mutex::new(None),
            changed: Notify::new(),
        }
    }

    fn set(&self, result: Result<BoundaryExitStatus, String>) {
        let mut current = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_none() {
            *current = Some(result);
            self.changed.notify_waiters();
        }
    }

    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        loop {
            let changed = self.changed.notified();
            let result = self
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(result) = result {
                return result.map_err(BackendError::Terminated);
            }
            changed.await;
        }
    }
}

#[async_trait]
impl BoundaryProcess for RemoteExecProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        self.exit.wait().await
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        expect_response(
            self.client
                .call(Request::ExecSignal {
                    process_id: self.process_id.clone(),
                    signal: SignalWire::from(signal),
                })
                .await?,
            "signaled",
        )
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        self.signal(BoundarySignal::Kill).await
    }
}

struct RemoteTerminal {
    client: Arc<GuestClient>,
    process_id: String,
}

#[async_trait]
impl BoundaryTerminal for RemoteTerminal {
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError> {
        let response = self
            .client
            .call(Request::Resize {
                process_id: self.process_id.clone(),
                cols,
                rows,
            })
            .await?;
        if matches!(response, Response::Resized) {
            Ok(())
        } else {
            Err(unexpected_response("resized", &response))
        }
    }
}

async fn open_exec_session(
    client: Arc<GuestClient>,
    spec: ExecSpec,
) -> Result<ExecSession, BackendError> {
    let (stream, response) = client
        .call_stream(Request::Exec {
            spec: ExecSpecWire::from(spec),
        })
        .await?;
    let Response::ExecStarted { process_id, pty } = response else {
        return Err(unexpected_response("exec_started", &response));
    };
    let (network_reader, network_writer) = tokio::io::split(stream);
    let (stdin, stdin_pump) = tokio::io::duplex(64 * 1024);
    let (stdout, stdout_pump) = tokio::io::duplex(64 * 1024);
    let (stderr, stderr_pump) = tokio::io::duplex(64 * 1024);
    let exit = Arc::new(RemoteExit::new());
    tokio::spawn(pump_exec_input(stdin_pump, network_writer));
    tokio::spawn(pump_exec_responses(
        network_reader,
        stdout_pump,
        stderr_pump,
        exit.clone(),
    ));

    let process: Arc<dyn BoundaryProcess> = Arc::new(RemoteExecProcess {
        client: client.clone(),
        process_id: process_id.clone(),
        exit,
    });
    let terminal: Option<Arc<dyn BoundaryTerminal>> = if pty {
        Some(Arc::new(RemoteTerminal { client, process_id }))
    } else {
        None
    };
    let stdin: BoundaryInput = Box::new(stdin);
    let stdout: BoundaryOutput = Box::new(stdout);
    let stderr: Option<BoundaryOutput> = if pty { None } else { Some(Box::new(stderr)) };
    Ok(ExecSession {
        process,
        stdin: Some(stdin),
        stdout,
        stderr,
        terminal,
    })
}

async fn pump_exec_input(
    mut input: tokio::io::DuplexStream,
    mut network: tokio::io::WriteHalf<BoundaryDuplexStream>,
) {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        match input.read(&mut buffer).await {
            Ok(0) => {
                let _ = write_stream_frame(&mut network, STREAM_STDIN_CLOSED, &[]).await;
                return;
            }
            Ok(read) => {
                if write_stream_frame(&mut network, STREAM_STDIN, &buffer[..read])
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

async fn pump_exec_responses(
    mut network: tokio::io::ReadHalf<BoundaryDuplexStream>,
    mut stdout: tokio::io::DuplexStream,
    mut stderr: tokio::io::DuplexStream,
    exit: Arc<RemoteExit>,
) {
    loop {
        match read_stream_frame(&mut network).await {
            Ok(Some((STREAM_STDOUT, payload))) => {
                if stdout.write_all(&payload).await.is_err() {
                    exit.set(Err("VM exec stdout consumer closed".to_string()));
                    return;
                }
            }
            Ok(Some((STREAM_STDERR, payload))) => {
                if stderr.write_all(&payload).await.is_err() {
                    exit.set(Err("VM exec stderr consumer closed".to_string()));
                    return;
                }
            }
            Ok(Some((STREAM_EXIT, payload))) => {
                let result = serde_json::from_slice::<ExitStatusWire>(&payload)
                    .map(BoundaryExitStatus::from)
                    .map_err(|error| format!("decode VM exec exit: {error}"));
                exit.set(result);
                return;
            }
            Ok(Some((channel, _))) => {
                exit.set(Err(format!(
                    "VM exec returned unexpected stream channel {channel}"
                )));
                return;
            }
            Ok(None) => {
                exit.set(Err("VM exec stream closed before exit status".to_string()));
                return;
            }
            Err(error) => {
                exit.set(Err(format!("read VM exec stream: {error}")));
                return;
            }
        }
    }
}

/// Pulls guest proxy connections over one authenticated vsock stream each.
struct VmNetworkMediation {
    client: Arc<GuestClient>,
}

#[async_trait]
impl NetworkMediationSource for VmNetworkMediation {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        let (stream, response) = self.client.open_exchange(Request::AcceptNetwork).await?;
        let Response::NetworkConnected { identity } = response else {
            return Err(unexpected_response("network_connected", &response));
        };
        Ok(MediatedConnection {
            stream,
            binary_identity: identity.into_result(),
        })
    }
}

struct GuestClient {
    topology: VmTopology,
    next_request_id: AtomicU64,
}

impl GuestClient {
    fn new(topology: VmTopology) -> Self {
        Self {
            topology,
            next_request_id: AtomicU64::new(1),
        }
    }

    async fn call(&self, request: Request) -> Result<Response, BackendError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| BackendError::Unavailable("guest control request timed out".to_string()))?
    }

    async fn call_idempotent(&self, request: Request) -> Result<Response, BackendError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            loop {
                match self.exchange(request.clone()).await {
                    Ok(response) => return Ok(response),
                    Err(BackendError::Unavailable(_)) => {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(|_| {
            BackendError::Unavailable(
                "guest idempotent control request timed out while waiting for VM boot".to_string(),
            )
        })?
    }

    async fn call_wait(&self, request: Request) -> Result<Response, BackendError> {
        self.exchange(request).await
    }

    async fn call_stream(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.open_exchange(request))
            .await
            .map_err(|_| BackendError::Unavailable("guest stream request timed out".to_string()))?
    }

    async fn exchange(&self, request: Request) -> Result<Response, BackendError> {
        let (_, response) = self.open_exchange(request).await?;
        Ok(response)
    }

    async fn open_exchange(
        &self,
        request: Request,
    ) -> Result<(BoundaryDuplexStream, Response), BackendError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let envelope = RequestEnvelope {
            request_id,
            boundary_id: self.topology.boundary_id.clone(),
            bootstrap_token: self.topology.bootstrap_token.clone(),
            request,
        };
        let mut stream = self.connect_vsock().await?;
        let frame = encode_frame(&envelope)
            .map_err(|error| BackendError::Process(format!("encode control request: {error}")))?;
        stream.write_all(&frame).await.map_err(|error| {
            BackendError::Unavailable(format!("write guest control request: {error}"))
        })?;
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.map_err(|error| {
            BackendError::Unavailable(format!("read guest control response header: {error}"))
        })?;
        let declared = u32::from_be_bytes(header) as usize;
        if declared > MAX_CONTROL_FRAME_BYTES {
            return Err(BackendError::Process(format!(
                "guest control response is too large: {declared} bytes"
            )));
        }
        let mut frame = Vec::with_capacity(4 + declared);
        frame.extend_from_slice(&header);
        frame.resize(4 + declared, 0);
        stream.read_exact(&mut frame[4..]).await.map_err(|error| {
            BackendError::Unavailable(format!("read guest control response: {error}"))
        })?;
        let response: ResponseEnvelope = decode_frame(&frame)
            .map_err(|error| BackendError::Process(format!("decode control response: {error}")))?;
        if response.request_id != request_id {
            return Err(BackendError::Process(format!(
                "guest response ID {} did not match request ID {request_id}",
                response.request_id
            )));
        }
        let response = match response.response {
            Response::Error { kind, message } => Err(guest_error(&kind, message)),
            response => Ok(response),
        }?;
        Ok((stream, response))
    }

    async fn connect_vsock(&self) -> Result<BoundaryDuplexStream, BackendError> {
        loop {
            match self.connect_vsock_once().await {
                Ok(stream) => return Ok(stream),
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    }

    async fn connect_vsock_once(&self) -> Result<BoundaryDuplexStream, BackendError> {
        match &self.topology.transport {
            VmTransport::MappedUnix { socket_path } => {
                let stream = UnixStream::connect(socket_path).await.map_err(|error| {
                    BackendError::Unavailable(format!(
                        "connect to mapped VM control socket {}: {error}",
                        socket_path.display()
                    ))
                })?;
                Ok(Box::new(stream))
            }
            VmTransport::HostVsock {
                guest_cid,
                control_port,
            } => connect_host_vsock(*guest_cid, *control_port),
        }
    }
}

#[cfg(target_os = "linux")]
fn connect_host_vsock(
    guest_cid: u32,
    control_port: u32,
) -> Result<BoundaryDuplexStream, BackendError> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(BackendError::Unavailable(format!(
            "create host vsock: {}",
            std::io::Error::last_os_error()
        )));
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(|error| {
        BackendError::Unavailable(format!("convert host vsock address family: {error}"))
    })?;
    let address = libc::sockaddr_vm {
        svm_family: family,
        svm_reserved1: 0,
        svm_port: control_port,
        svm_cid: guest_cid,
        svm_zero: [0; 4],
    };
    let address_length =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>()).map_err(|error| {
            BackendError::Unavailable(format!("convert host vsock address length: {error}"))
        })?;
    let result = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if result != 0 {
        return Err(BackendError::Unavailable(format!(
            "connect host vsock CID {guest_cid} port {control_port}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd.into_raw_fd()) };
    stream.set_nonblocking(true).map_err(|error| {
        BackendError::Unavailable(format!("set host vsock nonblocking: {error}"))
    })?;
    let stream = UnixStream::from_std(stream).map_err(|error| {
        BackendError::Unavailable(format!("register host vsock with Tokio: {error}"))
    })?;
    Ok(Box::new(stream))
}

#[cfg(not(target_os = "linux"))]
fn connect_host_vsock(
    _guest_cid: u32,
    _control_port: u32,
) -> Result<BoundaryDuplexStream, BackendError> {
    Err(BackendError::Unavailable(
        "host AF_VSOCK transport is supported only on Linux".to_string(),
    ))
}

fn expect_response(response: Response, expected: &str) -> Result<(), BackendError> {
    let matches = matches!(
        (&response, expected),
        (Response::Attached, "attached")
            | (Response::Confirmed, "confirmed")
            | (Response::Signaled, "signaled")
            | (Response::Terminated, "terminated")
    );
    if matches {
        Ok(())
    } else {
        Err(unexpected_response(expected, &response))
    }
}

fn unexpected_response(expected: &str, response: &Response) -> BackendError {
    BackendError::Process(format!(
        "expected guest response {expected:?}, received {response:?}"
    ))
}

fn guest_error(kind: &str, message: String) -> BackendError {
    let message = format!("VM guest process leaf: {message}");
    match kind {
        "invalid" => BackendError::Descriptor(message),
        "denied" => BackendError::Denied(message),
        "unavailable" => BackendError::Unavailable(message),
        "terminated" => BackendError::Terminated(message),
        _ => BackendError::Process(message),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };

    use super::*;

    fn sandbox() -> SandboxContext {
        SandboxContext {
            sandbox_id: "sandbox-1".to_string(),
            policy: SandboxPolicy {
                version: 1,
                filesystem: FilesystemPolicy::default(),
                network: NetworkPolicy::default(),
                landlock: LandlockPolicy::default(),
                process: ProcessPolicy::default(),
            },
            agent: AgentSpec {
                program: "/bin/true".to_string(),
                args: Vec::new(),
                workdir: Some("/sandbox".to_string()),
                timeout_secs: 5,
                interactive: false,
            },
        }
    }

    #[test]
    fn topology_debug_redacts_token() {
        let topology = VmTopology {
            boundary_id: "sandbox-1".to_string(),
            transport: VmTransport::MappedUnix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
            },
            bootstrap_token: "never-log-this-never-log-this".to_string(),
        };
        let debug = format!("{topology:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
    }

    #[test]
    fn topology_must_match_sandbox() {
        let topology = VmTopology {
            boundary_id: "other".to_string(),
            transport: VmTransport::MappedUnix {
                socket_path: PathBuf::from("/tmp/vsock.sock"),
            },
            bootstrap_token: "0123456789abcdef0123456789abcdef".to_string(),
        };
        assert!(matches!(
            validate_topology(&topology, &sandbox()),
            Err(BackendError::Descriptor(_))
        ));
    }
}
