// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private guest mode shared by VM isolation drivers.
//!
//! This is transport and lifecycle glue, not another supervisor model. When
//! the host authorizes `start_agent`, it invokes the existing
//! `openshell-supervisor-process` implementation inside the VM.

#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::Path;

const DEFAULT_CONTROL_PORT: u32 = 5500;
const DEFAULT_AGENT_UID: u32 = 10_001;
const DEFAULT_AGENT_GID: u32 = 10_001;

/// Driver-private configuration injected into the guest image at provision time.
#[derive(Clone, Serialize, Deserialize)]
pub struct GuestConfig {
    pub boundary_id: String,
    pub bootstrap_token: String,
    #[serde(default = "default_control_port")]
    pub control_port: u32,
    #[serde(default = "default_agent_uid")]
    pub agent_uid: u32,
    #[serde(default = "default_agent_gid")]
    pub agent_gid: u32,
    /// Absolute, driver-owned helper runtime used for namespace setup.
    #[serde(default = "default_trusted_runtime_root")]
    pub trusted_runtime_root: std::path::PathBuf,
    /// Driver-resolved environment exposed only to workload processes.
    #[serde(default)]
    pub child_env: std::collections::HashMap<String, String>,
}

impl std::fmt::Debug for GuestConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestConfig")
            .field("boundary_id", &self.boundary_id)
            .field("bootstrap_token", &"<redacted>")
            .field("control_port", &self.control_port)
            .field("agent_uid", &self.agent_uid)
            .field("agent_gid", &self.agent_gid)
            .field("trusted_runtime_root", &self.trusted_runtime_root)
            .field("child_env_keys", &self.child_env.keys().collect::<Vec<_>>())
            .finish()
    }
}

const fn default_control_port() -> u32 {
    DEFAULT_CONTROL_PORT
}

const fn default_agent_uid() -> u32 {
    DEFAULT_AGENT_UID
}

const fn default_agent_gid() -> u32 {
    DEFAULT_AGENT_GID
}

fn default_trusted_runtime_root() -> std::path::PathBuf {
    std::path::PathBuf::from("/opt/openshell/bin/openshell-runtime")
}

#[cfg(target_os = "linux")]
mod linux {
    #[cfg(test)]
    use super::{DEFAULT_AGENT_GID, DEFAULT_AGENT_UID, default_trusted_runtime_root};
    use super::{GuestConfig, Path};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd as _, OwnedFd};
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use openshell_core::proposals::AgentProposals;
    use openshell_core::provider_credentials::ProviderCredentialState;
    use openshell_isolation::contract::{
        BoundaryExec, BoundaryPortForward, BoundaryProcess, BoundaryTerminal, ExecSession,
        LoopbackTarget,
    };
    use openshell_supervisor_network::identity_source::ProcfsIdentityResolver;
    use openshell_supervisor_process::boundary_io::BoundaryRuntimeState;
    use openshell_supervisor_process::netns::{
        NetworkNamespace, create_conformant_netns_for_proxy,
    };
    use openshell_supervisor_process::process::{
        ProcessEnforcementMode, ProcessStatus, ResolvedProcessIdentity,
    };
    use openshell_supervisor_process::run::{AgentSignaler, spawn_workload};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::protocol::{
        AgentSpecWire, BinaryIdentityWire, ExecSpecWire, ExitStatusWire, Request, RequestEnvelope,
        Response, ResponseEnvelope, STREAM_EXIT, STREAM_STDERR, STREAM_STDIN, STREAM_STDIN_CLOSED,
        STREAM_STDOUT, SandboxPolicyWire, SignalWire, read_frame, read_stream_frame, write_frame,
        write_stream_frame,
    };

    const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn run_guest(config_path: &Path) -> Result<(), String> {
        if std::process::id() == 1 {
            prepare_pid1_filesystems()?;
        }
        let bytes = std::fs::read(config_path)
            .map_err(|error| format!("read guest config {}: {error}", config_path.display()))?;
        let config: GuestConfig = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode guest config {}: {error}", config_path.display()))?;
        validate_config(&config)?;
        openshell_supervisor_process::netns::configure_trusted_runtime_root(
            config.trusted_runtime_root.clone(),
        )
        .map_err(|error| format!("configure trusted guest helper runtime: {error}"))?;
        let child_env = serde_json::to_string(&config.child_env)
            .map_err(|error| format!("encode guest workload environment: {error}"))?;
        // This runs before the Tokio runtime or control threads exist. The process
        // supervisor consumes the serialized map and applies values only to
        // workload children.
        unsafe {
            std::env::set_var(openshell_core::sandbox_env::USER_ENVIRONMENT, child_env);
        }
        let process_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("create guest process runtime: {error}"))?;
        let runtime = Arc::new(GuestRuntime::new(
            config.clone(),
            process_runtime.handle().clone(),
        ));
        serve(config.control_port, runtime)
    }

    fn validate_config(config: &GuestConfig) -> Result<(), String> {
        if config.boundary_id.is_empty() {
            return Err("guest boundary ID must not be empty".to_string());
        }
        if config.bootstrap_token.len() < 32 {
            return Err("guest bootstrap token must contain at least 32 bytes".to_string());
        }
        if config.control_port == 0 {
            return Err("guest control port must be nonzero".to_string());
        }
        if config.agent_uid == 0 || config.agent_gid == 0 {
            return Err("guest agent UID and GID must be nonzero".to_string());
        }
        if !config.trusted_runtime_root.is_absolute() {
            return Err("guest trusted helper runtime root must be absolute".to_string());
        }
        Ok(())
    }

    fn prepare_pid1_filesystems() -> Result<(), String> {
        for path in ["/proc", "/sys", "/dev", "/run", "/tmp", "/sandbox"] {
            std::fs::create_dir_all(path).map_err(|error| format!("create {path}: {error}"))?;
        }
        mount_if_needed("proc", "/proc", "proc")?;
        mount_if_needed("sysfs", "/sys", "sysfs")?;
        mount_if_needed("devtmpfs", "/dev", "devtmpfs")?;
        std::fs::create_dir_all("/dev/pts").map_err(|error| format!("create /dev/pts: {error}"))?;
        mount_if_needed("devpts", "/dev/pts", "devpts")?;
        Ok(())
    }

    fn mount_if_needed(source: &str, target: &str, file_system: &str) -> Result<(), String> {
        let source = CString::new(source).map_err(|error| error.to_string())?;
        let target_c = CString::new(target).map_err(|error| error.to_string())?;
        let file_system = CString::new(file_system).map_err(|error| error.to_string())?;
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                file_system.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBUSY) {
            Ok(())
        } else {
            Err(format!("mount {file_system:?} on {target}: {error}"))
        }
    }

    fn serve(port: u32, runtime: Arc<GuestRuntime>) -> Result<(), String> {
        let listener = VsockListener::bind(port)
            .map_err(|error| format!("bind guest control vsock port {port}: {error}"))?;
        eprintln!("VM process supervisor leaf listening on vsock port {port}");
        loop {
            match listener.accept() {
                Ok(stream) => {
                    let runtime = runtime.clone();
                    std::thread::spawn(move || {
                        if let Err(error) = serve_one(stream, &runtime) {
                            eprintln!("VM guest control request failed: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("accept guest control connection: {error}")),
            }
        }
    }

    fn serve_one(mut stream: VsockStream, runtime: &GuestRuntime) -> Result<(), String> {
        stream
            .set_timeout(CONTROL_IO_TIMEOUT)
            .map_err(|error| format!("set control timeout: {error}"))?;
        let request: RequestEnvelope =
            read_frame(&mut stream).map_err(|error| format!("read control frame: {error}"))?;
        if !runtime.authenticate(&request) {
            let response = ResponseEnvelope {
                request_id: request.request_id,
                response: guest_error("denied", "control authentication failed"),
            };
            return write_frame(&mut stream, &response)
                .map_err(|error| format!("write control frame: {error}"));
        }
        match request.request.clone() {
            Request::Exec { spec } => {
                let (process_id, session) = match runtime.start_exec(spec) {
                    Ok(started) => started,
                    Err(response) => {
                        return write_frame(
                            &mut stream,
                            &ResponseEnvelope {
                                request_id: request.request_id,
                                response,
                            },
                        )
                        .map_err(|error| format!("write exec error response: {error}"));
                    }
                };
                write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::ExecStarted {
                            process_id: process_id.clone(),
                            pty: session.terminal.is_some(),
                        },
                    },
                )
                .map_err(|error| format!("write exec start response: {error}"))?;
                return runtime.stream_exec(stream, &process_id, session);
            }
            Request::PortForward { host, port } => {
                let target = LoopbackTarget::new(host, port)
                    .map_err(|error| format!("validate port-forward target: {error}"))?;
                let mut target = runtime
                    .connect_port(target)
                    .map_err(|error| format!("connect guest loopback port: {error}"))?;
                write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::PortConnected,
                    },
                )
                .map_err(|error| format!("write port-forward response: {error}"))?;
                runtime.process_runtime.block_on(async move {
                    let mut stream = stream.into_tokio()?;
                    tokio::io::copy_bidirectional(&mut stream, &mut target)
                        .await
                        .map_err(|error| format!("bridge guest loopback stream: {error}"))
                })?;
                return Ok(());
            }
            Request::AcceptNetwork => {
                let (mut target, identity) = runtime.accept_network()?;
                write_frame(
                    &mut stream,
                    &ResponseEnvelope {
                        request_id: request.request_id,
                        response: Response::NetworkConnected { identity },
                    },
                )
                .map_err(|error| format!("write network mediation response: {error}"))?;
                runtime.process_runtime.block_on(async move {
                    let mut stream = stream.into_tokio()?;
                    tokio::io::copy_bidirectional(&mut stream, &mut target)
                        .await
                        .map_err(|error| format!("bridge guest network mediation stream: {error}"))
                })?;
                return Ok(());
            }
            _ => {}
        }
        let response = ResponseEnvelope {
            request_id: request.request_id,
            response: runtime.dispatch(request),
        };
        write_frame(&mut stream, &response).map_err(|error| format!("write control frame: {error}"))
    }

    struct GuestRuntime {
        config: GuestConfig,
        process_runtime: tokio::runtime::Handle,
        state: Mutex<RuntimeState>,
        next_exec_id: AtomicU64,
        exec_handles: Mutex<std::collections::HashMap<String, ExecHandle>>,
    }

    struct ExecHandle {
        process: Arc<dyn BoundaryProcess>,
        terminal: Option<Arc<dyn BoundaryTerminal>>,
    }

    enum RuntimeState {
        AwaitingAttach,
        Bound(PreparedBoundary),
        Ready(PreparedBoundary),
        Running(Arc<ManagedProcess>),
    }

    #[derive(Clone)]
    struct PreparedBoundary {
        netns: Option<Arc<NetworkNamespace>>,
        network_listener: Option<Arc<tokio::net::TcpListener>>,
        proxy_port: u16,
    }

    async fn bridge_exec_stream(
        stream: tokio::net::UnixStream,
        session: ExecSession,
    ) -> Result<(), String> {
        let ExecSession {
            process,
            stdin,
            stdout,
            stderr,
            terminal: _,
        } = session;
        let (mut network_reader, network_writer) = tokio::io::split(stream);
        let network_writer = Arc::new(tokio::sync::Mutex::new(network_writer));

        let stdin_task = stdin.map(|mut stdin| {
            tokio::spawn(async move {
                while let Some((channel, payload)) = read_stream_frame(&mut network_reader).await? {
                    match channel {
                        STREAM_STDIN => stdin.write_all(&payload).await?,
                        STREAM_STDIN_CLOSED => {
                            stdin.shutdown().await?;
                            break;
                        }
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected host-to-guest stream channel",
                            ));
                        }
                    }
                }
                Ok::<(), io::Error>(())
            })
        });

        let stdout_task = tokio::spawn(pump_exec_output(
            stdout,
            STREAM_STDOUT,
            network_writer.clone(),
        ));
        let stderr_task = stderr.map(|stderr| {
            tokio::spawn(pump_exec_output(
                stderr,
                STREAM_STDERR,
                network_writer.clone(),
            ))
        });

        let status = process
            .wait()
            .await
            .map_err(|error| format!("wait for guest exec: {error}"))?;
        stdout_task
            .await
            .map_err(|error| format!("join guest exec stdout: {error}"))?
            .map_err(|error| format!("stream guest exec stdout: {error}"))?;
        if let Some(stderr_task) = stderr_task {
            stderr_task
                .await
                .map_err(|error| format!("join guest exec stderr: {error}"))?
                .map_err(|error| format!("stream guest exec stderr: {error}"))?;
        }
        let exit = serde_json::to_vec(&ExitStatusWire::from(status))
            .map_err(|error| format!("encode guest exec exit: {error}"))?;
        write_stream_frame(&mut *network_writer.lock().await, STREAM_EXIT, &exit)
            .await
            .map_err(|error| format!("write guest exec exit: {error}"))?;
        if let Some(stdin_task) = stdin_task {
            stdin_task.abort();
        }
        Ok(())
    }

    async fn pump_exec_output(
        mut output: openshell_isolation::contract::BoundaryOutput,
        channel: u8,
        writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::UnixStream>>>,
    ) -> io::Result<()> {
        let mut buffer = vec![0; 16 * 1024];
        loop {
            let read = output.read(&mut buffer).await?;
            if read == 0 {
                return Ok(());
            }
            write_stream_frame(&mut *writer.lock().await, channel, &buffer[..read]).await?;
        }
    }

    impl GuestRuntime {
        fn new(config: GuestConfig, process_runtime: tokio::runtime::Handle) -> Self {
            Self {
                config,
                process_runtime,
                state: Mutex::new(RuntimeState::AwaitingAttach),
                next_exec_id: AtomicU64::new(1),
                exec_handles: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn dispatch(&self, envelope: RequestEnvelope) -> Response {
            if !self.authenticate(&envelope) {
                return guest_error("denied", "control authentication failed");
            }
            match envelope.request {
                Request::Attach { policy } => self.attach((*policy).into()),
                Request::Confirm => self.confirm(),
                Request::StartAgent {
                    sandbox_id,
                    spec,
                    policy,
                    ca_cert,
                    ca_bundle,
                    provider_env,
                } => self.start_agent(sandbox_id, spec, *policy, ca_cert, ca_bundle, provider_env),
                Request::Wait { process_id } => self.wait(&process_id),
                Request::Signal { process_id, signal } => self.signal(&process_id, signal),
                Request::Terminate { process_id } => self.terminate(&process_id),
                Request::ExecSignal { process_id, signal } => self.signal_exec(&process_id, signal),
                Request::Resize {
                    process_id,
                    cols,
                    rows,
                } => self.resize_exec(&process_id, cols, rows),
                Request::Exec { .. } | Request::PortForward { .. } | Request::AcceptNetwork => {
                    guest_error("invalid", "streaming request used on control path")
                }
            }
        }

        fn authenticate(&self, envelope: &RequestEnvelope) -> bool {
            constant_time_eq(
                envelope.boundary_id.as_bytes(),
                self.config.boundary_id.as_bytes(),
            ) && constant_time_eq(
                envelope.bootstrap_token.as_bytes(),
                self.config.bootstrap_token.as_bytes(),
            )
        }

        fn start_exec(&self, spec: ExecSpecWire) -> Result<(String, ExecSession), Response> {
            let executor = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return Err(guest_error("invalid", "agent process has not been started"));
                };
                process.boundary_exec()
            };
            let session = self
                .process_runtime
                .block_on(executor.exec(spec.into()))
                .map_err(|error| guest_error("failed", error.to_string()))?;
            let process_id = format!("exec-{}", self.next_exec_id.fetch_add(1, Ordering::Relaxed));
            lock(&self.exec_handles).insert(
                process_id.clone(),
                ExecHandle {
                    process: session.process.clone(),
                    terminal: session.terminal.clone(),
                },
            );
            Ok((process_id, session))
        }

        fn signal_exec(&self, process_id: &str, signal: SignalWire) -> Response {
            let process = lock(&self.exec_handles)
                .get(process_id)
                .map(|handle| handle.process.clone());
            let Some(process) = process else {
                return guest_error("invalid", "unknown exec process ID");
            };
            match self.process_runtime.block_on(process.signal(signal.into())) {
                Ok(()) => Response::Signaled,
                Err(error) => guest_error("failed", error.to_string()),
            }
        }

        fn resize_exec(&self, process_id: &str, cols: u16, rows: u16) -> Response {
            let terminal = lock(&self.exec_handles)
                .get(process_id)
                .and_then(|handle| handle.terminal.clone());
            let Some(terminal) = terminal else {
                return guest_error("invalid", "exec process has no terminal");
            };
            match self.process_runtime.block_on(terminal.resize(cols, rows)) {
                Ok(()) => Response::Resized,
                Err(error) => guest_error("failed", error.to_string()),
            }
        }

        fn connect_port(
            &self,
            target: LoopbackTarget,
        ) -> Result<openshell_isolation::contract::BoundaryDuplexStream, String> {
            let port_forward = {
                let state = lock(&self.state);
                let RuntimeState::Running(process) = &*state else {
                    return Err("agent process has not been started".to_string());
                };
                process.port_forward()
            };
            self.process_runtime
                .block_on(port_forward.connect(target))
                .map_err(|error| error.to_string())
        }

        fn accept_network(&self) -> Result<(tokio::net::TcpStream, BinaryIdentityWire), String> {
            let process = loop {
                let running = {
                    let state = lock(&self.state);
                    match &*state {
                        RuntimeState::Running(process) => Some(process.clone()),
                        _ => None,
                    }
                };
                if let Some(process) = running {
                    break process;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let listener = process
                .network_listener()
                .ok_or_else(|| "network mediation requested for a non-proxy policy".to_string())?;
            let (stream, workload_addr) = self
                .process_runtime
                .block_on(listener.accept())
                .map_err(|error| format!("accept guest proxy connection: {error}"))?;
            let proxy_addr = stream
                .local_addr()
                .map_err(|error| format!("read guest proxy address: {error}"))?;
            let identity = process
                .identity_resolver()
                .resolve_connection(workload_addr, proxy_addr);
            Ok((stream, BinaryIdentityWire::from(identity)))
        }

        fn stream_exec(
            &self,
            stream: VsockStream,
            process_id: &str,
            session: ExecSession,
        ) -> Result<(), String> {
            let process_id = process_id.to_string();
            self.process_runtime.block_on(async move {
                let stream = stream.into_tokio()?;
                bridge_exec_stream(stream, session).await
            })?;
            lock(&self.exec_handles).remove(&process_id);
            Ok(())
        }

        fn attach(&self, policy: openshell_core::policy::SandboxPolicy) -> Response {
            let mut state = lock(&self.state);
            match &*state {
                RuntimeState::AwaitingAttach => {
                    let prepared = match PreparedBoundary::establish(&self.process_runtime, &policy)
                    {
                        Ok(prepared) => prepared,
                        Err(error) => return guest_error("failed", error),
                    };
                    *state = RuntimeState::Bound(prepared);
                    Response::Attached
                }
                RuntimeState::Bound(_) => Response::Attached,
                _ => guest_error("invalid", "boundary has already advanced past attach"),
            }
        }

        fn confirm(&self) -> Response {
            let mut state = lock(&self.state);
            match &*state {
                RuntimeState::Bound(prepared) => {
                    if let Err(error) = prepared.confirm(&self.process_runtime) {
                        return guest_error("failed", error);
                    }
                    *state = RuntimeState::Ready(prepared.clone());
                    Response::Confirmed
                }
                RuntimeState::Ready(_) => Response::Confirmed,
                RuntimeState::AwaitingAttach => {
                    guest_error("invalid", "boundary must be attached before confirm")
                }
                RuntimeState::Running(_) => {
                    guest_error("invalid", "boundary has already started its agent")
                }
            }
        }

        fn start_agent(
            &self,
            sandbox_id: String,
            spec: AgentSpecWire,
            policy: SandboxPolicyWire,
            ca_cert: Option<Vec<u8>>,
            ca_bundle: Option<Vec<u8>>,
            provider_env: std::collections::HashMap<String, String>,
        ) -> Response {
            let mut state = lock(&self.state);
            let RuntimeState::Ready(prepared) = &*state else {
                return guest_error("invalid", "boundary must be confirmed before start_agent");
            };
            let ca_file_paths = match install_ca_material(ca_cert, ca_bundle) {
                Ok(paths) => paths,
                Err(error) => return guest_error("failed", error),
            };
            let launch = ManagedProcessLaunch {
                sandbox_id,
                spec,
                policy: policy.into(),
                resolved_identity: ResolvedProcessIdentity::new(
                    Some(self.config.agent_uid),
                    Some(self.config.agent_gid),
                ),
                provider_env,
                ca_file_paths,
            };
            let process =
                match ManagedProcess::spawn(&self.process_runtime, launch, prepared.clone()) {
                    Ok(process) => Arc::new(process),
                    Err(error) => return guest_error("failed", error),
                };
            let process_id = process.process_id();
            *state = RuntimeState::Running(process);
            Response::Started { process_id }
        }

        fn wait(&self, process_id: &str) -> Response {
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.wait() {
                Ok(status) => Response::Exited { status },
                Err(error) => guest_error("failed", error),
            }
        }

        fn signal(&self, process_id: &str, signal: SignalWire) -> Response {
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.signal(signal) {
                Ok(()) => Response::Signaled,
                Err(error) => guest_error("terminated", error),
            }
        }

        fn terminate(&self, process_id: &str) -> Response {
            let process = match self.running_process(process_id) {
                Ok(process) => process,
                Err(response) => return response,
            };
            match process.signal(SignalWire::Kill) {
                Ok(()) => Response::Terminated,
                Err(_) if process.has_exited() => Response::Terminated,
                Err(error) => guest_error("failed", error),
            }
        }

        fn running_process(&self, process_id: &str) -> Result<Arc<ManagedProcess>, Response> {
            let state = lock(&self.state);
            let RuntimeState::Running(process) = &*state else {
                return Err(guest_error("invalid", "agent process has not been started"));
            };
            if process.process_id() != process_id {
                return Err(guest_error("invalid", "unknown process ID"));
            }
            Ok(process.clone())
        }
    }

    impl PreparedBoundary {
        fn establish(
            runtime: &tokio::runtime::Handle,
            policy: &openshell_core::policy::SandboxPolicy,
        ) -> Result<Self, String> {
            let netns = create_conformant_netns_for_proxy(policy)
                .map_err(|error| format!("establish guest workload network namespace: {error}"))?
                .map(Arc::new);
            let proxy_port = policy
                .network
                .proxy
                .as_ref()
                .and_then(|proxy| proxy.http_addr)
                .map_or(3128, |address| address.port());
            let network_listener = if let Some(netns) = netns.as_ref() {
                let address = std::net::SocketAddr::new(netns.host_ip(), proxy_port);
                Some(Arc::new(
                    runtime
                        .block_on(tokio::net::TcpListener::bind(address))
                        .map_err(|error| {
                            format!("bind guest mediation listener {address}: {error}")
                        })?,
                ))
            } else {
                None
            };
            Ok(Self {
                netns,
                network_listener,
                proxy_port,
            })
        }

        fn confirm(&self, runtime: &tokio::runtime::Handle) -> Result<(), String> {
            if let Some(netns) = self.netns.as_ref() {
                runtime
                    .block_on(
                        netns
                            .egress_ceiling_verifier()
                            .verify_bounded(self.proxy_port, Duration::from_secs(2)),
                    )
                    .map_err(|error| format!("verify guest egress ceiling: {error}"))?;
                if self.network_listener.is_none() {
                    return Err("guest proxy namespace has no mediation listener".to_string());
                }
            }
            Ok(())
        }
    }

    fn install_ca_material(
        ca_cert: Option<Vec<u8>>,
        ca_bundle: Option<Vec<u8>>,
    ) -> Result<Option<(std::path::PathBuf, std::path::PathBuf)>, String> {
        let (ca_cert, ca_bundle) = match (ca_cert, ca_bundle) {
            (Some(ca_cert), Some(ca_bundle)) => (ca_cert, ca_bundle),
            (None, None) => return Ok(None),
            _ => {
                return Err(
                    "VM proxy CA certificate and bundle must be supplied together".to_string(),
                );
            }
        };
        let directory = std::path::PathBuf::from("/run/openshell/proxy-ca");
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("create guest proxy CA directory: {error}"))?;
        let ca_path = directory.join("ca.crt");
        let bundle_path = directory.join("ca-bundle.crt");
        std::fs::write(&ca_path, ca_cert)
            .map_err(|error| format!("write guest proxy CA: {error}"))?;
        std::fs::write(&bundle_path, ca_bundle)
            .map_err(|error| format!("write guest proxy CA bundle: {error}"))?;
        Ok(Some((ca_path, bundle_path)))
    }

    type ProcessExit = Result<ExitStatusWire, String>;
    type SharedProcessExit = Arc<(Mutex<Option<ProcessExit>>, Condvar)>;

    struct ManagedProcess {
        pid: i32,
        signaler: AgentSignaler,
        exit: SharedProcessExit,
        boundary_exec: Arc<dyn BoundaryExec>,
        port_forward: Arc<dyn BoundaryPortForward>,
        network_listener: Option<Arc<tokio::net::TcpListener>>,
        identity_resolver: ProcfsIdentityResolver,
        _netns: Option<Arc<NetworkNamespace>>,
    }

    struct ManagedProcessLaunch {
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: openshell_core::policy::SandboxPolicy,
        resolved_identity: ResolvedProcessIdentity,
        provider_env: std::collections::HashMap<String, String>,
        ca_file_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    }

    impl ManagedProcess {
        fn spawn(
            runtime: &tokio::runtime::Handle,
            launch: ManagedProcessLaunch,
            prepared: PreparedBoundary,
        ) -> Result<Self, String> {
            let ManagedProcessLaunch {
                sandbox_id,
                spec,
                policy,
                resolved_identity,
                provider_env,
                ca_file_paths,
            } = launch;
            if spec.program.is_empty() {
                return Err("agent program must not be empty".to_string());
            }
            let boundary_runtime = BoundaryRuntimeState::new();
            let entrypoint_pid = Arc::new(AtomicU32::new(0));
            let mut spawned = runtime
                .block_on(spawn_workload(
                    &spec.program,
                    &spec.args,
                    spec.workdir.as_deref(),
                    spec.timeout_secs,
                    spec.interactive,
                    Some(&sandbox_id),
                    None,
                    None,
                    false,
                    &policy,
                    resolved_identity,
                    ProcessEnforcementMode::Full,
                    entrypoint_pid.clone(),
                    None,
                    ProviderCredentialState::from_child_env_snapshot(0, provider_env.clone()),
                    provider_env,
                    ca_file_paths,
                    AgentProposals::default(),
                    prepared.netns.as_deref(),
                    None,
                    None,
                    Some(boundary_runtime),
                ))
                .map_err(|error| format!("start process supervisor leaf: {error}"))?;
            let pid = i32::try_from(spawned.pid())
                .map_err(|_| "process supervisor PID does not fit i32".to_string())?;
            let signaler = spawned.signaler();
            let boundary_exec = spawned.boundary_exec();
            let port_forward = spawned.port_forward();
            let network_listener = prepared.network_listener.clone();
            let exit = Arc::new((Mutex::new(None), Condvar::new()));
            let reaper_exit = exit.clone();
            runtime.spawn(async move {
                let result = spawned
                    .wait()
                    .await
                    .map(process_status)
                    .map_err(|error| format!("wait for process supervisor leaf: {error}"));
                let (state, changed) = &*reaper_exit;
                *lock(state) = Some(result);
                changed.notify_all();
            });
            Ok(Self {
                pid,
                signaler,
                exit,
                boundary_exec,
                port_forward,
                network_listener,
                identity_resolver: ProcfsIdentityResolver { entrypoint_pid },
                _netns: prepared.netns,
            })
        }

        fn process_id(&self) -> String {
            self.pid.to_string()
        }

        fn wait(&self) -> ProcessExit {
            let (state, changed) = &*self.exit;
            let mut exit = lock(state);
            while exit.is_none() {
                exit = changed
                    .wait(exit)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            exit.as_ref().expect("exit checked above").clone()
        }

        fn signal(&self, signal: SignalWire) -> Result<(), String> {
            if self.has_exited() {
                return Err("agent process has already exited".to_string());
            }
            let result = match signal {
                SignalWire::Term => self.signaler.term(),
                SignalWire::Kill => self.signaler.kill(),
                SignalWire::Int => self.signaler.interrupt(),
                SignalWire::Hup => self.signaler.hangup(),
            };
            result.map_err(|error| format!("signal process supervisor group: {error}"))
        }

        fn has_exited(&self) -> bool {
            let (state, _) = &*self.exit;
            lock(state).is_some()
        }

        fn boundary_exec(&self) -> Arc<dyn BoundaryExec> {
            self.boundary_exec.clone()
        }

        fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
            self.port_forward.clone()
        }

        fn network_listener(&self) -> Option<Arc<tokio::net::TcpListener>> {
            self.network_listener.clone()
        }

        fn identity_resolver(&self) -> ProcfsIdentityResolver {
            self.identity_resolver.clone()
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn process_status(status: ProcessStatus) -> ExitStatusWire {
        status.signal().map_or_else(
            || ExitStatusWire::Exited(status.code()),
            ExitStatusWire::Signaled,
        )
    }

    fn guest_error(kind: &str, message: impl Into<String>) -> Response {
        Response::Error {
            kind: kind.to_string(),
            message: message.into(),
        }
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        let max_len = left.len().max(right.len());
        let mut difference = left.len() ^ right.len();
        for index in 0..max_len {
            let left_byte = left.get(index).copied().unwrap_or_default();
            let right_byte = right.get(index).copied().unwrap_or_default();
            difference |= usize::from(left_byte ^ right_byte);
        }
        difference == 0
    }

    struct VsockListener {
        fd: OwnedFd,
    }

    impl VsockListener {
        fn bind(port: u32) -> io::Result<Self> {
            let family = libc::sa_family_t::try_from(libc::AF_VSOCK).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "AF_VSOCK exceeds sa_family_t")
            })?;
            let address_length = libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "sockaddr_vm exceeds socklen_t")
                })?;
            let raw_fd =
                unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if raw_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let address = libc::sockaddr_vm {
                svm_family: family,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: libc::VMADDR_CID_ANY,
                svm_zero: [0; 4],
            };
            let result = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    address_length,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::listen(fd.as_raw_fd(), 16) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
        }

        fn accept(&self) -> io::Result<VsockStream> {
            let raw_fd = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw_fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(VsockStream {
                    file: unsafe { File::from_raw_fd(raw_fd) },
                })
            }
        }
    }

    struct VsockStream {
        file: File,
    }

    impl VsockStream {
        fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
            let option_length =
                libc::socklen_t::try_from(size_of::<libc::timeval>()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "timeval exceeds socklen_t")
                })?;
            let timeout = libc::timeval {
                tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
                tv_usec: timeout.subsec_micros().into(),
            };
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                let result = unsafe {
                    libc::setsockopt(
                        self.file.as_raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&raw const timeout).cast(),
                        option_length,
                    )
                };
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }

        fn into_tokio(self) -> Result<tokio::net::UnixStream, String> {
            let stream =
                unsafe { std::os::unix::net::UnixStream::from_raw_fd(self.file.into_raw_fd()) };
            stream
                .set_nonblocking(true)
                .map_err(|error| format!("set guest vsock nonblocking: {error}"))?;
            tokio::net::UnixStream::from_std(stream)
                .map_err(|error| format!("register guest vsock with Tokio: {error}"))
        }
    }

    impl Read for VsockStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.file.read(buffer)
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.file.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn guest_config_debug_redacts_token() {
            let config = GuestConfig {
                boundary_id: "sandbox-1".to_string(),
                bootstrap_token: "never-log-this-never-log-this".to_string(),
                control_port: 5500,
                agent_uid: DEFAULT_AGENT_UID,
                agent_gid: DEFAULT_AGENT_GID,
                trusted_runtime_root: default_trusted_runtime_root(),
                child_env: std::collections::HashMap::new(),
            };
            let debug = format!("{config:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("never-log-this"));
        }

        #[test]
        fn constant_time_comparison_checks_length_and_content() {
            assert!(constant_time_eq(b"same", b"same"));
            assert!(!constant_time_eq(b"same", b"different"));
            assert!(!constant_time_eq(b"same", b"sam"));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::run_guest;

#[cfg(not(target_os = "linux"))]
pub fn run_guest(_config_path: &Path) -> Result<(), String> {
    Err("the VM guest process leaf is supported only on Linux guests".to_string())
}
