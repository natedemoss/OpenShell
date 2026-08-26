// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Driver-private, length-delimited JSON protocol carried over virtio-vsock.

use std::fmt;
use std::io::{self, Read, Write};

use openshell_core::policy::{
    FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkMode, NetworkPolicy,
    ProcessPolicy, ProxyPolicy, SandboxPolicy,
};
use openshell_isolation::AgentSpec;
use openshell_isolation::contract::{
    BinaryIdentity, BoundaryExitStatus, BoundarySignal, ExecSpec, ResolveError, Sha256Digest,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const STREAM_STDIN: u8 = 0;
pub const STREAM_STDOUT: u8 = 1;
pub const STREAM_STDERR: u8 = 2;
pub const STREAM_EXIT: u8 = 3;
pub const STREAM_STDIN_CLOSED: u8 = 4;
pub const MAX_STREAM_FRAME_BYTES: usize = 64 * 1024;

pub async fn write_stream_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    channel: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_STREAM_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "VM stream frame exceeds limit",
        ));
    }
    writer.write_u8(channel).await?;
    writer
        .write_u32(payload.len().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VM stream frame length overflow",
            )
        })?)
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

pub async fn read_stream_frame(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<(u8, Vec<u8>)>> {
    let channel = match reader.read_u8().await {
        Ok(channel) => channel,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let declared = reader.read_u32().await? as usize;
    if declared > MAX_STREAM_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("VM stream frame is too large: {declared} bytes"),
        ));
    }
    let mut payload = vec![0; declared];
    reader.read_exact(&mut payload).await?;
    Ok(Some((channel, payload)))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub request_id: u64,
    pub boundary_id: String,
    pub bootstrap_token: String,
    pub request: Request,
}

impl fmt::Debug for RequestEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestEnvelope")
            .field("request_id", &self.request_id)
            .field("boundary_id", &self.boundary_id)
            .field("bootstrap_token", &"<redacted>")
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    Attach {
        policy: Box<SandboxPolicyWire>,
    },
    Confirm,
    StartAgent {
        sandbox_id: String,
        spec: AgentSpecWire,
        policy: Box<SandboxPolicyWire>,
        ca_cert: Option<Vec<u8>>,
        ca_bundle: Option<Vec<u8>>,
        provider_env: std::collections::HashMap<String, String>,
    },
    Wait {
        process_id: String,
    },
    Signal {
        process_id: String,
        signal: SignalWire,
    },
    Terminate {
        process_id: String,
    },
    Exec {
        spec: ExecSpecWire,
    },
    ExecSignal {
        process_id: String,
        signal: SignalWire,
    },
    Resize {
        process_id: String,
        cols: u16,
        rows: u16,
    },
    PortForward {
        host: std::net::IpAddr,
        port: u16,
    },
    AcceptNetwork,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attach { policy: _ } => formatter
                .debug_struct("Attach")
                .field("policy", &"<redacted>")
                .finish(),
            Self::Confirm => formatter.write_str("Confirm"),
            Self::StartAgent {
                sandbox_id,
                spec,
                policy: _,
                ca_cert,
                ca_bundle,
                provider_env,
            } => formatter
                .debug_struct("StartAgent")
                .field("sandbox_id", sandbox_id)
                .field("spec", spec)
                .field("policy", &"<redacted>")
                .field("ca_cert_present", &ca_cert.is_some())
                .field("ca_bundle_present", &ca_bundle.is_some())
                .field(
                    "provider_env_keys",
                    &provider_env.keys().collect::<Vec<_>>(),
                )
                .finish(),
            Self::Wait { process_id } => formatter
                .debug_struct("Wait")
                .field("process_id", process_id)
                .finish(),
            Self::Signal { process_id, signal } => formatter
                .debug_struct("Signal")
                .field("process_id", process_id)
                .field("signal", signal)
                .finish(),
            Self::Terminate { process_id } => formatter
                .debug_struct("Terminate")
                .field("process_id", process_id)
                .finish(),
            Self::Exec { spec } => formatter.debug_tuple("Exec").field(spec).finish(),
            Self::ExecSignal { process_id, signal } => formatter
                .debug_struct("ExecSignal")
                .field("process_id", process_id)
                .field("signal", signal)
                .finish(),
            Self::Resize {
                process_id,
                cols,
                rows,
            } => formatter
                .debug_struct("Resize")
                .field("process_id", process_id)
                .field("cols", cols)
                .field("rows", rows)
                .finish(),
            Self::PortForward { host, port } => formatter
                .debug_struct("PortForward")
                .field("host", host)
                .field("port", port)
                .finish(),
            Self::AcceptNetwork => formatter.write_str("AcceptNetwork"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub request_id: u64,
    pub response: Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Attached,
    Confirmed,
    Started { process_id: String },
    Exited { status: ExitStatusWire },
    Signaled,
    Terminated,
    ExecStarted { process_id: String, pty: bool },
    Resized,
    PortConnected,
    NetworkConnected { identity: BinaryIdentityWire },
    Error { kind: String, message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentityWire {
    pub binary_path: Option<std::path::PathBuf>,
    pub binary_digest: Option<String>,
    pub ancestors: Vec<std::path::PathBuf>,
    pub cmdline_paths: Vec<std::path::PathBuf>,
    pub resolve_error: Option<String>,
}

impl From<Result<BinaryIdentity, ResolveError>> for BinaryIdentityWire {
    fn from(identity: Result<BinaryIdentity, ResolveError>) -> Self {
        match identity {
            Ok(identity) => Self {
                binary_path: Some(identity.binary_path),
                binary_digest: identity.binary_digest.map(|digest| digest.to_string()),
                ancestors: identity.ancestors,
                cmdline_paths: identity.cmdline_paths,
                resolve_error: None,
            },
            Err(error) => Self {
                binary_path: None,
                binary_digest: None,
                ancestors: Vec::new(),
                cmdline_paths: Vec::new(),
                resolve_error: Some(error.to_string()),
            },
        }
    }
}

impl BinaryIdentityWire {
    pub fn into_result(self) -> Result<BinaryIdentity, ResolveError> {
        if let Some(error) = self.resolve_error {
            return Err(ResolveError::Failed(error));
        }
        let binary_path = self
            .binary_path
            .ok_or_else(|| ResolveError::Failed("VM identity omitted binary path".to_string()))?;
        let binary_digest = self
            .binary_digest
            .map(|digest| digest.parse::<Sha256Digest>())
            .transpose()?;
        Ok(BinaryIdentity {
            binary_path,
            binary_digest,
            ancestors: self.ancestors,
            cmdline_paths: self.cmdline_paths,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSpecWire {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub pty: bool,
}

impl From<ExecSpec> for ExecSpecWire {
    fn from(spec: ExecSpec) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            env: spec.env,
            workdir: spec.workdir,
            pty: spec.pty,
        }
    }
}

impl From<ExecSpecWire> for ExecSpec {
    fn from(spec: ExecSpecWire) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            env: spec.env,
            workdir: spec.workdir,
            pty: spec.pty,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSpecWire {
    pub program: String,
    pub args: Vec<String>,
    pub workdir: Option<String>,
    pub timeout_secs: u64,
    pub interactive: bool,
}

impl From<AgentSpec> for AgentSpecWire {
    fn from(spec: AgentSpec) -> Self {
        Self {
            program: spec.program,
            args: spec.args,
            workdir: spec.workdir,
            timeout_secs: spec.timeout_secs,
            interactive: spec.interactive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicyWire {
    pub version: u32,
    pub read_only: Vec<std::path::PathBuf>,
    pub read_write: Vec<std::path::PathBuf>,
    pub include_workdir: bool,
    pub network: NetworkModeWire,
    pub proxy_addr: Option<std::net::SocketAddr>,
    pub landlock: LandlockCompatibilityWire,
    pub run_as_user: Option<String>,
    pub run_as_group: Option<String>,
}

impl From<SandboxPolicy> for SandboxPolicyWire {
    fn from(policy: SandboxPolicy) -> Self {
        Self {
            version: policy.version,
            read_only: policy.filesystem.read_only,
            read_write: policy.filesystem.read_write,
            include_workdir: policy.filesystem.include_workdir,
            network: NetworkModeWire::from(policy.network.mode),
            proxy_addr: policy.network.proxy.and_then(|proxy| proxy.http_addr),
            landlock: LandlockCompatibilityWire::from(policy.landlock.compatibility),
            run_as_user: policy.process.run_as_user,
            run_as_group: policy.process.run_as_group,
        }
    }
}

impl From<SandboxPolicyWire> for SandboxPolicy {
    fn from(policy: SandboxPolicyWire) -> Self {
        let proxy = matches!(policy.network, NetworkModeWire::Proxy).then_some(ProxyPolicy {
            http_addr: policy.proxy_addr,
        });
        Self {
            version: policy.version,
            filesystem: FilesystemPolicy {
                read_only: policy.read_only,
                read_write: policy.read_write,
                include_workdir: policy.include_workdir,
            },
            network: NetworkPolicy {
                mode: policy.network.into(),
                proxy,
            },
            landlock: LandlockPolicy {
                compatibility: policy.landlock.into(),
            },
            process: ProcessPolicy {
                run_as_user: policy.run_as_user,
                run_as_group: policy.run_as_group,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkModeWire {
    Block,
    Proxy,
    Allow,
}

impl From<NetworkMode> for NetworkModeWire {
    fn from(mode: NetworkMode) -> Self {
        match mode {
            NetworkMode::Block => Self::Block,
            NetworkMode::Proxy => Self::Proxy,
            NetworkMode::Allow => Self::Allow,
        }
    }
}

impl From<NetworkModeWire> for NetworkMode {
    fn from(mode: NetworkModeWire) -> Self {
        match mode {
            NetworkModeWire::Block => Self::Block,
            NetworkModeWire::Proxy => Self::Proxy,
            NetworkModeWire::Allow => Self::Allow,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockCompatibilityWire {
    BestEffort,
    HardRequirement,
}

impl From<LandlockCompatibility> for LandlockCompatibilityWire {
    fn from(compatibility: LandlockCompatibility) -> Self {
        match compatibility {
            LandlockCompatibility::BestEffort => Self::BestEffort,
            LandlockCompatibility::HardRequirement => Self::HardRequirement,
        }
    }
}

impl From<LandlockCompatibilityWire> for LandlockCompatibility {
    fn from(compatibility: LandlockCompatibilityWire) -> Self {
        match compatibility {
            LandlockCompatibilityWire::BestEffort => Self::BestEffort,
            LandlockCompatibilityWire::HardRequirement => Self::HardRequirement,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalWire {
    Term,
    Kill,
    Int,
    Hup,
}

impl From<BoundarySignal> for SignalWire {
    fn from(signal: BoundarySignal) -> Self {
        match signal {
            BoundarySignal::Term => Self::Term,
            BoundarySignal::Kill => Self::Kill,
            BoundarySignal::Int => Self::Int,
            BoundarySignal::Hup => Self::Hup,
        }
    }
}

impl From<SignalWire> for BoundarySignal {
    fn from(signal: SignalWire) -> Self {
        match signal {
            SignalWire::Term => Self::Term,
            SignalWire::Kill => Self::Kill,
            SignalWire::Int => Self::Int,
            SignalWire::Hup => Self::Hup,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExitStatusWire {
    Exited(i32),
    Signaled(i32),
}

impl From<ExitStatusWire> for BoundaryExitStatus {
    fn from(status: ExitStatusWire) -> Self {
        match status {
            ExitStatusWire::Exited(code) => Self::Exited(code),
            ExitStatusWire::Signaled(signal) => Self::Signaled(signal),
        }
    }
}

impl From<BoundaryExitStatus> for ExitStatusWire {
    fn from(status: BoundaryExitStatus) -> Self {
        match status {
            BoundaryExitStatus::Exited(code) => Self::Exited(code),
            BoundaryExitStatus::Signaled(signal) => Self::Signaled(signal),
        }
    }
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(message).map_err(FrameError::Serialize)?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, FrameError> {
    let header: [u8; 4] = frame
        .get(..4)
        .ok_or(FrameError::Truncated)?
        .try_into()
        .map_err(|_| FrameError::Truncated)?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(declared));
    }
    let payload = frame.get(4..).ok_or(FrameError::Truncated)?;
    if payload.len() != declared {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }
    serde_json::from_slice(payload).map_err(FrameError::Deserialize)
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let declared = u32::from_be_bytes(header) as usize;
    if declared > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::TooLarge(declared));
    }
    let mut frame = Vec::with_capacity(4 + declared);
    frame.extend_from_slice(&header);
    frame.resize(4 + declared, 0);
    reader.read_exact(&mut frame[4..])?;
    decode_frame(&frame)
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<(), FrameError> {
    let frame = encode_frame(message)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("control frame is truncated")]
    Truncated,
    #[error("control frame is too large: {0} bytes")]
    TooLarge(usize),
    #[error("control frame declared {declared} bytes but contained {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("serialize control frame: {0}")]
    Serialize(serde_json::Error),
    #[error("deserialize control frame: {0}")]
    Deserialize(serde_json::Error),
    #[error("read or write control frame: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_redacts_token() {
        let request = RequestEnvelope {
            request_id: 7,
            boundary_id: "sandbox-1".to_string(),
            bootstrap_token: "never-log-this".to_string(),
            request: Request::StartAgent {
                sandbox_id: "sandbox-1".to_string(),
                spec: AgentSpecWire {
                    program: "/bin/true".to_string(),
                    args: Vec::new(),
                    workdir: Some("/sandbox".to_string()),
                    timeout_secs: 5,
                    interactive: false,
                },
                policy: Box::new(SandboxPolicyWire::from(SandboxPolicy {
                    version: 1,
                    filesystem: FilesystemPolicy::default(),
                    network: NetworkPolicy::default(),
                    landlock: LandlockPolicy::default(),
                    process: ProcessPolicy::default(),
                })),
                ca_cert: Some(b"test certificate".to_vec()),
                ca_bundle: Some(b"test bundle".to_vec()),
                provider_env: std::collections::HashMap::from([(
                    "OPENAI_API_KEY".to_string(),
                    "test credential".to_string(),
                )]),
            },
        };
        let frame = encode_frame(&request).expect("encode request");
        let decoded: RequestEnvelope = decode_frame(&frame).expect("decode request");
        assert_eq!(decoded, request);
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("never-log-this"));
        assert!(!debug.contains("test credential"));
        assert!(!debug.contains("test certificate"));
        assert!(!debug.contains("test bundle"));
        assert!(debug.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn rejects_declared_oversize() {
        let oversized = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1).expect("test size fits u32");
        let mut frame = Vec::from(oversized.to_be_bytes());
        frame.extend_from_slice(b"{}");
        assert!(matches!(
            decode_frame::<RequestEnvelope>(&frame),
            Err(FrameError::TooLarge(_))
        ));
    }
}
