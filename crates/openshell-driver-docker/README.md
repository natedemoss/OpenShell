# openshell-driver-docker

Docker-backed compute and isolation driver for local Linux OpenShell gateways.

The driver connects to `[openshell.drivers.docker].socket_path` when configured.
Otherwise, it selects a standard local Docker socket and falls back to
`/var/run/docker.sock` when Docker is explicitly enabled.

## Runtime model

Docker uses RFC 0012 supervisor-owned boundary creation. The compute driver
resolves the immutable workload image and launches a native
`openshell-sandbox` process on the gateway host. That supervisor registers the
Docker `IsolationBackend`, creates the container, confirms enforcement, starts
the workload, and exposes exec through the normal supervisor relay.

The workload container contains no OpenShell binary, gateway credential, TLS
private key, or supervisor capability set. The dedicated mode runs the
workload as the gateway user's numeric UID and GID so the unprivileged host
supervisor can capture syscall arguments and hash the calling executable. It
uses `/` as the initial working directory and does not provide driver mounts.

The backend binds a private host Unix socket before container creation and
passes OCI seccomp `listenerPath`, `listenerMetadata`, and `SCMP_ACT_NOTIFY`
through the Docker seccomp profile. runc sends the listener FD directly to the
host supervisor with `SCM_RIGHTS` before the workload starts. The container
drops every Linux capability and has direct networking disabled.

The listener injects connected sockets for workload TCP and DNS operations.
DNS queries travel directly to the supervisor policy-DNS service and return
short-lived synthetic addresses. A later connection to a synthetic address is
bound to the queried hostname, calling-binary identity, allowed port, policy
generation, and pinned real addresses. The supervisor consumes these streams
without binding a container-visible proxy port or setting proxy environment
variables. Direct real-IP and non-mediated UDP traffic fail closed.

For TLS termination, the backend read-only mounts the generated public CA and
combined public trust bundle. CA private key material remains in host
supervisor memory.

The current implementation supports create, confirm, start, wait,
signal-main-process, delete, Docker exec, policy DNS, transparent TCP, and TLS
termination. Port forwarding, exec signaling, GPU devices, resource limits,
driver mounts, images that require root, and durable running-boundary recovery
remain unsupported and fail closed.

## Supervisor binary resolution

The native host supervisor is resolved in this order:

1. `supervisor_bin` in `[openshell.drivers.docker]`.
2. `supervisor_image` in `[openshell.drivers.docker]`, extracting
   `/openshell-sandbox` to a host cache.
3. A sibling `openshell-sandbox` next to `openshell-gateway`.
4. A local Linux cargo target build for the Docker daemon architecture.
5. The release-matched default supervisor image.

The resolved binary executes on the host; it is never mounted into the
workload container.

## Gateway authentication

The compute driver writes the sandbox JWT to a host-only state directory and
passes that path only to the native supervisor. HTTPS CA, certificate, and key
paths likewise remain on the host. The supervisor connects to the gateway over
the configured `grpc_endpoint`; host aliases such as
`host.openshell.internal` are normalized to loopback for the native process.

## Testing

The standard Docker runner exercises this implementation:

```shell
mise run e2e:docker
```

Set `OPENSHELL_E2E_SANDBOX_IMAGE` to test another workload image supported by
the smoke scenario.
