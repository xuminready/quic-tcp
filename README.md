# QUIC-TCP
A Rust-based TCP proxy that transparently bridges connections via QUIC (over UDP).

## Features

### 1. Protocol Tunneling (QUIC <-> TCP)
This implementation serves as a bridge, forwarding data between QUIC and TCP streams.

### 2. Concurrency & Scalability
The proxy supports multiple concurrent connections using Rust's `mio` library.
- `tcp-to-quic`: A server that accepts TCP connections and forwards them through a single QUIC connection.
- `quic-to-tcp`: A server that listens on a QUIC connection and proxies incoming streams to separate TCP connections.

### 3. State Management
Robust handling of QUIC connection states:
- **Early Data**: The proxy supports sending and receiving early data before the main connection handshake completes.
- **Session Management**: Streams are tracked and managed until they are closed.
- **Partial Writes**: Buffering logic handles cases where data cannot be fully written to the underlying transport (QUIC or TCP) in a single operation.

## Usage

### Build

Since this project uses the `quiche` library (which compiles **BoringSSL** from source), you need to install some build prerequisites depending on your operating system:

#### Linux (Debian/Ubuntu/gLinux)
Requires `cmake`:
```bash
sudo apt update && sudo apt install -y cmake
```

#### macOS
Requires Xcode Command Line Tools and `cmake` (installable via Homebrew):
```bash
# Install Xcode Command Line Tools (if not already installed)
xcode-select --install

# Install CMake
brew install cmake
```
*(Optional: `brew install go nasm` to enable BoringSSL assembly optimizations).*

#### Windows
Requires a C++ compiler (Visual Studio), `cmake`, and `go` (required by BoringSSL build scripts):
1. **Visual Studio**: Install [Visual Studio Community](https://visualstudio.microsoft.com/downloads/) and select the **Desktop development with C++** workload.
2. **CMake**: Install [CMake for Windows](https://cmake.org/download/) (ensure it is added to your system PATH).
3. **Go**: Install [Go](https://go.dev/doc/install).
4. **NASM** (Optional): Install [NASM](https://www.nasm.us/) for assembly optimizations.

You can quickly install CMake, Go, and NASM via `winget` in PowerShell:
```powershell
winget install kitware.cmake
winget install Gold.Go
winget install NASM
```

#### Compile
Once the prerequisites are installed, build the project using cargo:
```bash
cargo build --release
```

### Run

#### Start TCP to QUIC Server (Client-side Proxy)
Listens on a local TCP port and forwards traffic over QUIC to the remote proxy.
```bash
RUST_LOG=debug cargo run --release --bin tcp-to-quic <Local_TCP_IP:Port> <Remote_UDP_IP:Port>

# Example:
RUST_LOG=debug cargo run --release --bin tcp-to-quic 127.0.0.1:8080 127.0.0.1:4433
```

#### Start QUIC to TCP Server (Server-side Proxy)
Listens on a UDP port for QUIC connections and proxies them to the target TCP server.
```bash
RUST_LOG=debug cargo run --release --bin quic-to-tcp <Local_UDP_IP:Port> <Remote_TCP_IP:Port>

# Example:
RUST_LOG=debug cargo run --release --bin quic-to-tcp 127.0.0.1:4433 127.0.0.1:80
```

### P2P Mode (UDP Hole Punching)

The proxy supports a P2P mode that allows establishing QUIC connections between two peers even if both are behind NATs (firewalls), without requiring port forwarding. This is achieved using a rendezvous server to coordinate **UDP Hole Punching**.

#### 1. Start the Rendezvous Server
Run this server on a machine with a publicly reachable IP (or locally for testing):
```bash
RUST_LOG=debug cargo run --release --bin rendezvous-server [port]

# Example (defaults to port 5000):
RUST_LOG=debug cargo run --release --bin rendezvous-server 5000
```

#### 2. Start the Server Proxy (`quic-to-tcp`) in P2P Mode
This peer will register itself at the rendezvous server and wait for a client connection.
```bash
RUST_LOG=debug cargo run --release --bin quic-to-tcp p2p <Rendezvous_Server_IP:Port> <Name> <Capacity> <Location> <Remote_TCP_IP:Port>

# Example (registering as 'my-server' and forwarding to a local web server on port 80):
RUST_LOG=debug cargo run --release --bin quic-to-tcp p2p 127.0.0.1:5000 my-server 100Mbps US-West 127.0.0.1:80
```

#### 3. Start the Client Proxy (`tcp-to-quic`) in P2P Mode
This peer will query the rendezvous server, list all available servers, prompt you to select one, perform UDP hole punching, and then start the QUIC tunnel.
```bash
RUST_LOG=debug cargo run --release --bin tcp-to-quic p2p <Rendezvous_Server_IP:Port> <Local_TCP_IP:Port>

# Example (listening on local port 8080):
RUST_LOG=debug cargo run --release --bin tcp-to-quic p2p 127.0.0.1:5000 127.0.0.1:8080
```
*When prompted, select the server number (e.g., `1`) and press Enter. The peers will automatically perform hole punching and establish the secure QUIC tunnel.*

## Project Structure
- [`src/lib.rs`](src/lib.rs): Core library containing the `Session` struct (managing QUIC/TCP streams, buffering, and flushing) and shared utility functions (IP validation, token generation, etc.).
- [`src/bin/tcp_to_quic.rs`](src/bin/tcp_to_quic.rs): Binary for the TCP-to-QUIC proxy server (supports Direct and P2P modes).
- [`src/bin/quic_to_tcp.rs`](src/bin/quic_to_tcp.rs): Binary for the QUIC-to-TCP proxy server (supports Direct and P2P modes).
- [`src/bin/rendezvous_server.rs`](src/bin/rendezvous_server.rs): Binary for the Rendezvous Server (helps peers perform UDP hole punching).

## Certificate Generation
The QUIC server (`quic-to-tcp`) requires a TLS certificate and private key (`cert.crt` and `cert.key`) to be present in its working directory.

For development and testing, you can generate a self-signed certificate using `openssl`:

```bash
openssl req -x509 -newkey rsa:2048 -keyout cert.key -out cert.crt -days 365 -nodes -subj "/CN=localhost"
```

*Note: The `-nodes` flag is required to store the private key without a password, allowing the proxy to load it automatically.*

## Dependencies
- `quiche`: QUIC implementation.
- `mio`: Asynchronous I/O.
- `log` / `env_logger`: Logging.
- `ring`: Cryptographic operations (used for token generation).
  