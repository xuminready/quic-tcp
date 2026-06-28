# QUIC-TCP
A Rust-based TCP proxy that transparently bridges connections via QUIC (over UDP).

## Features

### 1. Protocol Tunneling (QUIC <-> TCP)
This implementation serves as a bridge, forwarding data between QUIC and TCP streams.

### 2. Concurrency & Scalability
The proxy supports multiple concurrent connections using Rust's `mio` library.
- `tcp_to_quic`: A server that accepts TCP connections and forwards them through a single QUIC connection.
- `quic_to_tcp`: A server that listens on a QUIC connection and proxies incoming streams to separate TCP connections.

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
cargo run --release --bin tcp_to_quic <Local_TCP_IP> <Local_Port> <Remote_UDP_IP> <Remote_Port>

# Example:
cargo run --release --bin tcp_to_quic 127.0.0.1 8080 127.0.0.1 4433
```

#### Start QUIC to TCP Server (Server-side Proxy)
Listens on a UDP port for QUIC connections and proxies them to the target TCP server.
```bash
cargo run --release --bin quic_to_tcp <Local_UDP_IP> <Local_Port> <Remote_TCP_IP> <Remote_Port>

# Example:
cargo run --release --bin quic_to_tcp 127.0.0.1 4433 127.0.0.1 80
```

## Project Structure
- [`src/lib.rs`](src/lib.rs): Core library containing the `Session` struct (managing QUIC/TCP streams, buffering, and flushing) and shared utility functions (IP validation, token generation, etc.).
- [`src/bin/tcp_to_quic.rs`](src/bin/tcp_to_quic.rs): Binary for the TCP-to-QUIC proxy server.
- [`src/bin/quic_to_tcp.rs`](src/bin/quic_to_tcp.rs): Binary for the QUIC-to-TCP proxy server.

## Dependencies
- `quiche`: QUIC implementation.
- `mio`: Asynchronous I/O.
- `log` / `env_logger`: Logging.
- `ring`: Cryptographic operations (used for token generation).
  