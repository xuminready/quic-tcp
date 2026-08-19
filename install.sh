#!/usr/bin/env bash
# ==============================================================================
# QUIC-TCP Installation & Systemd Service Configuration Script
# ==============================================================================
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "          QUIC-TCP Installation & Systemd Service Setup               "
echo "======================================================================"
echo -e "${NC}"

# Check for root / sudo permissions
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installation script must be run as root or with sudo.${NC}"
    echo -e "Please run: ${BOLD}sudo $0${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/quic-tcp"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

# 1. Ensure Cargo/Rust or pre-built binaries exist
echo -e "${BLUE}[1/5] Checking build artifacts...${NC}"
if [ ! -f "$SCRIPT_DIR/target/release/quic-to-tcp" ] || \
   [ ! -f "$SCRIPT_DIR/target/release/tcp-to-quic" ] || \
   [ ! -f "$SCRIPT_DIR/target/release/rendezvous-server" ]; then
    echo -e "${YELLOW}[*] Release binaries not found. Building release binaries with cargo...${NC}"
    
    # Locate cargo if running under sudo
    if command -v cargo &>/dev/null; then
        CARGO_BIN="cargo"
    elif [ -f "$HOME/.cargo/bin/cargo" ]; then
        CARGO_BIN="$HOME/.cargo/bin/cargo"
    elif [ -n "$SUDO_USER" ] && [ -f "$(eval echo ~$SUDO_USER)/.cargo/bin/cargo" ]; then
        CARGO_BIN="$(eval echo ~$SUDO_USER)/.cargo/bin/cargo"
    else
        echo -e "${RED}[ERROR] 'cargo' not found in PATH or standard user directories.${NC}"
        echo "Please install Rust (https://rustup.rs) or run 'cargo build --release' before installing."
        exit 1
    fi

    (cd "$SCRIPT_DIR" && $CARGO_BIN build --release)
fi

# 2. Install binaries to /usr/local/bin
echo -e "${BLUE}[2/5] Installing binaries to ${BIN_DIR}...${NC}"
mkdir -p "$BIN_DIR"
cp -f "$SCRIPT_DIR/target/release/quic-to-tcp" "$BIN_DIR/quic-to-tcp"
cp -f "$SCRIPT_DIR/target/release/tcp-to-quic" "$BIN_DIR/tcp-to-quic"
cp -f "$SCRIPT_DIR/target/release/rendezvous-server" "$BIN_DIR/rendezvous-server"
chmod 755 "$BIN_DIR/quic-to-tcp" "$BIN_DIR/tcp-to-quic" "$BIN_DIR/rendezvous-server"
echo -e "${GREEN}[+] Binaries installed successfully to ${BIN_DIR}.${NC}"

# 3. Create configuration directory
mkdir -p "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"

# Ensure TLS certificate exists for quic-to-tcp in /etc/quic-tcp
generate_certificate() {
    if [ ! -f "$CONFIG_DIR/cert.crt" ] || [ ! -f "$CONFIG_DIR/cert.key" ]; then
        echo -e "${YELLOW}[*] Generating self-signed TLS certificate for QUIC server in ${CONFIG_DIR}...${NC}"
        openssl req -x509 -newkey rsa:2048 -keyout "$CONFIG_DIR/cert.key" -out "$CONFIG_DIR/cert.crt" \
            -days 3650 -nodes -subj "/CN=localhost" 2>/dev/null
        chmod 600 "$CONFIG_DIR/cert.key"
        chmod 644 "$CONFIG_DIR/cert.crt"
        echo -e "${GREEN}[+] Generated $CONFIG_DIR/cert.crt and $CONFIG_DIR/cert.key.${NC}"
    fi
}

# 4. Interactive Configuration
echo -e "\n${BLUE}[3/5] Component Selection & Configuration${NC}"
echo "Which service(s) would you like to configure and enable on this machine?"
echo "  1) Rendezvous Server (Signaling & Coordination)"
echo "  2) Server Proxy      (quic-to-tcp: exposes local/remote TCP server over QUIC)"
echo "  3) Client Proxy      (tcp-to-quic: bridges local TCP port to QUIC tunnel)"
echo "  4) All Services"
echo "  5) Binaries only (Do not configure systemd services now)"

read -rp "Enter choice [1-5] (default: 2): " COMPONENT_CHOICE
COMPONENT_CHOICE=${COMPONENT_CHOICE:-2}

configure_rendezvous() {
    echo -e "\n${CYAN}--- Configuring Rendezvous Server ---${NC}"
    read -rp "Enter UDP listening port [5050]: " RDV_PORT
    RDV_PORT=${RDV_PORT:-5050}

    cat <<EOF > "$CONFIG_DIR/rendezvous-server.env"
# QUIC-TCP Rendezvous Server Configuration
PORT=${RDV_PORT}
RUST_LOG=info
RENDEZVOUS_PEER_TIMEOUT_SECS=30
RENDEZVOUS_CLEANUP_TIMEOUT_SECS=120
EOF
    chmod 600 "$CONFIG_DIR/rendezvous-server.env"

    cp -f "$SCRIPT_DIR/systemd/rendezvous-server.service" "$SYSTEMD_DIR/rendezvous-server.service"
    systemctl daemon-reload
    systemctl enable --now rendezvous-server.service
    echo -e "${GREEN}[+] rendezvous-server.service configured and started on port ${RDV_PORT}.${NC}"
}

configure_quic_to_tcp() {
    generate_certificate
    echo -e "\n${CYAN}--- Configuring Server Proxy (quic-to-tcp) ---${NC}"
    echo "Select Operating Mode:"
    echo "  1) P2P Mode (Authenticated UDP Hole Punching via Rendezvous) [Recommended]"
    echo "  2) Direct Mode (Static UDP port / Public IP)"
    read -rp "Enter choice [1-2] (default: 1): " MODE_CHOICE
    MODE_CHOICE=${MODE_CHOICE:-1}

    if [ "$MODE_CHOICE" -eq 1 ]; then
        read -rp "Enter Rendezvous Server Address (IP:Port) [127.0.0.1:5050]: " RDV_ADDR
        RDV_ADDR=${RDV_ADDR:-127.0.0.1:5050}

        read -rp "Enter Target TCP Server Address to forward to (IP:Port) [127.0.0.1:8080]: " TCP_ADDR
        TCP_ADDR=${TCP_ADDR:-127.0.0.1:8080}

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="p2p ${RDV_ADDR} ${TCP_ADDR} ${PASSCODE}"
    else
        read -rp "Enter Local UDP Listening Address (IP:Port) [0.0.0.0:4433]: " UDP_ADDR
        UDP_ADDR=${UDP_ADDR:-0.0.0.0:4433}

        read -rp "Enter Target TCP Server Address to forward to (IP:Port) [127.0.0.1:8080]: " TCP_ADDR
        TCP_ADDR=${TCP_ADDR:-127.0.0.1:8080}

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="${UDP_ADDR} ${TCP_ADDR} ${PASSCODE}"
    fi

    cat <<EOF > "$CONFIG_DIR/quic-to-tcp.env"
# QUIC-TCP Server Proxy Configuration
ARGS="${ARGS}"
RUST_LOG=info
EOF
    chmod 600 "$CONFIG_DIR/quic-to-tcp.env"

    cp -f "$SCRIPT_DIR/systemd/quic-to-tcp.service" "$SYSTEMD_DIR/quic-to-tcp.service"
    systemctl daemon-reload
    systemctl enable --now quic-to-tcp.service
    echo -e "${GREEN}[+] quic-to-tcp.service configured and started.${NC}"
}

configure_tcp_to_quic() {
    echo -e "\n${CYAN}--- Configuring Client Proxy (tcp-to-quic) ---${NC}"
    echo "Select Operating Mode:"
    echo "  1) P2P Mode (Connect to Rendezvous Server) [Recommended]"
    echo "  2) Direct Mode (Connect directly to Remote QUIC UDP Server)"
    read -rp "Enter choice [1-2] (default: 1): " MODE_CHOICE
    MODE_CHOICE=${MODE_CHOICE:-1}

    if [ "$MODE_CHOICE" -eq 1 ]; then
        read -rp "Enter Rendezvous Server Address (IP:Port) [127.0.0.1:5050]: " RDV_ADDR
        RDV_ADDR=${RDV_ADDR:-127.0.0.1:5050}

        read -rp "Enter Local TCP Listening Port (IP:Port) [127.0.0.1:7070]: " TCP_LOCAL_ADDR
        TCP_LOCAL_ADDR=${TCP_LOCAL_ADDR:-127.0.0.1:7070}

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="p2p ${RDV_ADDR} ${TCP_LOCAL_ADDR} ${PASSCODE}"
    else
        read -rp "Enter Local TCP Listening Port (IP:Port) [127.0.0.1:7070]: " TCP_LOCAL_ADDR
        TCP_LOCAL_ADDR=${TCP_LOCAL_ADDR:-127.0.0.1:7070}

        read -rp "Enter Remote QUIC Server Address (IP:Port) [127.0.0.1:4433]: " QUIC_REMOTE_ADDR
        QUIC_REMOTE_ADDR=${QUIC_REMOTE_ADDR:-127.0.0.1:4433}

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="${TCP_LOCAL_ADDR} ${QUIC_REMOTE_ADDR} ${PASSCODE}"
    fi

    cat <<EOF > "$CONFIG_DIR/tcp-to-quic.env"
# QUIC-TCP Client Proxy Configuration
ARGS="${ARGS}"
RUST_LOG=info
EOF
    chmod 600 "$CONFIG_DIR/tcp-to-quic.env"

    cp -f "$SCRIPT_DIR/systemd/tcp-to-quic.service" "$SYSTEMD_DIR/tcp-to-quic.service"
    systemctl daemon-reload
    systemctl enable --now tcp-to-quic.service
    echo -e "${GREEN}[+] tcp-to-quic.service configured and started.${NC}"
}

case "$COMPONENT_CHOICE" in
    1)
        configure_rendezvous
        ;;
    2)
        configure_quic_to_tcp
        ;;
    3)
        configure_tcp_to_quic
        ;;
    4)
        configure_rendezvous
        configure_quic_to_tcp
        configure_tcp_to_quic
        ;;
    5)
        echo -e "${YELLOW}[*] Skipping systemd service setup. Binaries installed in ${BIN_DIR}.${NC}"
        ;;
    *)
        echo -e "${RED}[ERROR] Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac

# 5. Summary & Useful Commands
echo -e "\n${BLUE}[5/5] Setup Complete!${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
echo -e "${BOLD}Installed Binaries:${NC}"
echo "  - /usr/local/bin/rendezvous-server"
echo "  - /usr/local/bin/quic-to-tcp"
echo "  - /usr/local/bin/tcp-to-quic"
echo ""
echo -e "${BOLD}Configuration Files & Environment:${NC}"
echo "  - /etc/quic-tcp/"
echo ""
echo -e "${BOLD}Useful Service Management Commands:${NC}"
echo "  - Check status:   systemctl status <service_name> (e.g. quic-to-tcp, tcp-to-quic, rendezvous-server)"
echo "  - View live logs: journalctl -u <service_name> -f"
echo "  - Restart:        systemctl restart <service_name>"
echo "  - Stop:           systemctl stop <service_name>"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
