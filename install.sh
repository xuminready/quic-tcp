#!/usr/bin/env bash
# ==============================================================================
# QUIC-TCP Installation & Multi-Instance Systemd Service Setup Script
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/quic-tcp"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

# Privilege helper functions - only request sudo when writing to system directories
run_root() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

write_root_file() {
    local target_file="$1"
    local mode="${2:-600}"
    if [ "$EUID" -eq 0 ]; then
        cat > "$target_file"
        chmod "$mode" "$target_file"
    else
        sudo tee "$target_file" > /dev/null
        sudo chmod "$mode" "$target_file"
    fi
}

# Function to list all running and configured QUIC-TCP services
list_services() {
    echo -e "\n${CYAN}${BOLD}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}                 Configured & Running QUIC-TCP Services               ${NC}"
    echo -e "${CYAN}${BOLD}======================================================================${NC}"

    local found=0

    # 1. Check systemd units
    if command -v systemctl &>/dev/null; then
        local units
        units=$(systemctl list-units --type=service --all 'quic-to-tcp*' 'tcp-to-quic*' 'rendezvous-server*' --no-legend --no-pager 2>/dev/null | awk '{print $1}' || true)
        
        # Also check unit files in /etc/systemd/system
        local unit_files
        unit_files=$(find "$SYSTEMD_DIR" -maxdepth 1 -name "quic-to-tcp*.service" -o -name "tcp-to-quic*.service" -o -name "rendezvous-server*.service" 2>/dev/null | xargs -n 1 basename 2>/dev/null || true)

        # Merge and deduplicate
        local all_services
        all_services=$(echo -e "${units}\n${unit_files}" | grep -v '^$' | grep -v '@\.service$' | sort -u || true)

        if [ -n "$all_services" ]; then
            for svc in $all_services; do
                found=1
                local is_active
                is_active=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
                local is_enabled
                is_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")

                local status_color="$YELLOW"
                if [ "$is_active" = "active" ]; then
                    status_color="$GREEN"
                elif [ "$is_active" = "failed" ]; then
                    status_color="$RED"
                fi

                # Extract instance name
                local instance=""
                if [[ "$svc" =~ @(.+)\.service$ ]]; then
                    instance="${BASH_REMATCH[1]}"
                fi

                # Read config details if available
                local conf_file=""
                local details=""
                if [[ "$svc" =~ ^quic-to-tcp ]]; then
                    if [ -n "$instance" ] && [ -f "$CONFIG_DIR/quic-to-tcp-${instance}.env" ]; then
                        conf_file="$CONFIG_DIR/quic-to-tcp-${instance}.env"
                    elif [ -f "$CONFIG_DIR/quic-to-tcp.env" ]; then
                        conf_file="$CONFIG_DIR/quic-to-tcp.env"
                    fi
                elif [[ "$svc" =~ ^tcp-to-quic ]]; then
                    if [ -n "$instance" ] && [ -f "$CONFIG_DIR/tcp-to-quic-${instance}.env" ]; then
                        conf_file="$CONFIG_DIR/tcp-to-quic-${instance}.env"
                    elif [ -f "$CONFIG_DIR/tcp-to-quic.env" ]; then
                        conf_file="$CONFIG_DIR/tcp-to-quic.env"
                    fi
                elif [[ "$svc" =~ ^rendezvous-server ]]; then
                    if [ -n "$instance" ] && [ -f "$CONFIG_DIR/rendezvous-server-${instance}.env" ]; then
                        conf_file="$CONFIG_DIR/rendezvous-server-${instance}.env"
                    elif [ -f "$CONFIG_DIR/rendezvous-server.env" ]; then
                        conf_file="$CONFIG_DIR/rendezvous-server.env"
                    fi
                fi

                if [ -n "$conf_file" ] && [ -f "$conf_file" ]; then
                    details=$(grep -E '^(ARGS|PORT)=' "$conf_file" | tr '\n' ' ' || true)
                fi

                echo -e "• ${BOLD}${svc}${NC}"
                echo -e "    Status:   ${status_color}${is_active}${NC} (${is_enabled})"
                if [ -n "$details" ]; then
                    echo -e "    Config:   ${details}"
                fi
                if [ -n "$conf_file" ]; then
                    echo -e "    Env File: ${conf_file}"
                fi
                echo ""
            done
        fi
    fi

    # 2. Check for orphan env files in /etc/quic-tcp
    if [ -d "$CONFIG_DIR" ]; then
        local orphan_envs
        orphan_envs=$(find "$CONFIG_DIR" -maxdepth 1 -name "*.env" 2>/dev/null | sort || true)
        if [ -n "$orphan_envs" ] && [ "$found" -eq 0 ]; then
            echo -e "${YELLOW}Config files found in ${CONFIG_DIR}:${NC}"
            for env in $orphan_envs; do
                echo "  - $env: $(grep -E '^(ARGS|PORT)=' "$env" || true)"
                found=1
            done
        fi
    fi

    if [ "$found" -eq 0 ]; then
        echo -e "${YELLOW}No QUIC-TCP services are currently installed or running.${NC}\n"
    fi
    echo -e "${CYAN}${BOLD}======================================================================${NC}\n"
}

# Check if direct list flag is provided
if [ "$1" = "list" ] || [ "$1" = "--list" ] || [ "$1" = "-l" ]; then
    list_services
    exit 0
fi

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "          QUIC-TCP Installation & Systemd Service Setup               "
echo "======================================================================"
echo -e "${NC}"

# 1. Ensure Cargo/Rust or pre-built binaries exist (Runs as current user without sudo)
echo -e "${BLUE}[1/5] Checking build artifacts...${NC}"
if [ ! -f "$SCRIPT_DIR/target/release/quic-to-tcp" ] || \
   [ ! -f "$SCRIPT_DIR/target/release/tcp-to-quic" ] || \
   [ ! -f "$SCRIPT_DIR/target/release/rendezvous-server" ]; then
    echo -e "${YELLOW}[*] Release binaries not found. Building release binaries with cargo...${NC}"
    
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

# 2. Install binaries to /usr/local/bin (Elevates only if needed)
echo -e "${BLUE}[2/5] Installing binaries to ${BIN_DIR}...${NC}"
run_root mkdir -p "$BIN_DIR"
run_root cp -f "$SCRIPT_DIR/target/release/quic-to-tcp" "$BIN_DIR/quic-to-tcp"
run_root cp -f "$SCRIPT_DIR/target/release/tcp-to-quic" "$BIN_DIR/tcp-to-quic"
run_root cp -f "$SCRIPT_DIR/target/release/rendezvous-server" "$BIN_DIR/rendezvous-server"
run_root chmod 755 "$BIN_DIR/quic-to-tcp" "$BIN_DIR/tcp-to-quic" "$BIN_DIR/rendezvous-server"
echo -e "${GREEN}[+] Binaries installed successfully to ${BIN_DIR}.${NC}"

# 3. Create configuration directory & install systemd templates
run_root mkdir -p "$CONFIG_DIR"
run_root chmod 755 "$CONFIG_DIR"

install_systemd_templates() {
    run_root cp -f "$SCRIPT_DIR/systemd/rendezvous-server@.service" "$SYSTEMD_DIR/rendezvous-server@.service"
    run_root cp -f "$SCRIPT_DIR/systemd/quic-to-tcp@.service" "$SYSTEMD_DIR/quic-to-tcp@.service"
    run_root cp -f "$SCRIPT_DIR/systemd/tcp-to-quic@.service" "$SYSTEMD_DIR/tcp-to-quic@.service"
    run_root systemctl daemon-reload
}
install_systemd_templates

# Ensure TLS certificate exists for quic-to-tcp in /etc/quic-tcp
generate_certificate() {
    if [ ! -f "$CONFIG_DIR/cert.crt" ] || [ ! -f "$CONFIG_DIR/cert.key" ]; then
        echo -e "${YELLOW}[*] Generating self-signed TLS certificate for QUIC server in ${CONFIG_DIR}...${NC}"
        TMP_DIR="$(mktemp -d)"
        openssl req -x509 -newkey rsa:2048 -keyout "$TMP_DIR/cert.key" -out "$TMP_DIR/cert.crt" \
            -days 3650 -nodes -subj "/CN=localhost" 2>/dev/null
        run_root cp -f "$TMP_DIR/cert.key" "$CONFIG_DIR/cert.key"
        run_root cp -f "$TMP_DIR/cert.crt" "$CONFIG_DIR/cert.crt"
        run_root chmod 600 "$CONFIG_DIR/cert.key"
        run_root chmod 644 "$CONFIG_DIR/cert.crt"
        rm -rf "$TMP_DIR"
        echo -e "${GREEN}[+] Generated $CONFIG_DIR/cert.crt and $CONFIG_DIR/cert.key.${NC}"
    fi
}

# 4. Interactive Configuration
echo -e "\n${BLUE}[3/5] Component Selection & Multi-Instance Configuration${NC}"
echo "Which service would you like to configure and start?"
echo "  1) Rendezvous Server (Signaling & Hole Punching Coordination)"
echo "  2) Server Proxy      (quic-to-tcp: exposes local/remote TCP server over QUIC)"
echo "  3) Client Proxy      (tcp-to-quic: bridges local TCP port to QUIC tunnel)"
echo "  4) List Running / Configured Services"
echo "  5) Binaries only (Do not configure systemd services now)"

read -rp "Enter choice [1-5] (default: 2): " COMPONENT_CHOICE
COMPONENT_CHOICE=${COMPONENT_CHOICE:-2}

configure_rendezvous() {
    echo -e "\n${CYAN}--- Configuring Rendezvous Server Instance ---${NC}"
    read -rp "Enter UDP listening port [5050]: " RDV_PORT
    RDV_PORT=${RDV_PORT:-5050}

    read -rp "Enter unique instance name/identifier [${RDV_PORT}]: " INSTANCE_NAME
    INSTANCE_NAME=${INSTANCE_NAME:-$RDV_PORT}
    # Sanitize instance name
    INSTANCE_NAME=$(echo "$INSTANCE_NAME" | tr -cd 'a-zA-Z0-9_-')

    cat <<EOF | write_root_file "$CONFIG_DIR/rendezvous-server-${INSTANCE_NAME}.env" 600
# QUIC-TCP Rendezvous Server Configuration (${INSTANCE_NAME})
PORT=${RDV_PORT}
RUST_LOG=info
RENDEZVOUS_PEER_TIMEOUT_SECS=30
RENDEZVOUS_CLEANUP_TIMEOUT_SECS=120
EOF

    local service_unit="rendezvous-server@${INSTANCE_NAME}.service"
    run_root systemctl daemon-reload
    run_root systemctl enable --now "$service_unit"
    echo -e "${GREEN}[+] ${service_unit} configured and started on UDP port ${RDV_PORT}.${NC}"
}

configure_quic_to_tcp() {
    generate_certificate
    echo -e "\n${CYAN}--- Configuring Server Proxy Instance (quic-to-tcp) ---${NC}"
    echo "Select Operating Mode:"
    echo "  1) P2P Mode (Authenticated UDP Hole Punching via Rendezvous) [Recommended]"
    echo "  2) Direct Mode (Static UDP port / Public IP)"
    read -rp "Enter choice [1-2] (default: 1): " MODE_CHOICE
    MODE_CHOICE=${MODE_CHOICE:-1}

    local DEFAULT_INSTANCE="8080"
    if [ "$MODE_CHOICE" -eq 1 ]; then
        read -rp "Enter Rendezvous Server Address (IP:Port) [127.0.0.1:5050]: " RDV_ADDR
        RDV_ADDR=${RDV_ADDR:-127.0.0.1:5050}

        read -rp "Enter Target TCP Server Address to forward to (IP:Port) [127.0.0.1:8080]: " TCP_ADDR
        TCP_ADDR=${TCP_ADDR:-127.0.0.1:8080}
        DEFAULT_INSTANCE=$(echo "$TCP_ADDR" | awk -F: '{print $NF}')

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="p2p ${RDV_ADDR} ${TCP_ADDR} ${PASSCODE}"
    else
        read -rp "Enter Local UDP Listening Address (IP:Port) [0.0.0.0:4433]: " UDP_ADDR
        UDP_ADDR=${UDP_ADDR:-0.0.0.0:4433}
        DEFAULT_INSTANCE=$(echo "$UDP_ADDR" | awk -F: '{print $NF}')

        read -rp "Enter Target TCP Server Address to forward to (IP:Port) [127.0.0.1:8080]: " TCP_ADDR
        TCP_ADDR=${TCP_ADDR:-127.0.0.1:8080}

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="${UDP_ADDR} ${TCP_ADDR} ${PASSCODE}"
    fi

    read -rp "Enter unique instance name/identifier [${DEFAULT_INSTANCE}]: " INSTANCE_NAME
    INSTANCE_NAME=${INSTANCE_NAME:-$DEFAULT_INSTANCE}
    INSTANCE_NAME=$(echo "$INSTANCE_NAME" | tr -cd 'a-zA-Z0-9_-')

    cat <<EOF | write_root_file "$CONFIG_DIR/quic-to-tcp-${INSTANCE_NAME}.env" 600
# QUIC-TCP Server Proxy Configuration (${INSTANCE_NAME})
ARGS="${ARGS}"
RUST_LOG=info
EOF

    local service_unit="quic-to-tcp@${INSTANCE_NAME}.service"
    run_root systemctl daemon-reload
    run_root systemctl enable --now "$service_unit"
    echo -e "${GREEN}[+] ${service_unit} configured and started.${NC}"
}

configure_tcp_to_quic() {
    echo -e "\n${CYAN}--- Configuring Client Proxy Instance (tcp-to-quic) ---${NC}"
    echo "Select Operating Mode:"
    echo "  1) P2P Mode (Connect to Rendezvous Server) [Recommended]"
    echo "  2) Direct Mode (Connect directly to Remote QUIC UDP Server)"
    read -rp "Enter choice [1-2] (default: 1): " MODE_CHOICE
    MODE_CHOICE=${MODE_CHOICE:-1}

    local DEFAULT_INSTANCE="7070"
    if [ "$MODE_CHOICE" -eq 1 ]; then
        read -rp "Enter Rendezvous Server Address (IP:Port) [127.0.0.1:5050]: " RDV_ADDR
        RDV_ADDR=${RDV_ADDR:-127.0.0.1:5050}

        read -rp "Enter Local TCP Listening Port (IP:Port) [127.0.0.1:7070]: " TCP_LOCAL_ADDR
        TCP_LOCAL_ADDR=${TCP_LOCAL_ADDR:-127.0.0.1:7070}
        DEFAULT_INSTANCE=$(echo "$TCP_LOCAL_ADDR" | awk -F: '{print $NF}')

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="p2p ${RDV_ADDR} ${TCP_LOCAL_ADDR} ${PASSCODE}"
    else
        read -rp "Enter Local TCP Listening Port (IP:Port) [127.0.0.1:7070]: " TCP_LOCAL_ADDR
        TCP_LOCAL_ADDR=${TCP_LOCAL_ADDR:-127.0.0.1:7070}
        DEFAULT_INSTANCE=$(echo "$TCP_LOCAL_ADDR" | awk -F: '{print $NF}')

        read -rp "Enter Remote QUIC Server Address (IP:Port) [127.0.0.1:4433]: " QUIC_REMOTE_ADDR
        QUIC_REMOTE_ADDR=${QUIC_REMOTE_ADDR:-127.0.0.1:4433}

        read -rp "Enter Shared Secret Passcode [my_tunnel_secret]: " PASSCODE
        PASSCODE=${PASSCODE:-my_tunnel_secret}

        ARGS="${TCP_LOCAL_ADDR} ${QUIC_REMOTE_ADDR} ${PASSCODE}"
    fi

    read -rp "Enter unique instance name/identifier [${DEFAULT_INSTANCE}]: " INSTANCE_NAME
    INSTANCE_NAME=${INSTANCE_NAME:-$DEFAULT_INSTANCE}
    INSTANCE_NAME=$(echo "$INSTANCE_NAME" | tr -cd 'a-zA-Z0-9_-')

    cat <<EOF | write_root_file "$CONFIG_DIR/tcp-to-quic-${INSTANCE_NAME}.env" 600
# QUIC-TCP Client Proxy Configuration (${INSTANCE_NAME})
ARGS="${ARGS}"
RUST_LOG=info
EOF

    local service_unit="tcp-to-quic@${INSTANCE_NAME}.service"
    run_root systemctl daemon-reload
    run_root systemctl enable --now "$service_unit"
    echo -e "${GREEN}[+] ${service_unit} configured and started.${NC}"
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
        list_services
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
echo -e "${BOLD}Multi-Instance Management Commands:${NC}"
echo "  - List all services:      ./install.sh --list  (or ./uninstall.sh --list)"
echo "  - Check instance status:  systemctl status <service>@<instance> (e.g. quic-to-tcp@8080, tcp-to-quic@7070)"
echo "  - View live logs:         journalctl -u <service>@<instance> -f"
echo "  - Restart instance:       systemctl restart <service>@<instance>"
echo "  - Stop instance:          systemctl stop <service>@<instance>"
echo -e "${GREEN}${BOLD}======================================================================${NC}"
