#!/usr/bin/env bash
# ==============================================================================
# QUIC-TCP Uninstallation & Instance Removal Script
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CONFIG_DIR="/etc/quic-tcp"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

run_root() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Function to discover all configured and running services
get_all_services() {
    local units=""
    if command -v systemctl &>/dev/null; then
        units=$(systemctl list-units --type=service --all 'quic-to-tcp*' 'tcp-to-quic*' 'rendezvous-server*' --no-legend --no-pager 2>/dev/null | awk '{print $1}' || true)
    fi

    local unit_files=""
    if [ -d "$SYSTEMD_DIR" ]; then
        unit_files=$(find "$SYSTEMD_DIR" -maxdepth 1 -name "quic-to-tcp*.service" -o -name "tcp-to-quic*.service" -o -name "rendezvous-server*.service" 2>/dev/null | xargs -n 1 basename 2>/dev/null || true)
    fi

    local env_services=""
    if [ -d "$CONFIG_DIR" ]; then
        for env in "$CONFIG_DIR"/*.env; do
            [ -f "$env" ] || continue
            local base
            base=$(basename "$env" .env)
            if [[ "$base" =~ ^(quic-to-tcp|tcp-to-quic|rendezvous-server)-(.+)$ ]]; then
                env_services+="${BASH_REMATCH[1]}@${BASH_REMATCH[2]}.service"$'\n'
            elif [[ "$base" =~ ^(quic-to-tcp|tcp-to-quic|rendezvous-server)$ ]]; then
                env_services+="${base}.service"$'\n'
            fi
        done
    fi

    echo -e "${units}\n${unit_files}\n${env_services}" | grep -v '^$' | grep -v '@\.service$' | sort -u || true
}

list_services() {
    echo -e "\n${CYAN}${BOLD}======================================================================${NC}"
    echo -e "${CYAN}${BOLD}                 Configured & Running QUIC-TCP Services               ${NC}"
    echo -e "${CYAN}${BOLD}======================================================================${NC}"

    local all_services
    all_services=$(get_all_services)
    local found=0

    if [ -n "$all_services" ]; then
        for svc in $all_services; do
            found=1
            local is_active="inactive"
            local is_enabled="disabled"
            if command -v systemctl &>/dev/null; then
                is_active=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
                is_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
            fi

            local status_color="$YELLOW"
            if [ "$is_active" = "active" ]; then
                status_color="$GREEN"
            elif [ "$is_active" = "failed" ]; then
                status_color="$RED"
            fi

            # Extract instance name and conf file
            local instance=""
            if [[ "$svc" =~ @(.+)\.service$ ]]; then
                instance="${BASH_REMATCH[1]}"
            fi

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
echo "          QUIC-TCP Uninstallation & Instance Removal                  "
echo "======================================================================"
echo -e "${NC}"

remove_single_service() {
    local svc_list=()
    while IFS= read -r line; do
        [ -n "$line" ] && svc_list+=("$line")
    done < <(get_all_services)

    if [ ${#svc_list[@]} -eq 0 ]; then
        echo -e "${YELLOW}No QUIC-TCP services found to remove.${NC}"
        return
    fi

    echo -e "\n${BLUE}Select a service instance to stop and remove:${NC}"
    for i in "${!svc_list[@]}"; do
        echo "  $((i + 1))) ${svc_list[$i]}"
    done
    echo "  q) Cancel"

    read -rp "Enter choice [1-${#svc_list[@]}]: " SELECTION
    if [[ "$SELECTION" =~ ^[0-9]+$ ]] && [ "$SELECTION" -ge 1 ] && [ "$SELECTION" -le ${#svc_list[@]} ]; then
        local target_svc="${svc_list[$((SELECTION - 1))]}"
        echo -e "\n${YELLOW}Stopping and disabling ${target_svc}...${NC}"
        run_root systemctl disable --now "$target_svc" 2>/dev/null || true

        # Extract instance
        local instance=""
        if [[ "$target_svc" =~ @(.+)\.service$ ]]; then
            instance="${BASH_REMATCH[1]}"
        fi

        # Remove specific env file
        if [[ "$target_svc" =~ ^quic-to-tcp ]]; then
            [ -n "$instance" ] && run_root rm -f "$CONFIG_DIR/quic-to-tcp-${instance}.env"
        elif [[ "$target_svc" =~ ^tcp-to-quic ]]; then
            [ -n "$instance" ] && run_root rm -f "$CONFIG_DIR/tcp-to-quic-${instance}.env"
        elif [[ "$target_svc" =~ ^rendezvous-server ]]; then
            [ -n "$instance" ] && run_root rm -f "$CONFIG_DIR/rendezvous-server-${instance}.env"
        fi

        run_root systemctl daemon-reload
        echo -e "${GREEN}[+] Successfully removed ${target_svc}.${NC}"
    else
        echo "Cancelled."
    fi
}

remove_all_services() {
    echo -e "\n${YELLOW}[1/2] Stopping and removing all QUIC-TCP service instances...${NC}"
    local all_services
    all_services=$(get_all_services)

    if [ -n "$all_services" ]; then
        for svc in $all_services; do
            echo "Stopping and disabling ${svc}..."
            run_root systemctl disable --now "$svc" 2>/dev/null || true
        done
    fi

    # Remove unit files from /etc/systemd/system
    run_root rm -f "$SYSTEMD_DIR"/quic-to-tcp*.service
    run_root rm -f "$SYSTEMD_DIR"/tcp-to-quic*.service
    run_root rm -f "$SYSTEMD_DIR"/rendezvous-server*.service

    run_root systemctl daemon-reload
    echo -e "${GREEN}[+] All systemd service instances stopped and removed.${NC}"
}

echo "What action would you like to perform?"
echo "  1) Remove a specific service instance"
echo "  2) Stop and remove all service instances (Keep binaries)"
echo "  3) Complete Uninstallation (Remove all services, configs, and binaries)"
echo "  4) List running / configured services"
echo "  5) Cancel"

read -rp "Enter choice [1-5] (default: 1): " UNINSTALL_CHOICE
UNINSTALL_CHOICE=${UNINSTALL_CHOICE:-1}

case "$UNINSTALL_CHOICE" in
    1)
        remove_single_service
        ;;
    2)
        remove_all_services
        if [ -d "$CONFIG_DIR" ]; then
            read -rp "Do you want to delete all configuration files in ${CONFIG_DIR}? [y/N]: " REMOVE_CONF
            if [[ "$REMOVE_CONF" =~ ^[Yy]$ ]]; then
                run_root rm -rf "$CONFIG_DIR"
                echo "Removed ${CONFIG_DIR} directory."
            fi
        fi
        ;;
    3)
        remove_all_services

        echo -e "\n${YELLOW}[2/3] Removing installed binaries from ${BIN_DIR}...${NC}"
        run_root rm -f "$BIN_DIR/quic-to-tcp"
        run_root rm -f "$BIN_DIR/tcp-to-quic"
        run_root rm -f "$BIN_DIR/rendezvous-server"

        echo -e "\n${YELLOW}[3/3] Configuration directory ${CONFIG_DIR}${NC}"
        if [ -d "$CONFIG_DIR" ]; then
            read -rp "Do you want to delete all configuration files and TLS certificates in ${CONFIG_DIR}? [y/N]: " REMOVE_CONF
            if [[ "$REMOVE_CONF" =~ ^[Yy]$ ]]; then
                run_root rm -rf "$CONFIG_DIR"
                echo "Removed ${CONFIG_DIR} directory."
            fi
        fi
        echo -e "\n${GREEN}${BOLD}[+] Complete uninstallation finished!${NC}"
        ;;
    4)
        list_services
        ;;
    5)
        echo "Cancelled."
        exit 0
        ;;
    *)
        echo -e "${RED}[ERROR] Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac
