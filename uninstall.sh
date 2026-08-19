#!/usr/bin/env bash
# ==============================================================================
# QUIC-TCP Uninstallation Script
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "                   QUIC-TCP Uninstallation                           "
echo "======================================================================"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This uninstall script must be run as root or with sudo.${NC}"
    echo -e "Please run: ${BOLD}sudo $0${NC}"
    exit 1
fi

SERVICES=("rendezvous-server" "quic-to-tcp" "tcp-to-quic")

echo -e "${YELLOW}[1/3] Stopping and disabling systemd services...${NC}"
for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "${svc}.service" 2>/dev/null || systemctl is-enabled --quiet "${svc}.service" 2>/dev/null; then
        echo "Stopping and disabling ${svc}.service..."
        systemctl disable --now "${svc}.service" 2>/dev/null || true
    fi
    if [ -f "/etc/systemd/system/${svc}.service" ]; then
        rm -f "/etc/systemd/system/${svc}.service"
    fi
done

systemctl daemon-reload

echo -e "${YELLOW}[2/3] Removing installed binaries...${NC}"
rm -f /usr/local/bin/quic-to-tcp
rm -f /usr/local/bin/tcp-to-quic
rm -f /usr/local/bin/rendezvous-server

echo -e "${YELLOW}[3/3] Configuration directory /etc/quic-tcp${NC}"
read -rp "Do you want to delete all configuration files and TLS certificates in /etc/quic-tcp? [y/N]: " REMOVE_CONF
if [[ "$REMOVE_CONF" =~ ^[Yy]$ ]]; then
    rm -rf /etc/quic-tcp
    echo "Removed /etc/quic-tcp directory."
else
    echo "Kept /etc/quic-tcp directory."
fi

echo -e "\n${GREEN}${BOLD}[+] QUIC-TCP uninstallation complete!${NC}"
