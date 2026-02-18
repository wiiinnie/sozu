#!/usr/bin/env bash
set -e

#############################################
# Multi-Instance Dusk Node Installer (Official Wrapper)
# Uses the official Dusk installer and adapts for multiple instances
#############################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
NETWORK="mainnet"
INSTANCE=1
FEATURE="default"

# Help message
show_help() {
    cat << EOF
Multi-Instance Dusk Node Installer (Official Wrapper)

This script uses the official Dusk installer and adapts it for multi-instance deployment.

Usage: $0 [OPTIONS]

OPTIONS:
    --instance N           Instance number (default: 1)
                          Instance 1 uses port 9001, Instance 2 uses 9002, etc.
    
    --network NETWORK      Network to install (default: mainnet)
                          Options: mainnet, testnet, devnet
    
    --feature FEATURE      Optional feature (default: default)
                          Options: default, archive
    
    -h, --help            Show this help message

EXAMPLES:
    # Install first instance on testnet
    sudo bash $0 --instance 1 --network testnet
    
    # Install second instance on mainnet
    sudo bash $0 --instance 2 --network mainnet

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --instance)
            INSTANCE="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --feature)
            FEATURE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

# Validate
if ! [[ "$INSTANCE" =~ ^[0-9]+$ ]] || [ "$INSTANCE" -lt 1 ]; then
    echo -e "${RED}Error: Instance must be a positive integer${NC}"
    exit 1
fi

if [[ ! "$NETWORK" =~ ^(mainnet|testnet|devnet)$ ]]; then
    echo -e "${RED}Error: Network must be mainnet, testnet, or devnet${NC}"
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Calculate ports
KADCAST_PORT=$((9000 + INSTANCE))
HTTP_PORT=$((8080 + INSTANCE))
DUSK_ROOT="/opt/dusk${INSTANCE}"
SERVICE_NAME="rusk-${INSTANCE}"
LOG_FILE="/var/log/rusk-${INSTANCE}.log"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Multi-Instance Dusk Node Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Instance Number:    ${YELLOW}${INSTANCE}${NC}"
echo -e "Network:            ${YELLOW}${NETWORK}${NC}"
echo -e "Feature:            ${YELLOW}${FEATURE}${NC}"
echo -e "Kadcast Port:       ${YELLOW}${KADCAST_PORT}/udp${NC}"
echo -e "HTTP Port:          ${YELLOW}${HTTP_PORT} (localhost only)${NC}"
echo -e "Installation Path:  ${YELLOW}${DUSK_ROOT}${NC}"
echo -e "Service Name:       ${YELLOW}${SERVICE_NAME}${NC}"
echo ""

# Check if instance already exists
if [ -d "$DUSK_ROOT" ]; then
    echo -e "${YELLOW}Warning: Instance $INSTANCE already exists at $DUSK_ROOT${NC}"
    read -p "Do you want to upgrade/reinstall? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    echo "Stopping existing service..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
fi

# Step 1: Download and run official installer to /opt/dusk (temporary)
echo -e "${GREEN}Step 1: Running official Dusk installer...${NC}"
echo ""

# Create temp directory for official install
TEMP_INSTALL="/opt/dusk-temp-${INSTANCE}"
rm -rf "$TEMP_INSTALL"

# Download and run official installer with modified DUSK_ROOT
export INSTALL_PATH="$TEMP_INSTALL"

# Download official installer
INSTALLER_URL="https://github.com/dusk-network/node-installer/releases/latest/download/node-installer.sh"
curl -sSfL "$INSTALLER_URL" > /tmp/dusk-installer-${INSTANCE}.sh

# Run official installer with network and feature flags
# We'll install to temp location first
bash /tmp/dusk-installer-${INSTANCE}.sh --network "$NETWORK" --feature "$FEATURE" || {
    echo -e "${RED}Official installer failed${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}Step 2: Adapting installation for instance ${INSTANCE}...${NC}"
echo ""

# Move installation to instance-specific directory
if [ -d "/opt/dusk" ]; then
    rm -rf "$DUSK_ROOT"
    mv /opt/dusk "$DUSK_ROOT"
    echo -e "${GREEN}✓ Moved installation to ${DUSK_ROOT}${NC}"
else
    echo -e "${RED}Error: Official installation not found at /opt/dusk${NC}"
    exit 1
fi

# Stop the default rusk service
systemctl stop rusk 2>/dev/null || true
systemctl disable rusk 2>/dev/null || true

# Step 3: Adapt service file for this instance
echo -e "${GREEN}Step 3: Creating instance-specific service...${NC}"

# Copy and modify the service file
if [ -f "/etc/systemd/system/rusk.service" ]; then
    # Read the original service file and modify it
    sed "s|/opt/dusk|${DUSK_ROOT}|g" /etc/systemd/system/rusk.service | \
    sed "s|Description=.*|Description=DUSK Rusk - Instance ${INSTANCE}|" | \
    sed "s|rusk.log|rusk-${INSTANCE}.log|g" | \
    sed "s|rusk_recovery.log|rusk-${INSTANCE}-recovery.log|g" | \
    sed "s|^User=dusk|User=root|" \
    > /etc/systemd/system/${SERVICE_NAME}.service
    
    # Remove the original service file
    rm -f /etc/systemd/system/rusk.service
    
    echo -e "${GREEN}✓ Service file created: ${SERVICE_NAME}.service (running as root)${NC}"
else
    echo -e "${RED}Error: Original rusk.service not found${NC}"
    exit 1
fi

# Update all helper scripts to use instance-specific paths
echo -e "${GREEN}Updating helper scripts...${NC}"

# Update all shell scripts in bin directory to replace /opt/dusk with instance path
# Use word boundary to avoid replacing /opt/dusk1 -> /opt/dusk11
if [ -d "${DUSK_ROOT}/bin" ]; then
    for script in ${DUSK_ROOT}/bin/*.sh; do
        if [ -f "$script" ]; then
            # Only replace /opt/dusk followed by / or end of line, not /opt/dusk[0-9]
            sed -i "s|/opt/dusk/|${DUSK_ROOT}/|g" "$script"
            sed -i "s|/opt/dusk\"|${DUSK_ROOT}\"|g" "$script"
            sed -i "s|/opt/dusk'|${DUSK_ROOT}'|g" "$script"
            sed -i "s|/opt/dusk\$|${DUSK_ROOT}|g" "$script"
            sed -i "s|/opt/dusk |${DUSK_ROOT} |g" "$script"
        fi
    done
    echo -e "${GREEN}✓ Helper scripts updated${NC}"
fi

# Update any other scripts that might reference /opt/dusk (not followed by digits)
find ${DUSK_ROOT} -type f \( -name "*.sh" -o -name "rusk*" \) -exec sed -i \
    -e "s|/opt/dusk/|${DUSK_ROOT}/|g" \
    -e "s|/opt/dusk\"|${DUSK_ROOT}\"|g" \
    -e "s|/opt/dusk'|${DUSK_ROOT}'|g" \
    -e "s|/opt/dusk\$|${DUSK_ROOT}|g" \
    -e "s|/opt/dusk |${DUSK_ROOT} |g" \
    {} \;

# Step 4: Update configuration files with instance-specific ports
echo -e "${GREEN}Step 4: Configuring instance-specific ports...${NC}"

# Update rusk.toml - enable HTTP with instance-specific port on localhost only
if [ -f "${DUSK_ROOT}/conf/rusk.toml" ]; then
    # Remove any existing [http] section
    sed -i '/^\[http\]/,/^$/d' "${DUSK_ROOT}/conf/rusk.toml"
    
    # Add HTTP configuration with instance-specific port (localhost only)
    cat >> ${DUSK_ROOT}/conf/rusk.toml << EOF

# HTTP Configuration - Instance ${INSTANCE} (localhost only)
[http]
listen = true
listen_address = "127.0.0.1:${HTTP_PORT}"
EOF
    echo -e "${GREEN}✓ HTTP enabled on 127.0.0.1:${HTTP_PORT} (localhost only)${NC}"
fi

# Auto-detect public IP
echo -e "${GREEN}Detecting public IP address...${NC}"
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
            curl -s --max-time 5 https://ifconfig.me 2>/dev/null || \
            hostname -I | awk '{print $1}')

if [[ ! "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PUBLIC_IP="0.0.0.0"
    echo -e "${YELLOW}Warning: Could not detect valid IP, using 0.0.0.0${NC}"
else
    echo -e "${GREEN}✓ Detected public IP: ${PUBLIC_IP}${NC}"
fi

# Update Kadcast configuration
cat > ${DUSK_ROOT}/services/rusk.conf.user << EOF
# Kadcast configuration for instance ${INSTANCE}
KADCAST_PUBLIC_ADDRESS=${PUBLIC_IP}:${KADCAST_PORT}
KADCAST_LISTEN_ADDRESS=${PUBLIC_IP}:${KADCAST_PORT}
EOF

echo -e "${GREEN}✓ Kadcast configured: ${PUBLIC_IP}:${KADCAST_PORT}${NC}"

# Step 5: Configure firewall
echo -e "${GREEN}Step 5: Configuring firewall...${NC}"

if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        ufw allow ${KADCAST_PORT}/udp 2>/dev/null
        echo -e "${GREEN}✓ Port ${KADCAST_PORT}/udp opened (Kadcast)${NC}"
    else
        echo -e "${YELLOW}UFW is not active. Please open port ${KADCAST_PORT}/udp manually${NC}"
    fi
else
    echo -e "${YELLOW}UFW not found. Please open port ${KADCAST_PORT}/udp manually${NC}"
fi

# Step 6: Update logrotate configuration
echo -e "${GREEN}Step 6: Configuring log rotation...${NC}"

cat > /etc/logrotate.d/${SERVICE_NAME} << EOF
/var/log/rusk-${INSTANCE}.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}

/var/log/rusk-${INSTANCE}-recovery.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

# Remove old logrotate config if exists
rm -f /etc/logrotate.d/rusk

echo -e "${GREEN}✓ Log rotation configured${NC}"

# Reload systemd
systemctl daemon-reload

# Step 7: Consensus keys
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Consensus Keys Configuration${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if command -v sozu-beta3-rusk-wallet >/dev/null 2>&1; then
    echo -e "${CYAN}Enter the path to your wallet (e.g., ~/sozu_provisioner):${NC}"
    read -r WALLET_PATH
    
    if [ -n "$WALLET_PATH" ]; then
        WALLET_PATH="${WALLET_PATH/#\~/$HOME}"
        PROFILE_IDX=$((INSTANCE - 1))
        
        echo -e "${GREEN}Exporting keys for profile ${PROFILE_IDX}...${NC}"
        if sozu-beta3-rusk-wallet -w "${WALLET_PATH}" export --profile-idx ${PROFILE_IDX} -d ${DUSK_ROOT}/conf -n consensus.keys; then
            chmod 600 ${DUSK_ROOT}/conf/consensus.keys
            echo -e "${GREEN}✓ Consensus keys exported${NC}"
            
            echo -e "${CYAN}Enter consensus keys password:${NC}"
            read -s CONSENSUS_PASSWORD
            echo
            
            if [ -n "$CONSENSUS_PASSWORD" ]; then
                echo "DUSK_CONSENSUS_KEYS_PASS=${CONSENSUS_PASSWORD}" > ${DUSK_ROOT}/services/dusk.conf
                chmod 600 ${DUSK_ROOT}/services/dusk.conf
                echo -e "${GREEN}✓ Password configured${NC}"
            fi
        fi
    fi
fi

# Final summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Instance ${INSTANCE} Details:${NC}"
echo -e "  Installation: ${DUSK_ROOT}"
echo -e "  Service:      ${SERVICE_NAME}"
echo -e "  Kadcast:      ${PUBLIC_IP}:${KADCAST_PORT}/udp"
echo -e "  HTTP:         127.0.0.1:${HTTP_PORT} (localhost only)"
echo -e "  Logs:         ${LOG_FILE}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo ""
echo "1. Start the service:"
echo "   sudo systemctl enable ${SERVICE_NAME}"
echo "   sudo systemctl start ${SERVICE_NAME}"
echo ""
echo "2. Check status:"
echo "   sudo systemctl status ${SERVICE_NAME}"
echo "   tail -f ${LOG_FILE}"
echo ""
echo "3. Verify HTTP endpoint:"
echo "   curl http://localhost:${HTTP_PORT}/"
echo ""
echo "4. If you didn't export keys above, do it manually:"
echo "   sozu-beta3-rusk-wallet -w ~/sozu_provisioner export --profile-idx $((INSTANCE - 1)) -d ${DUSK_ROOT}/conf -n consensus.keys"
echo "   echo 'DUSK_CONSENSUS_KEYS_PASS=your_password' > ${DUSK_ROOT}/services/dusk.conf"
echo ""
