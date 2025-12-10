#!/bin/bash

set -e  # Exit on error

echo "=========================================="
echo "ACI Tool Container Deployment Script"
echo "=========================================="
echo ""
echo "This script will:"
echo "  - Build the acitool container"
echo "  - Configure environment from .env file"
echo "  - Set up shell alias for easy execution"
echo "  - Mount token cache for persistent authentication"
echo ""
read -p "Do you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Detect container runtime
echo ""
echo "Detecting container runtime..."
if type -P podman >/dev/null 2>&1; then
    CONTAINER_CMD="podman"
    echo "✓ Found podman"
elif type -P docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
    echo "✓ Found docker"
else
    echo "✗ Error: Neither podman nor docker is installed."
    echo "  Please install Docker or Podman first."
    exit 1
fi

# Check for .env file
echo ""
echo "Checking for .env file..."
if [ ! -f "./.env" ]; then
    echo "✗ Error: .env file not found!"
    echo "  Please create .env file from .env.example:"
    echo "    cp .env.example .env"
    echo "    # Edit .env and set your APIC_URL"
    exit 1
fi

# Load environment variables
echo "✓ Loading environment from .env..."
set -a
source ./.env
set +a

if [ -z "$APIC_URL" ]; then
    echo "✗ Error: APIC_URL not set in .env file"
    exit 1
fi
echo "  APIC_URL: ${APIC_URL}"

# Stop and remove existing container if it exists
echo ""
echo "Checking for existing container..."
if $CONTAINER_CMD ps -a --format '{{.Names}}' | grep -q '^acitool$'; then
    echo "  Found existing 'acitool' container, removing..."
    $CONTAINER_CMD stop acitool >/dev/null 2>&1 || true
    $CONTAINER_CMD rm acitool >/dev/null 2>&1 || true
    echo "✓ Removed old container"
fi

# Build the container
echo ""
echo "Building container image..."
$CONTAINER_CMD build \
    --no-cache \
    --build-arg VERIFY_SSL="${VERIFY_SSL:-false}" \
    --build-arg APIC_URL="${APIC_URL}" \
    -t acitool \
    .

echo "✓ Container image built successfully"

# Create token directory if it doesn't exist
mkdir -p ~/.aci_cache

# Start the container
echo ""
echo "Starting container..."
$CONTAINER_CMD run -itd \
    --name acitool \
    --env-file ./.env \
    -v ~/.aci_cache:/home/aciuser/.aci \
    acitool

echo "✓ Container started"

# Install shell alias
echo ""
echo "Installing shell alias..."
PROFILE_FILE=""
if [ -n "$BASH_VERSION" ]; then
    PROFILE_FILE="$HOME/.bashrc"
elif [ -n "$ZSH_VERSION" ]; then
    PROFILE_FILE="$HOME/.zshrc"
else
    echo "  ⚠ Unknown shell. Please manually add this function to your profile:"
    cat << 'EOF'
    acitool() {
        if [ $# -eq 0 ]; then
            echo "No arguments provided. Use --help for help."
            return 1
        fi

        # Check if we already detected the container runtime
        if [ -z "$CONTAINER_CMD" ]; then
            # First time - detect and cache the result
            if type -P podman >/dev/null 2>&1; then
                export CONTAINER_CMD="podman"
            elif type -P docker >/dev/null 2>&1; then
                export CONTAINER_CMD="docker"
            else
                echo "Error: Neither podman nor docker is installed."
                return 1
            fi
        fi

        # Start container if it's not running
        if ! $CONTAINER_CMD ps --format '{{.Names}}' | grep -q '^acitool$'; then
            $CONTAINER_CMD start acitool >/dev/null 2>&1
        fi

        $CONTAINER_CMD exec -it acitool python3 /app/acitool.py "$@"
    }
EOF
fi

if [ -n "$PROFILE_FILE" ]; then
    # Check if function already exists
    if grep -q "acitool()" "$PROFILE_FILE" 2>/dev/null; then
        echo "  ℹ Function already exists in $PROFILE_FILE"
    else
        echo "" >> "$PROFILE_FILE"
        echo "# ACI Tool function" >> "$PROFILE_FILE"
        cat << 'EOF' >> "$PROFILE_FILE"
acitool() {
    if [ $# -eq 0 ]; then
        echo "No arguments provided. Use --help for help."
        return 1
    fi

    # Check if we already detected the container runtime
    if [ -z "$CONTAINER_CMD" ]; then
        # First time - detect and cache the result
        if type -P podman >/dev/null 2>&1; then
            export CONTAINER_CMD="podman"
        elif type -P docker >/dev/null 2>&1; then
            export CONTAINER_CMD="docker"
        else
            echo "Error: Neither podman nor docker is installed."
            return 1
        fi
    fi

    # Start container if it's not running
    if ! $CONTAINER_CMD ps --format '{{.Names}}' | grep -q '^acitool$'; then
        $CONTAINER_CMD start acitool >/dev/null 2>&1
    fi

    $CONTAINER_CMD exec -it acitool python3 /app/acitool.py "$@"
}
EOF
        echo "✓ Function added to $PROFILE_FILE"
    fi
fi

# Final instructions
echo ""
echo "=========================================="
echo "✓ Installation Complete!"
echo "=========================================="
echo ""
echo "To use the tool:"
echo "  1. Reload your shell:"
echo "       source $PROFILE_FILE"
echo "     OR open a new terminal"
echo ""
echo "  2. Run acitool commands:"
echo "       acitool --help"
echo "       acitool clean vrf"
echo "       acitool ip 10.0.0.1"
echo ""
echo "Token cache: ~/.aci_cache"
echo "Container name: acitool"
echo ""
