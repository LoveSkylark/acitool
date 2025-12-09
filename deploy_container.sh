#!/bin/bash

echo "WARNING: This script will:"
echo "  - Clone acitool repository (if not already present) and build the pyscript container"
echo "  - Install in the current directory: $(pwd)"
echo "  - The container will reference the 'scripts' folder from the acitool directory"
echo "  - Add an acitool command to your shell profile"
read -p "Do you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Installation cancelled."
    exit 0
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
        exit 1
    fi
fi

# Clone the repository if it hasn't been done already
if [ -d "acitool" ]; then
    echo "Repository already exists, skipping git clone..."
else
    echo "Cloning repository..."
    git clone https://github.com/LoveSkylark/acitool.git
fi

echo "Copying profile configuration..."
sudo cp ./acitool/profile.d/* /etc/profile.d/ 2>/dev/null || echo "Note: No profile.d files found to copy"

echo "Building the container..."
$CONTAINER_CMD build --no-cache -t pyscript ./acitool/.

echo "Starting the container..."
$CONTAINER_CMD run -itd --name pyscript -v ./acitool/scripts:/scripts pyscript

echo "Installation complete. Please restart your terminal or source your profile to use the acitool command."
