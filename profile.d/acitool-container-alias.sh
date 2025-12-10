acitool() {
    if [ $# -eq 0 ]; then
        echo "No arguments provided. Use --help for help."
        return 1
    fi

    # Check if CONTAINER_CMD is already set to a valid value
    if [ "$CONTAINER_CMD" != "podman" ] && [ "$CONTAINER_CMD" != "docker" ]; then
        # Detect and cache container runtime
        if command -v podman >/dev/null 2>&1; then
            export CONTAINER_CMD="podman"
        elif command -v docker >/dev/null 2>&1; then
            export CONTAINER_CMD="docker"
        else
            echo "Error: Neither podman nor docker is installed."
            return 1
        fi
    fi

    # Start container if it's not running
    if ! $CONTAINER_CMD ps --format '{{.Names}}' | grep -q '^acitool$'; then
        echo "Starting acitool container..."
        $CONTAINER_CMD start acitool >/dev/null 2>&1
    fi

    $CONTAINER_CMD exec -it acitool python3 /app/acitool.py "$@"
}