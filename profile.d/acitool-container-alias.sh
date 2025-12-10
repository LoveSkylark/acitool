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