#!/bin/sh
set -eu

config_path=/host-config/config.yaml

if [ -d "$config_path" ]; then
    if ! rmdir "$config_path"; then
        echo "Error: config.yaml is a non-empty directory; rename it before retrying." >&2
        exit 1
    fi
    echo "Removed the empty config.yaml directory left by an earlier startup."
fi

if [ ! -e "$config_path" ]; then
    cp /host-config/config.example.yaml "$config_path"
    chown --reference=/host-config "$config_path"
    echo "Created config.yaml from config.example.yaml."
fi

exec "$@"
