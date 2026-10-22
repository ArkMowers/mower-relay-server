#!/bin/sh
set -eu
relay_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$relay_directory"
exec "$relay_directory/.relay-venv/bin/python" -m mower_relay_server --work-dir "$relay_directory" "$@"
