#!/usr/bin/env bash
# Convenience wrapper: java -cp target/classes com.dpi.Main "$@"
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
java -cp "$DIR/target/classes" com.dpi.Main "$@"
