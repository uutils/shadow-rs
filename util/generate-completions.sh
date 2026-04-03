#!/usr/bin/env bash
# Generate shell completions for all shadow-rs tools.
#
# Usage:
#   ./util/generate-completions.sh bash [output-dir]
#   ./util/generate-completions.sh zsh  [output-dir]
#   ./util/generate-completions.sh fish [output-dir]
#
# Requires: cargo build --features completions

set -euo pipefail

SHELL_TYPE="${1:-bash}"
OUTPUT_DIR="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build the completions binary
cargo build --manifest-path "$PROJECT_DIR/Cargo.toml" --features completions --bin shadow-rs-completions

BINARY="$PROJECT_DIR/target/debug/shadow-rs-completions"

if [ -n "$OUTPUT_DIR" ]; then
    "$BINARY" --all --shell "$SHELL_TYPE" --dir "$OUTPUT_DIR"
else
    "$BINARY" --all --shell "$SHELL_TYPE"
fi
