#!/usr/bin/env bash
# Compatibility loader for split shell helpers.

GHIDRA_RE_ROOT="${GHIDRA_RE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$GHIDRA_RE_ROOT/scripts/shell_lib/common_core.sh"
source "$GHIDRA_RE_ROOT/scripts/shell_lib/common_bridge.sh"
