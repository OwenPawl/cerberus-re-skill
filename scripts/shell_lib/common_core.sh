#!/usr/bin/env bash

set -euo pipefail

case "$(uname -s)" in
  Darwin)
    GHIDRA_RE_PLATFORM_DEFAULT="macos"
    GHIDRA_RE_CONFIG_HOME_DEFAULT="$HOME/.config/cerberus-re"
    GHIDRA_INSTALL_DIR_DEFAULT="/Applications/Ghidra"
    GHIDRA_JDK_DEFAULT="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    GHIDRA_RE_PLATFORM_DEFAULT="windows"
    if [[ -n "${APPDATA:-}" ]]; then
      GHIDRA_RE_CONFIG_HOME_DEFAULT="$APPDATA/cerberus-re"
    else
      GHIDRA_RE_CONFIG_HOME_DEFAULT="$HOME/AppData/Roaming/cerberus-re"
    fi
    GHIDRA_INSTALL_DIR_DEFAULT="/c/Program Files/Ghidra"
    GHIDRA_JDK_DEFAULT="/c/Program Files/Eclipse Adoptium/jdk-21"
    ;;
  *)
    GHIDRA_RE_PLATFORM_DEFAULT="linux"
    GHIDRA_RE_CONFIG_HOME_DEFAULT="$HOME/.config/cerberus-re"
    GHIDRA_INSTALL_DIR_DEFAULT="/opt/ghidra"
    GHIDRA_JDK_DEFAULT="${JAVA_HOME:-/usr/lib/jvm/default-java}"
    ;;
esac

GHIDRA_RE_ROOT="${GHIDRA_RE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Load the unified skill-host resolution layer so every script that sources
# common.sh can reason about Codex vs Claude Code install locations without
# duplicating logic. See scripts/lib/skill_host.sh for the full API.
if [[ -f "$GHIDRA_RE_ROOT/scripts/lib/skill_host.sh" ]]; then
  # shellcheck source=lib/skill_host.sh
  source "$GHIDRA_RE_ROOT/scripts/lib/skill_host.sh"
  GHIDRA_RE_SKILL_HOST="${GHIDRA_RE_SKILL_HOST:-$(ghidra_re_host_identify_root "$GHIDRA_RE_ROOT" || printf '')}"
fi

GHIDRA_RE_PLATFORM="${GHIDRA_RE_PLATFORM:-$GHIDRA_RE_PLATFORM_DEFAULT}"
GHIDRA_RE_CONFIG_HOME="${GHIDRA_RE_CONFIG_HOME:-$GHIDRA_RE_CONFIG_HOME_DEFAULT}"
GHIDRA_RE_DEFAULT_USER_CONFIG="$GHIDRA_RE_CONFIG_HOME/config.env"
GHIDRA_RE_USER_CONFIG="${GHIDRA_RE_USER_CONFIG:-$GHIDRA_RE_DEFAULT_USER_CONFIG}"
GHIDRA_RE_SKILL_CONFIG="${GHIDRA_RE_SKILL_CONFIG:-$GHIDRA_RE_ROOT/local.env}"

if [[ -f "$GHIDRA_RE_USER_CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$GHIDRA_RE_USER_CONFIG"
fi
if [[ -f "$GHIDRA_RE_SKILL_CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$GHIDRA_RE_SKILL_CONFIG"
fi

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$GHIDRA_INSTALL_DIR_DEFAULT}"
GHIDRA_JDK="${GHIDRA_JDK:-$GHIDRA_JDK_DEFAULT}"
GHIDRA_WORKSPACE="${GHIDRA_WORKSPACE:-$HOME/ghidra-projects}"
GHIDRA_PROJECTS_DIR="${GHIDRA_PROJECTS_DIR:-$GHIDRA_WORKSPACE/projects}"
GHIDRA_EXPORTS_DIR="${GHIDRA_EXPORTS_DIR:-$GHIDRA_WORKSPACE/exports}"
GHIDRA_LOGS_DIR="${GHIDRA_LOGS_DIR:-$GHIDRA_WORKSPACE/logs}"
GHIDRA_SOURCES_CACHE_DIR="${GHIDRA_SOURCES_CACHE_DIR:-$GHIDRA_WORKSPACE/sources}"
GHIDRA_CUSTOM_SCRIPTS_DIR="${GHIDRA_CUSTOM_SCRIPTS_DIR:-$GHIDRA_RE_ROOT/scripts/ghidra_scripts}"
GHIDRA_TEMPLATES_DIR="${GHIDRA_TEMPLATES_DIR:-$GHIDRA_RE_ROOT/templates}"
GHIDRA_RE_TRIAGE_MANIFEST="${GHIDRA_RE_TRIAGE_MANIFEST:-$GHIDRA_RE_ROOT/references/triage-patterns.json}"
GHIDRA_RE_BRIDGE_EXTENSION_DIR="${GHIDRA_RE_BRIDGE_EXTENSION_DIR:-$GHIDRA_RE_ROOT/bridge-extension/CodexGhidraBridge}"
GHIDRA_RE_BRIDGE_DIST_DIR="${GHIDRA_RE_BRIDGE_DIST_DIR:-$GHIDRA_RE_BRIDGE_EXTENSION_DIR/dist}"
GHIDRA_RE_BRIDGE_CONFIG_DIR="${GHIDRA_RE_BRIDGE_CONFIG_DIR:-$GHIDRA_RE_CONFIG_HOME}"
GHIDRA_RE_BRIDGE_SESSIONS_DIR="${GHIDRA_RE_BRIDGE_SESSIONS_DIR:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-sessions}"
GHIDRA_RE_BRIDGE_REQUESTS_DIR="${GHIDRA_RE_BRIDGE_REQUESTS_DIR:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-requests}"
GHIDRA_RE_BRIDGE_CURRENT_FILE="${GHIDRA_RE_BRIDGE_CURRENT_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-current.json}"
GHIDRA_RE_BRIDGE_INSTALL_STATE_FILE="${GHIDRA_RE_BRIDGE_INSTALL_STATE_FILE:-$GHIDRA_RE_BRIDGE_CONFIG_DIR/bridge-install-state.json}"
GHIDRA_RE_BRIDGE_SESSION_FILE="${GHIDRA_RE_BRIDGE_SESSION_FILE:-$GHIDRA_RE_BRIDGE_CURRENT_FILE}"
GHIDRA_RE_SOURCE_REGISTRY_FILE="${GHIDRA_RE_SOURCE_REGISTRY_FILE:-$GHIDRA_RE_CONFIG_HOME/sources.json}"
GHIDRA_NOTES_ENABLE_SHARED="${GHIDRA_NOTES_ENABLE_SHARED:-1}"
GHIDRA_NOTES_AUTO_SYNC="${GHIDRA_NOTES_AUTO_SYNC:-1}"
GHIDRA_NOTES_REPO="${GHIDRA_NOTES_REPO:-}"
GHIDRA_NOTES_ISSUE_TITLE="${GHIDRA_NOTES_ISSUE_TITLE:-Global Use-Case Driven Notes}"
GHIDRA_NOTES_ISSUE_NUMBER="${GHIDRA_NOTES_ISSUE_NUMBER:-}"
GHIDRA_NOTES_ROOT="${GHIDRA_NOTES_ROOT:-$GHIDRA_RE_CONFIG_HOME/shared-notes}"
GHIDRA_NOTES_CONFIG_FILE="${GHIDRA_NOTES_CONFIG_FILE:-$GHIDRA_NOTES_ROOT/config.json}"
GHIDRA_NOTES_QUEUE_DIR="${GHIDRA_NOTES_QUEUE_DIR:-$GHIDRA_NOTES_ROOT/queue}"
GHIDRA_NOTES_CACHE_DIR="${GHIDRA_NOTES_CACHE_DIR:-$GHIDRA_NOTES_ROOT/cache}"
GHIDRA_NOTES_STATE_FILE="${GHIDRA_NOTES_STATE_FILE:-$GHIDRA_NOTES_ROOT/state.json}"
GHIDRA_NOTES_CACHE_JSON="${GHIDRA_NOTES_CACHE_JSON:-$GHIDRA_NOTES_CACHE_DIR/notes.json}"
GHIDRA_NOTES_CACHE_MD="${GHIDRA_NOTES_CACHE_MD:-$GHIDRA_NOTES_CACHE_DIR/issue.md}"

ghidra_re_refresh_default_script_dirs() {
  GHIDRA_DEFAULT_SCRIPT_DIRS=(
    "$GHIDRA_CUSTOM_SCRIPTS_DIR"
    "$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts"
    "$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/ghidra_scripts"
    "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/ghidra_scripts"
    "$GHIDRA_INSTALL_DIR/Ghidra/Features/SwiftDemangler/ghidra_scripts"
    "$GHIDRA_INSTALL_DIR/Ghidra/Features/Jython/ghidra_scripts"
  )
}

ghidra_re_refresh_default_script_dirs

ghidra_re_die() {
  printf 'cerberus-re: %s\n' "$*" >&2
  exit 1
}

ghidra_re_python() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' python3
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    printf '%s\n' python
    return 0
  fi
  return 1
}

ghidra_re_platform_is_windows() {
  [[ "$GHIDRA_RE_PLATFORM" == "windows" ]]
}

ghidra_re_platform_is_macos() {
  [[ "$GHIDRA_RE_PLATFORM" == "macos" ]]
}

ghidra_re_ghidra_run_path() {
  local dir="${1:-$GHIDRA_INSTALL_DIR}"
  local candidate=""
  if ghidra_re_platform_is_windows; then
    for candidate in "$dir/ghidraRun.bat" "$dir/ghidraRun"; do
      [[ -f "$candidate" ]] && {
        printf '%s\n' "$candidate"
        return 0
      }
    done
    return 1
  fi
  for candidate in "$dir/ghidraRun" "$dir/ghidraRun.bat"; do
    [[ -f "$candidate" ]] && {
      printf '%s\n' "$candidate"
      return 0
    }
  done
  return 1
}

ghidra_re_analyze_headless_path() {
  local dir="${1:-$GHIDRA_INSTALL_DIR}"
  local candidate=""
  for candidate in "$dir/support/analyzeHeadless" "$dir/support/analyzeHeadless.bat"; do
    [[ -f "$candidate" ]] && {
      printf '%s\n' "$candidate"
      return 0
    }
  done
  return 1
}

ghidra_re_is_ghidra_dir() {
  local dir="${1:-}"
  [[ -n "$dir" ]] || return 1
  [[ -n "$(ghidra_re_analyze_headless_path "$dir" || true)" && -n "$(ghidra_re_ghidra_run_path "$dir" || true)" ]]
}

ghidra_re_resolve_ghidra_dir() {
  local dir="${1:-}"
  local nested=""
  [[ -n "$dir" && -d "$dir" ]] || return 1
  if ghidra_re_is_ghidra_dir "$dir"; then
    printf '%s\n' "$dir"
    return 0
  fi
  shopt -s nullglob
  for nested in "$dir"/ghidra_* "$dir"/Ghidra_* "$dir"/ghidra "$dir"/Ghidra; do
    if ghidra_re_is_ghidra_dir "$nested"; then
      printf '%s\n' "$nested"
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob
  return 1
}

ghidra_re_gradle_wrapper_path() {
  local dir="${1:-$GHIDRA_INSTALL_DIR}"
  local candidate=""
  for candidate in "$dir/support/gradle/gradlew" "$dir/support/gradle/gradlew.bat"; do
    [[ -f "$candidate" ]] && {
      printf '%s\n' "$candidate"
      return 0
    }
  done
  return 1
}

ghidra_re_valid_ghidra_dir() {
  local dir="${1:-}"
  [[ -n "$(ghidra_re_resolve_ghidra_dir "$dir" || true)" ]]
}

ghidra_re_valid_jdk_dir() {
  local dir="${1:-}"
  [[ -n "$dir" ]] || return 1
  if ghidra_re_platform_is_macos; then
    local resolved_dir=""
    resolved_dir="$(cd "$dir" 2>/dev/null && pwd -P || true)"
    [[ "$resolved_dir" == "/usr" ]] && return 1
  fi
  [[ ( -f "$dir/bin/java" || -f "$dir/bin/java.exe" ) && ( -f "$dir/bin/javac" || -f "$dir/bin/javac.exe" ) ]]
}

ghidra_re_macos_amfi_get_out_enabled() {
  ghidra_re_platform_is_macos || return 1
  local args=""
  args="$(nvram boot-args 2>/dev/null || true)"
  [[ "$args" == *"amfi_get_out_of_my_way=1"* ]]
}

ghidra_re_jdk_java_path() {
  local dir="${1:-}"
  if [[ -f "$dir/bin/java" ]]; then
    printf '%s\n' "$dir/bin/java"
    return 0
  fi
  if [[ -f "$dir/bin/java.exe" ]]; then
    printf '%s\n' "$dir/bin/java.exe"
    return 0
  fi
  return 1
}

ghidra_re_jdk_archs() {
  local dir="${1:-}"
  local java_path=""
  java_path="$(ghidra_re_jdk_java_path "$dir" 2>/dev/null || true)"
  [[ -n "$java_path" ]] || return 1
  if ghidra_re_platform_is_macos && command -v lipo >/dev/null 2>&1; then
    lipo -archs "$java_path" 2>/dev/null || true
  fi
}

ghidra_re_jdk_skip_start_smoke() {
  local dir="${1:-}"
  local archs=""
  ghidra_re_macos_amfi_get_out_enabled || return 1
  archs="$(ghidra_re_jdk_archs "$dir" || true)"
  [[ "$archs" == *arm64* && "$archs" != *x86_64* ]]
}

ghidra_re_jdk_can_start() {
  local dir="${1:-}"
  local java_path=""
  ghidra_re_valid_jdk_dir "$dir" || return 1
  ghidra_re_jdk_skip_start_smoke "$dir" && return 1
  java_path="$(ghidra_re_jdk_java_path "$dir" 2>/dev/null || true)"
  [[ -n "$java_path" ]] || return 1
  "$java_path" -version >/dev/null 2>&1
}

ghidra_re_detect_jdk_from_path() {
  local java_cmd=""
  local resolved=""
  local candidate=""
  for java_cmd in "$(command -v javac 2>/dev/null || true)" "$(command -v java 2>/dev/null || true)"; do
    [[ -n "$java_cmd" ]] || continue
    resolved="$java_cmd"
    if command -v readlink >/dev/null 2>&1; then
      resolved="$(readlink -f "$java_cmd" 2>/dev/null || printf '%s' "$java_cmd")"
    fi
    candidate="$(dirname "$(dirname "$resolved")")"
    if ghidra_re_jdk_can_start "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

ghidra_re_auto_configure_tools() {
  local detected=""
  if ghidra_re_valid_ghidra_dir "$GHIDRA_INSTALL_DIR"; then
    GHIDRA_INSTALL_DIR="$(ghidra_re_resolve_ghidra_dir "$GHIDRA_INSTALL_DIR")"
  else
    detected="$(ghidra_re_detect_ghidra_dir || true)"
    [[ -n "$detected" ]] && GHIDRA_INSTALL_DIR="$detected"
  fi

  if ! ghidra_re_jdk_can_start "$GHIDRA_JDK"; then
    detected="$(ghidra_re_detect_jdk_dir || true)"
    [[ -n "$detected" ]] && GHIDRA_JDK="$detected"
  fi

  ghidra_re_refresh_default_script_dirs
}

ghidra_re_require_tools() {
  ghidra_re_auto_configure_tools
  ghidra_re_valid_ghidra_dir "$GHIDRA_INSTALL_DIR" || ghidra_re_die "missing Ghidra install at $GHIDRA_INSTALL_DIR"
  ghidra_re_valid_jdk_dir "$GHIDRA_JDK" || ghidra_re_die "missing JDK at $GHIDRA_JDK"
  ghidra_re_jdk_can_start "$GHIDRA_JDK" || ghidra_re_die "JDK cannot start at $GHIDRA_JDK; on Apple Silicon with amfi_get_out_of_my_way=1, install an x64 Java 21 JDK and run under Rosetta"
}

ghidra_re_export_env() {
  ghidra_re_auto_configure_tools
  export JAVA_HOME="$GHIDRA_JDK"
  export PATH="$JAVA_HOME/bin:$PATH"
  export GHIDRA_INSTALL_DIR
}

ghidra_re_detect_ghidra_dir() {
  local -a candidates=()
  local candidate
  local resolved=""
  resolved="$(ghidra_re_resolve_ghidra_dir "${GHIDRA_INSTALL_DIR:-}" || true)"
  if [[ -n "$resolved" ]]; then
    printf '%s\n' "$resolved"
    return 0
  fi
  if ghidra_re_platform_is_windows; then
    candidates+=(
      "/c/Program Files/Ghidra"
      "/c/Tools/Ghidra"
      "$HOME/AppData/Local/Programs/Ghidra"
      "$HOME/Downloads"
      "$HOME/Desktop"
    )
    shopt -s nullglob
    candidates+=(
      /c/Program\ Files/ghidra_*
      /c/Program\ Files/Ghidra_*
      /c/Tools/ghidra_*
      /c/Tools/Ghidra_*
      "$HOME"/AppData/Local/Programs/ghidra_*
      "$HOME"/AppData/Local/Programs/Ghidra_*
      "$HOME"/Downloads/ghidra_*
      "$HOME"/Downloads/Ghidra_*
      "$HOME"/Downloads/ghidra_*/ghidra_*
      "$HOME"/Downloads/Ghidra_*/ghidra_*
      "$HOME"/Desktop/ghidra_*
      "$HOME"/Desktop/Ghidra_*
      "$HOME"/Desktop/ghidra_*/ghidra_*
      "$HOME"/Desktop/Ghidra_*/ghidra_*
    )
    shopt -u nullglob
  else
    candidates+=(
      /Applications/Ghidra
      "$HOME/Applications/Ghidra"
      /opt/ghidra
    )
    shopt -s nullglob
    candidates+=(
      /Applications/ghidra_*
      /Applications/Ghidra_*
      "$HOME"/Applications/ghidra_*
      "$HOME"/Applications/Ghidra_*
      "$HOME"/Downloads/ghidra_*
      "$HOME"/Downloads/Ghidra_*
      /opt/ghidra_*
    )
    shopt -u nullglob
  fi
  for candidate in "${candidates[@]}"; do
    resolved="$(ghidra_re_resolve_ghidra_dir "$candidate" || true)"
    if [[ -n "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  return 1
}

ghidra_re_detect_jdk_dir() {
  local candidate=""
  if ghidra_re_jdk_can_start "${GHIDRA_JDK:-}"; then
    printf '%s\n' "$GHIDRA_JDK"
    return 0
  fi
  if ghidra_re_jdk_can_start "${JAVA_HOME:-}"; then
    printf '%s\n' "$JAVA_HOME"
    return 0
  fi
  candidate="$(ghidra_re_detect_jdk_from_path || true)"
  if [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  local -a candidates=()
  if ghidra_re_platform_is_windows; then
    shopt -s nullglob
    candidates+=(
      /c/Program\ Files/Eclipse\ Adoptium/jdk-21*
      /c/Program\ Files/Eclipse\ Adoptium/jdk-*
      /c/Program\ Files/Java/jdk-21*
      /c/Program\ Files/Java/jdk-*
      "$HOME"/AppData/Local/Programs/Eclipse\ Adoptium/jdk-21*
      "$HOME"/AppData/Local/Programs/Eclipse\ Adoptium/jdk-*
      "$HOME"/AppData/Local/Programs/Java/jdk-*
    )
    shopt -u nullglob
  else
    candidates+=(
      "$HOME/.local/jdks/temurin-21-x64.jdk/Contents/Home"
      "$HOME/.local/jdks/zulu-21-x64.jdk/Contents/Home"
      "$HOME/Library/Java/JavaVirtualMachines/temurin-21-x64.jdk/Contents/Home"
      "$HOME/Library/Java/JavaVirtualMachines/zulu-21-x64.jdk/Contents/Home"
      /Library/Java/JavaVirtualMachines/temurin-21-x64.jdk/Contents/Home
      /Library/Java/JavaVirtualMachines/zulu-21-x64.jdk/Contents/Home
      /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
      /usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
      /usr/lib/jvm/java-21-openjdk
      /usr/lib/jvm/jdk-21
    )
  fi
  for candidate in "${candidates[@]}"; do
    if ghidra_re_jdk_can_start "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if ghidra_re_platform_is_macos && [[ -x /usr/libexec/java_home ]]; then
    candidate="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
    if ghidra_re_jdk_can_start "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  return 1
}

ghidra_re_ensure_workspace() {
  mkdir -p "$GHIDRA_PROJECTS_DIR" "$GHIDRA_EXPORTS_DIR" "$GHIDRA_LOGS_DIR" "$GHIDRA_SOURCES_CACHE_DIR"
}

ghidra_re_has_gh_cli() {
  command -v gh >/dev/null 2>&1
}

ghidra_re_gh_authenticated() {
  ghidra_re_has_gh_cli && gh auth status >/dev/null 2>&1
}

cerberus_re_skill_version() {
  if command -v git >/dev/null 2>&1 && [[ -d "$GHIDRA_RE_ROOT/.git" ]]; then
    git -C "$GHIDRA_RE_ROOT" rev-parse --short HEAD 2>/dev/null && return 0
  fi
  printf 'unknown\n'
}

ghidra_re_notes_enabled() {
  ghidra_re_flag_enabled "$GHIDRA_NOTES_ENABLE_SHARED"
}

ghidra_re_notes_auto_sync_enabled() {
  ghidra_re_flag_enabled "$GHIDRA_NOTES_AUTO_SYNC"
}

ghidra_re_notes_issue_url() {
  if [[ -n "${GHIDRA_NOTES_REPO:-}" && -n "${GHIDRA_NOTES_ISSUE_NUMBER:-}" ]]; then
    printf 'https://github.com/%s/issues/%s\n' "$GHIDRA_NOTES_REPO" "$GHIDRA_NOTES_ISSUE_NUMBER"
    return 0
  fi
  return 1
}

ghidra_re_notes_ensure_dirs() {
  mkdir -p "$GHIDRA_NOTES_ROOT" "$GHIDRA_NOTES_QUEUE_DIR" "$GHIDRA_NOTES_CACHE_DIR"
}

ghidra_re_notes_backend() {
  printf '%s/scripts/ghidra_notes_backend.py' "$GHIDRA_RE_ROOT"
}

ghidra_re_notes_init_files() {
  local python_cmd=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for shared notes support"
  ghidra_re_notes_ensure_dirs
  if [[ ! -f "$GHIDRA_NOTES_CONFIG_FILE" ]]; then
    "$python_cmd" - "$GHIDRA_NOTES_CONFIG_FILE" "$GHIDRA_NOTES_REPO" "$GHIDRA_NOTES_ISSUE_TITLE" "$GHIDRA_NOTES_ISSUE_NUMBER" "$GHIDRA_NOTES_ENABLE_SHARED" "$GHIDRA_NOTES_AUTO_SYNC" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = {
    "version": 1,
    "repo": sys.argv[2],
    "issue_title": sys.argv[3],
    "issue_number": sys.argv[4],
    "issue_url": f"https://github.com/{sys.argv[2]}/issues/{sys.argv[4]}" if sys.argv[4] else "",
    "enabled": sys.argv[5] not in {"0", "false", "no", "off"},
    "auto_sync": sys.argv[6] not in {"0", "false", "no", "off"},
}
path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
  fi
  if [[ ! -f "$GHIDRA_NOTES_STATE_FILE" ]]; then
    "$python_cmd" - "$GHIDRA_NOTES_STATE_FILE" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = {
    "version": 1,
    "last_sync_at": "",
    "last_pull_at": "",
    "last_error": "",
    "pending_queue_count": 0,
    "issue_url": "",
    "issue_number": "",
}
path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
  fi
  if [[ ! -f "$GHIDRA_NOTES_CACHE_JSON" ]]; then
    "$python_cmd" - "$GHIDRA_NOTES_CACHE_JSON" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = {"version": 1, "notes": [], "recently_seen": []}
path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
  fi
  if [[ ! -f "$GHIDRA_NOTES_CACHE_MD" ]]; then
    printf '# Shared Use-Case Notes\n\nNo shared notes have been pulled yet.\n' >"$GHIDRA_NOTES_CACHE_MD"
  fi
}

ghidra_re_notes_queue_count() {
  ghidra_re_notes_ensure_dirs
  find "$GHIDRA_NOTES_QUEUE_DIR" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' '
}

ghidra_re_notes_current_context_json() {
  local requested_session="${1:-}"
  local requested_project="${2:-}"
  local requested_program="${3:-}"
  local python_cmd=""
  local session_file=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for shared notes support"
  if [[ -n "$requested_session" || -n "$requested_project" || -n "$requested_program" ]]; then
    session_file="$(ghidra_re_bridge_resolve_session_file "$requested_session" "$requested_project" "$requested_program" 2>/dev/null || true)"
  else
    session_file="$(ghidra_re_bridge_current_session_file || true)"
  fi
  "$python_cmd" - "$session_file" "$GHIDRA_RE_PLATFORM" "$GHIDRA_RE_ROOT" <<'PY'
import json, pathlib, subprocess, sys

session_file = sys.argv[1]
platform = sys.argv[2]
skill_root = pathlib.Path(sys.argv[3])

payload = {
    "platform": platform or "unknown",
    "skill_version": "unknown",
    "context_mode": "headless",
    "mission_name": "",
    "project_name": "",
    "program_name": "",
    "program_path": "",
    "session_id": "",
}

if (skill_root / ".git").exists():
    try:
        payload["skill_version"] = subprocess.check_output(
            ["git", "-C", str(skill_root), "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip() or "unknown"
    except Exception:
        pass

if session_file and pathlib.Path(session_file).is_file():
    try:
        session = json.loads(pathlib.Path(session_file).read_text(encoding="utf-8"))
        payload["context_mode"] = "live"
        payload["project_name"] = session.get("project_name", "")
        payload["program_name"] = session.get("program_name", "")
        payload["program_path"] = session.get("program_path", "")
        payload["session_id"] = session.get("session_id", "")
    except Exception:
        pass

print(json.dumps(payload))
PY
}

ghidra_re_auto_configure_tools

ghidra_re_timestamp() {
  date '+%Y%m%d-%H%M%S'
}

ghidra_re_sanitize_name() {
  local raw="$1"
  raw="${raw##*/}"
  raw="${raw%.*}"
  raw="$(printf '%s' "$raw" | tr '[:space:]/:' '_' | tr -cd '[:alnum:]_.-')"
  if [[ -z "$raw" ]]; then
    raw="ghidra_project"
  fi
  printf '%s' "$raw"
}

ghidra_re_project_location() {
  printf '%s/%s' "$GHIDRA_PROJECTS_DIR" "$1"
}

ghidra_re_project_file() {
  printf '%s/%s/%s.gpr' "$GHIDRA_PROJECTS_DIR" "$1" "$1"
}

ghidra_re_project_rep_dir() {
  printf '%s/%s/%s.rep' "$GHIDRA_PROJECTS_DIR" "$1" "$1"
}

ghidra_re_headless_lock_path() {
  local project_name="$1"
  local project_dir=""
  local key=""
  project_dir="$(ghidra_re_project_location "$project_name")"
  key="$(ghidra_re_sanitize_name "$project_dir")"
  printf '%s/headless-locks/%s.lockdir' "$GHIDRA_RE_CONFIG_HOME" "$key"
}

ghidra_re_stat_mtime() {
  local path="$1"
  stat -f %m "$path" 2>/dev/null || stat -c %Y "$path" 2>/dev/null || printf '0'
}

ghidra_re_acquire_headless_lock() {
  local project_name="$1"
  local operation="${2:-headless}"
  local timeout_s="${GHIDRA_HEADLESS_LOCK_TIMEOUT:-600}"
  local stale_s="${GHIDRA_HEADLESS_LOCK_STALE_SECONDS:-1800}"
  local lock_dir=""
  local start_s=""
  local now_s=""
  local mtime_s=""
  lock_dir="$(ghidra_re_headless_lock_path "$project_name")"
  mkdir -p "$(dirname "$lock_dir")"
  start_s="$(date +%s)"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    now_s="$(date +%s)"
    mtime_s="$(ghidra_re_stat_mtime "$lock_dir")"
    if [[ "$mtime_s" =~ ^[0-9]+$ && $((now_s - mtime_s)) -ge "$stale_s" ]]; then
      rm -rf "$lock_dir"
      continue
    fi
    if [[ $((now_s - start_s)) -ge "$timeout_s" ]]; then
      ghidra_re_die "timed out waiting for Ghidra headless project lock at $lock_dir; avoid running same-project headless operations in parallel"
    fi
    sleep 1
  done
  "$(ghidra_re_python)" - "$lock_dir" "$project_name" "$operation" "$(ghidra_re_project_location "$project_name")" <<'PY'
import json, os, pathlib, sys, datetime
lock_dir, project, operation, project_location = sys.argv[1:5]
payload = {
    "project_name": project,
    "project_location": project_location,
    "operation": operation,
    "pid": os.getpid(),
    "created_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
}
pathlib.Path(lock_dir, "owner.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
  printf '%s' "$lock_dir"
}

ghidra_re_release_headless_lock() {
  local lock_dir="${1:-}"
  [[ -n "$lock_dir" ]] || return 0
  rm -rf "$lock_dir"
}

ghidra_re_log_dir() {
  printf '%s/%s' "$GHIDRA_LOGS_DIR" "$1"
}

ghidra_re_export_dir() {
  printf '%s/%s/%s' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_triage_dir() {
  printf '%s/%s/%s/triage' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_dossiers_dir() {
  printf '%s/%s/%s/dossiers' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_findings_dir() {
  printf '%s/%s/%s/findings' "$GHIDRA_EXPORTS_DIR" "$1" "$2"
}

ghidra_re_target_key() {
  printf '%s:%s' "$1" "$2"
}

ghidra_re_source_registry_init() {
  local python_cmd=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for source registry support"
  mkdir -p "$(dirname "$GHIDRA_RE_SOURCE_REGISTRY_FILE")"
  if [[ ! -f "$GHIDRA_RE_SOURCE_REGISTRY_FILE" ]]; then
    "$python_cmd" - "$GHIDRA_RE_SOURCE_REGISTRY_FILE" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"version": 1, "sources": []}, indent=2), encoding="utf-8")
PY
  fi
}

ghidra_re_source_lookup() {
  local source_name="$1"
  local python_cmd=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for source registry support"
  ghidra_re_source_registry_init
  "$python_cmd" - "$GHIDRA_RE_SOURCE_REGISTRY_FILE" "$source_name" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
name = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
for item in payload.get("sources", []):
    if item.get("name") == name:
        print(json.dumps(item))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

ghidra_re_source_resolve_path() {
  local source_name="$1"
  local source_relative_path="$2"
  local copy_mode="${3:-cache}"
  local python_cmd=""
  local source_json=""
  python_cmd="$(ghidra_re_python)" || ghidra_re_die "python is required for source registry support"
  source_json="$(ghidra_re_source_lookup "$source_name")" || ghidra_re_die "source not found: $source_name"
  "$python_cmd" - "$source_json" "$source_relative_path" "$copy_mode" "$GHIDRA_SOURCES_CACHE_DIR" <<'PY'
import json, pathlib, shutil, sys
source = json.loads(sys.argv[1])
relative = sys.argv[2]
copy_mode = sys.argv[3]
cache_root = pathlib.Path(sys.argv[4])
root = pathlib.Path(source.get("root", ""))
if not root.exists():
    raise SystemExit(f"source root not found: {root}")
relative_path = pathlib.PurePosixPath(relative)
parts = [part for part in relative_path.parts if part not in ("", "/")]
resolved = root.joinpath(*parts)
if not resolved.exists():
    raise SystemExit(f"target not found in source {source.get('name')}: {resolved}")
if copy_mode == "direct":
    print(str(resolved))
    raise SystemExit(0)
cache_path = cache_root / source.get("name", "source") / pathlib.Path(*parts)
cache_path.parent.mkdir(parents=True, exist_ok=True)
if resolved.is_file():
    shutil.copy2(resolved, cache_path)
else:
    if cache_path.exists():
      shutil.rmtree(cache_path)
    shutil.copytree(resolved, cache_path)
print(str(cache_path))
PY
}

ghidra_re_resolve_binary_spec() {
  local spec="$1"
  local copy_mode="${2:-cache}"
  if [[ -f "$spec" ]]; then
    printf '%s\n' "$spec"
    return 0
  fi
  if [[ "$spec" == source:*:* ]]; then
    local source_name="${spec#source:}"
    source_name="${source_name%%:*}"
    local source_path="${spec#source:${source_name}:}"
    ghidra_re_source_resolve_path "$source_name" "$source_path" "$copy_mode"
    return 0
  fi
  return 1
}

ghidra_re_program_name_from_binary() {
  basename "$1"
}

ghidra_re_triage_manifest() {
  [[ -f "$GHIDRA_RE_TRIAGE_MANIFEST" ]] || \
    ghidra_re_die "triage manifest not found at $GHIDRA_RE_TRIAGE_MANIFEST"
  printf '%s' "$GHIDRA_RE_TRIAGE_MANIFEST"
}

ghidra_re_join_script_paths() {
  local joined=""
  local path
  for path in "$@"; do
    [[ -z "$path" ]] && continue
    if ghidra_re_platform_is_windows && command -v cygpath >/dev/null 2>&1; then
      case "$path" in
        /*|.*|~*)
          path="$(cygpath -aw "$path" 2>/dev/null || printf '%s' "$path")"
          ;;
      esac
    fi
    if [[ -z "$joined" ]]; then
      joined="$path"
    else
      joined="${joined};${path}"
    fi
  done
  printf '%s' "$joined"
}

ghidra_re_script_path() {
  local dirs=("${GHIDRA_DEFAULT_SCRIPT_DIRS[@]}")
  local extra
  for extra in "$@"; do
    [[ -z "$extra" ]] && continue
    dirs+=("$extra")
  done
  ghidra_re_join_script_paths "${dirs[@]}"
}

ghidra_re_optional_headless_args() {
  local args=()
  if [[ -n "${GHIDRA_ANALYSIS_TIMEOUT_PER_FILE:-}" ]]; then
    args+=("-analysisTimeoutPerFile" "$GHIDRA_ANALYSIS_TIMEOUT_PER_FILE")
  fi
  if [[ -n "${GHIDRA_MAX_CPU:-}" ]]; then
    args+=("-max-cpu" "$GHIDRA_MAX_CPU")
  fi
  if [[ ${#args[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\0' "${args[@]}"
}

ghidra_re_normalize_script_args() {
  local normalized=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --*=*)
        normalized+=("${1#--}")
        shift
        ;;
      --*)
        [[ $# -ge 2 ]] || ghidra_re_die "missing value for script argument $1"
        normalized+=("${1#--}=$2")
        shift 2
        ;;
      *)
        normalized+=("$1")
        shift
        ;;
    esac
  done
  if [[ ${#normalized[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s\0' "${normalized[@]}"
}

ghidra_re_flag_enabled() {
  local value="${1:-}"
  case "$value" in
    1|true|yes|on|"")
      return 0
      ;;
    0|false|no|off)
      return 1
      ;;
    *)
      ghidra_re_die "unsupported boolean flag value: $value"
      ;;
  esac
}

ghidra_re_require_project() {
  local project_name="$1"
  [[ -f "$(ghidra_re_project_file "$project_name")" ]] || ghidra_re_die "project $project_name not found at $(ghidra_re_project_file "$project_name")"
}
