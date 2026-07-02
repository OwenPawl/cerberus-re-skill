"""Import and analysis: import_analyze, import_macos_framework, run_script."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.ghidra_locator import analyze_headless_path
from cerberus_re_skill.core.subprocess_utils import find_python, find_tool, run
from cerberus_re_skill.core.utils import flag_enabled, sanitize_name, timestamp
from cerberus_re_skill.modules.headless_lock import project_headless_lock

HEADLESS_SCRIPT_FAILURE_MARKERS = (
    "ERROR REPORT SCRIPT ERROR",
    "SCRIPT ERROR:",
    "GhidraScriptLoadException",
    "ClassNotFoundException",
    "NoClassDefFoundError",
    "The class could not be found or loaded",
)


def _python() -> str:
    return find_python()


def _headless() -> Path:
    auto_configure()
    headless = analyze_headless_path(cfg.ghidra_install_dir)
    if not headless:
        raise RuntimeError(f"analyzeHeadless not found in {cfg.ghidra_install_dir}")
    return headless


def auto_configure() -> None:
    from cerberus_re_skill.modules.bridge import auto_configure as _ac
    _ac()


def _optional_headless_args() -> list[str]:
    args = []
    if cfg.analysis_timeout_per_file:
        args += ["-analysisTimeoutPerFile", cfg.analysis_timeout_per_file]
    if cfg.max_cpu:
        args += ["-max-cpu", cfg.max_cpu]
    return args


def _macho_loader_args(skip_macho_reexports: bool) -> list[str]:
    if not skip_macho_reexports:
        return []
    return ["-loader", "MachoLoader", "-loader-reexport", "false"]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _macho_archs(binary: Path) -> list[str]:
    lipo = find_tool("lipo")
    if not lipo:
        raise RuntimeError("--macho-arch requires Apple's lipo tool on PATH")
    result = run([lipo, "-archs", binary], check=False, capture_output=True)
    stdout = result.stdout.decode(errors="replace").strip()
    stderr = result.stderr.decode(errors="replace").strip()
    if result.returncode != 0:
        detail = stderr or stdout or f"lipo exited {result.returncode}"
        raise RuntimeError(f"--macho-arch requires a Mach-O readable by lipo: {detail}")
    return stdout.split()


def _stage_macho_arch(binary: Path, arch: str) -> tuple[Path, dict[str, Any]]:
    requested = arch.strip()
    if not requested:
        raise RuntimeError("--macho-arch cannot be empty")
    if not re.fullmatch(r"[A-Za-z0-9_]+", requested):
        raise RuntimeError(f"unsupported --macho-arch value: {arch!r}")

    archs = _macho_archs(binary)
    if requested not in archs:
        raise RuntimeError(
            f"requested Mach-O arch {requested!r} not found in {binary}; "
            f"available: {', '.join(archs) or '<none>'}"
        )
    if len(archs) == 1:
        return binary, {
            "requested_arch": requested,
            "available_archs": archs,
            "staged": False,
            "reason": "input_already_single_arch",
        }

    digest = _sha256_file(binary)[:16]
    out_dir = cfg.sources_cache_dir / "macho-slices" / digest
    out_dir.mkdir(parents=True, exist_ok=True)
    staged = out_dir / f"{binary.name}.{requested}"
    if not staged.exists():
        lipo = find_tool("lipo")
        if not lipo:
            raise RuntimeError("--macho-arch requires Apple's lipo tool on PATH")
        tmp = staged.with_name(f".{staged.name}.tmp")
        try:
            run([lipo, "-thin", requested, binary, "-output", tmp], check=True)
            os.replace(tmp, staged)
        except Exception:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
    return staged, {
        "requested_arch": requested,
        "available_archs": archs,
        "staged": True,
        "original_binary": str(binary),
        "staged_binary": str(staged),
    }


def import_analyze(
    binary_path: str | Path,
    project_name: str | None = None,
    *,
    skip_macho_reexports: bool = False,
    macho_arch: str = "",
    disable_analysis_options: list[str] | None = None,
) -> dict:
    """Import and analyze a binary with Ghidra analyzeHeadless.

    Returns a dict with project/program/log info.
    """
    from cerberus_re_skill.modules.bridge import ensure_workspace, export_env, require_tools

    source_resolution = None
    if isinstance(binary_path, str) and binary_path.startswith("source:"):
        from cerberus_re_skill.modules.sources import resolve_source

        try:
            _prefix, source_name, source_path = binary_path.split(":", 2)
        except ValueError:
            raise RuntimeError("source import spec must be source:<name>:/path/in/source")
        source_resolution = resolve_source(source_name, source_path)
        binary_path = source_resolution["resolution"]["resolved_path"]

    binary = Path(binary_path)
    if not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")

    macho_arch_info: dict[str, Any] | None = None
    if macho_arch:
        binary, macho_arch_info = _stage_macho_arch(binary, macho_arch)

    if project_name is None:
        project_name = sanitize_name(binary.stem)
    disabled_options = _normalize_disabled_analysis_options(disable_analysis_options or [])

    program_name = binary.name
    project_location = cfg.project_location(project_name)
    log_dir = cfg.log_dir(project_name)
    ts = timestamp()
    log_file = log_dir / f"import-{ts}.log"
    script_log = log_dir / f"import-{ts}.script.log"
    script_path = cfg.script_path_str()

    require_tools()
    env = export_env()
    ensure_workspace()
    project_location.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    headless = _headless()
    cmd: list[str] = [
        str(headless),
        str(project_location),
        project_name,
        "-import", str(binary),
        "-overwrite",
    ]
    cmd += _macho_loader_args(skip_macho_reexports)
    cmd += ["-scriptPath", script_path]
    if disabled_options:
        cmd += [
            "-preScript",
            "SetAnalysisOptions.java",
            *[f"{option}=false" for option in disabled_options],
        ]
    if flag_enabled(cfg.import_demangle):
        cmd += ["-postScript", "DemangleAllScript.java"]
    cmd += _optional_headless_args()
    cmd += ["-log", str(log_file), "-scriptlog", str(script_log)]

    with project_headless_lock(project_name, project_location, operation="import-analyze"):
        run(cmd, env=env, check=True)

    failure_reason = _import_failure_reason(log_file, script_log)
    if failure_reason:
        raise RuntimeError(f"Ghidra import failed: {failure_reason}")

    summary = _summarize_import_log(log_file, script_log)

    return {
        "ok": True,
        "binary": str(binary),
        "project_name": project_name,
        "program_name": program_name,
        "source_resolution": source_resolution,
        "project_file": str(cfg.project_file(project_name)),
        "log": str(log_file),
        "script_log": str(script_log),
        "warnings": summary,
        "skip_macho_reexports": skip_macho_reexports,
        "macho_arch": macho_arch_info,
        "disabled_analysis_options": disabled_options,
    }


def _normalize_disabled_analysis_options(options: list[str]) -> list[str]:
    normalized: list[str] = []
    for option in options:
        name = str(option).strip()
        if not name:
            raise RuntimeError("--disable-analysis-option cannot be empty")
        if name.startswith("-"):
            raise RuntimeError(f"analysis option names cannot start with '-': {name!r}")
        if name not in normalized:
            normalized.append(name)
    return normalized


def _import_failure_reason(log_file: Path, script_log: Path) -> str:
    haystack = ""
    for path in (log_file, script_log):
        if path.exists():
            haystack += path.read_text(encoding="utf-8", errors="replace") + "\n"
    markers = [
        "REPORT: Import failed",
        "Import failed for file",
        "Abort due to Headless analyzer error",
    ]
    for marker in markers:
        if marker in haystack:
            return _headless_failure_tail(haystack) or marker
    return ""


def _summarize_import_log(log_file: Path, script_log: Path) -> dict:
    unresolved_count = 0
    system = private = swift_rt = other = 0
    symbol_length_failures = 0
    demangle_failures = 0

    if log_file.exists():
        text = log_file.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if "-> not found in project" in line:
                unresolved_count += 1
                m = re.search(r"\[(.+?)\]", line)
                path = m.group(1) if m else ""
                if path.startswith("/usr/lib/swift/"):
                    swift_rt += 1
                elif path.startswith("/System/Library/PrivateFrameworks/"):
                    private += 1
                elif path.startswith("/System/Library/Frameworks/") or path.startswith("/usr/lib/"):
                    system += 1
                else:
                    other += 1
            if "Symbol name exceeds maximum length" in line:
                symbol_length_failures += 1

    if script_log.exists():
        with script_log.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "Unable to demangle:" in line:
                    demangle_failures += 1

    return {
        "unresolved_count": unresolved_count,
        "unresolved_system": system,
        "unresolved_private": private,
        "unresolved_swift_runtime": swift_rt,
        "unresolved_other": other,
        "symbol_length_failures": symbol_length_failures,
        "demangle_failures": demangle_failures,
    }


def import_macos_framework(
    framework_path: str | Path,
    project_name: str | None = None,
) -> dict:
    """Import a macOS framework by resolving its executable first."""
    framework = Path(framework_path)
    if not framework.exists():
        raise RuntimeError(f"framework not found: {framework}")
    executable = _resolve_framework_executable(framework)
    if executable is None:
        raise RuntimeError(
            "framework executable not found on disk; dyld-cache-only framework "
            "import is not supported by import macos-framework yet"
        )
    return import_analyze(str(executable), project_name)


def _resolve_framework_executable(framework: Path) -> Path | None:
    if framework.is_file():
        return framework
    if framework.suffix != ".framework":
        return None
    name = framework.name[: -len(".framework")]
    for candidate in (
        framework / name,
        framework / "Versions" / "Current" / name,
        framework / "Versions" / "A" / name,
    ):
        if candidate.is_file():
            return candidate
    return None


def run_script(
    script_name: str,
    project_name: str,
    program_name: str | None = None,
    script_args: list[str] | None = None,
    extra_script_paths: list[Path] | None = None,
) -> dict:
    """Run a Ghidra headless script against an existing project/program."""
    from cerberus_re_skill.modules.bridge import ensure_workspace, export_env, require_tools

    project_file = cfg.project_file(project_name)
    if not project_file.exists():
        raise RuntimeError(f"project {project_name!r} not found at {project_file}")

    bridge_sessions = _matching_bridge_session_summaries(project_name, program_name or "")
    if bridge_sessions:
        session_list = ", ".join(bridge_sessions)
        raise RuntimeError(
            "active bridge session holds the Ghidra project lock; close it before "
            f"running headless script exports: python3 -m cerberus_re_skill bridge close --project {project_name}. "
            f"Matching session(s): {session_list}"
        )

    project_location = cfg.project_location(project_name)
    log_dir = cfg.log_dir(project_name)
    ts = timestamp()
    log_file = log_dir / f"script-{ts}.log"
    script_log = log_dir / f"script-{ts}.script.log"
    script_path = cfg.script_path_str(extra_script_paths)

    require_tools()
    env = export_env()
    log_dir.mkdir(parents=True, exist_ok=True)

    headless = _headless()
    cmd: list[str] = [
        str(headless),
        str(project_location),
        project_name,
        "-readOnly",
    ]
    if not flag_enabled(os.environ.get("GHIDRA_RUN_SCRIPT_ANALYSIS", "0")):
        cmd += ["-noanalysis"]
    cmd += [
        "-scriptPath", script_path,
        "-postScript", script_name,
    ]
    if script_args:
        cmd += script_args
    if program_name:
        cmd += ["-process", program_name]
    cmd += _optional_headless_args()
    cmd += ["-log", str(log_file), "-scriptlog", str(script_log)]

    with project_headless_lock(project_name, project_location, operation=f"run-script:{script_name}"):
        result = run(cmd, env=env, check=False, capture_output=True)

    failure = _headless_script_failure(
        result.returncode,
        _decode_process_bytes(result.stdout),
        _decode_process_bytes(result.stderr),
        log_file,
        script_log,
    )
    if failure:
        raise RuntimeError(f"Ghidra script {script_name} failed: {failure}")

    return {
        "ok": True,
        "project_name": project_name,
        "script_name": script_name,
        "log": str(log_file),
        "script_log": str(script_log),
    }


def _matching_bridge_session_summaries(project_name: str, program_name: str) -> list[str]:
    try:
        from cerberus_re_skill.modules.bridge_sessions import find_matching_sessions
    except Exception:
        return []

    try:
        matches = find_matching_sessions("", project_name, program_name)
    except Exception:
        return []

    summaries: list[str] = []
    for session_file in matches:
        try:
            payload = json.loads(Path(session_file).read_text(encoding="utf-8"))
        except Exception:
            summaries.append(str(session_file))
            continue
        session_id = str(payload.get("session_id") or Path(session_file).stem)
        pid = payload.get("pid")
        program = payload.get("program_name") or payload.get("program_path") or ""
        details = f"{session_id}"
        if pid:
            details += f" pid={pid}"
        if program:
            details += f" program={program}"
        summaries.append(details)
    return summaries


def _headless_script_failure(
    returncode: int,
    stdout: str,
    stderr: str,
    log_file: Path,
    script_log: Path,
) -> str:
    parts = [stdout, stderr, _read_text_if_exists(log_file), _read_text_if_exists(script_log)]
    haystack = "\n".join(part for part in parts if part)
    if returncode != 0:
        return _headless_failure_tail(haystack) or f"AnalyzeHeadless exited {returncode}"
    if any(marker in haystack for marker in HEADLESS_SCRIPT_FAILURE_MARKERS):
        return _headless_failure_tail(haystack) or "script failure marker observed"
    return ""


def _headless_failure_tail(text: str) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    marker_indexes = [
        index for index, line in enumerate(lines)
        if any(marker in line for marker in HEADLESS_SCRIPT_FAILURE_MARKERS)
    ]
    if marker_indexes:
        start = max(0, marker_indexes[0] - 2)
        end = min(len(lines), marker_indexes[-1] + 8)
        return "\n".join(lines[start:end])
    return "\n".join(lines[-12:])


def _read_text_if_exists(path: Path) -> str:
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    return ""


def _decode_process_bytes(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="replace")
