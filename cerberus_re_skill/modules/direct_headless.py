"""Direct Ghidra headless helpers that bypass the launcher wrapper."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import timestamp


def direct_export_apple_bundle(
    project: str,
    program: str,
    output_dir: str | Path,
    *,
    timeout_seconds: float = 600.0,
) -> dict[str, Any]:
    """Run ExportAppleBundle.java through direct Java 21 AnalyzeHeadless."""
    java = _java_bin()
    utility_jar = cfg.ghidra_install_dir / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    if not utility_jar.exists():
        raise RuntimeError(f"Ghidra Utility.jar not found: {utility_jar}")
    project_location = cfg.project_location(project)
    out = Path(output_dir)
    log_dir = cfg.logs_dir / project
    log_dir.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    stamp = timestamp()
    log_file = log_dir / f"direct-export-apple-bundle-{stamp}.log"
    script_log = log_dir / f"direct-export-apple-bundle-{stamp}.script.log"
    command = [
        str(java),
        "-Xmx2G",
        "-XX:ParallelGCThreads=2",
        "-XX:CICompilerCount=2",
        "-Djava.awt.headless=true",
        "-Djava.system.class.loader=ghidra.GhidraClassLoader",
        "-cp",
        str(utility_jar),
        "ghidra.Ghidra",
        "ghidra.app.util.headless.AnalyzeHeadless",
        str(project_location),
        project,
        "-readOnly",
        "-noanalysis",
        "-scriptPath",
        cfg.script_path_str(),
        "-postScript",
        "ExportAppleBundle.java",
        f"outdir={out}",
        "-process",
        program,
        "-log",
        str(log_file),
        "-scriptlog",
        str(script_log),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=str(cfg.skill_root),
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "command": command,
            "output": str(out),
            "log": str(log_file),
            "script_log": str(script_log),
            "stdout": _decode(result.stdout),
            "stderr": _decode(result.stderr),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": 124,
            "command": command,
            "output": str(out),
            "log": str(log_file),
            "script_log": str(script_log),
            "stdout": _decode(exc.stdout),
            "stderr": _decode(exc.stderr) or "timed out",
        }


def _java_bin() -> Path:
    override = os.environ.get("GHIDRA_RE_DIRECT_JAVA")
    if override:
        path = Path(override)
        if path.exists():
            return path
    candidates = []
    if cfg.ghidra_jdk:
        candidates.append(cfg.ghidra_jdk / "bin" / "java")
    candidates.extend(
        [
            Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home/bin/java"),
            Path("/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home/bin/java"),
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    try:
        home = subprocess.check_output(["/usr/libexec/java_home", "-v", "21"], text=True).strip()
        if home:
            java = Path(home) / "bin" / "java"
            if java.exists():
                return java
    except Exception:
        pass
    raise RuntimeError("Java 21 executable not found for direct Ghidra headless fallback")


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="replace")
