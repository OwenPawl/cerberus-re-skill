"""Generate a disposable iOS Simulator framework-loading host."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Sequence

from cerberus_re_skill.core.config import cfg


SIMULATOR_FRAMEWORK_HOST_SCHEMA = "ghidra-re.simulator-framework-host.v1"
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess]


def generate_simulator_framework_host(
    *,
    frameworks: Sequence[str],
    output: str | Path | None = None,
    compile_harness: bool = False,
    compile_output: str | Path | None = None,
    deployment_target: str = "18.0",
    hold_seconds: int = 120,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Generate a load-only simulator host for isolated external probing."""
    normalized = _normalize_frameworks(frameworks)
    if hold_seconds < 1 or hold_seconds > 86400:
        raise RuntimeError("hold_seconds must be between 1 and 86400")
    if not deployment_target.strip():
        raise RuntimeError("deployment_target is required")

    out_path = Path(output) if output else cfg.exports_dir / "simulator_framework_host.m"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_render_host(normalized, hold_seconds=hold_seconds), encoding="utf-8")
    result: dict[str, Any] = {
        "ok": True,
        "schema": SIMULATOR_FRAMEWORK_HOST_SCHEMA,
        "output": str(out_path),
        "frameworks": normalized,
        "deployment_target": deployment_target,
        "hold_seconds": hold_seconds,
        "platform": "ios-simulator",
        "safety_default": "load_only_wait_for_external_probe",
        "runtime_invocation": "not_performed",
    }
    if compile_harness:
        build = compile_simulator_framework_host(
            out_path,
            output=compile_output,
            deployment_target=deployment_target,
            runner=runner,
        )
        result["compile"] = build
        result["ok"] = build["ok"]
    return result


def compile_simulator_framework_host(
    source_path: str | Path,
    *,
    output: str | Path | None = None,
    deployment_target: str = "18.0",
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Compile and ad-hoc sign a generated simulator host executable."""
    source = Path(source_path)
    if not source.exists():
        raise RuntimeError(f"simulator host source not found: {source}")
    xcrun = shutil.which("xcrun")
    if not xcrun:
        raise RuntimeError("xcrun not found; cannot compile an iOS Simulator host")
    codesign = shutil.which("codesign")
    if not codesign:
        raise RuntimeError("codesign not found; cannot sign an iOS Simulator host")

    out_path = Path(output) if output else source.with_suffix("")
    command = [
        xcrun,
        "--sdk",
        "iphonesimulator",
        "clang",
        "-fobjc-arc",
        "-framework",
        "Foundation",
        "-target",
        f"arm64-apple-ios{deployment_target}-simulator",
        str(source),
        "-o",
        str(out_path),
    ]
    run = runner or _run_command
    compile_proc = run(command)
    compile_result = _command_result(command, compile_proc)
    if not compile_result["ok"]:
        return {
            "ok": False,
            "output": str(out_path),
            "compile": compile_result,
            "sign": {"ok": False, "status": "skipped_compile_failed"},
        }

    sign_command = [codesign, "-s", "-", str(out_path)]
    sign_result = _command_result(sign_command, run(sign_command))
    return {
        "ok": sign_result["ok"],
        "output": str(out_path),
        "compile": compile_result,
        "sign": sign_result,
    }


def _normalize_frameworks(frameworks: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for framework in frameworks:
        path = framework.strip()
        if not path:
            continue
        if not path.startswith("/"):
            raise RuntimeError("framework paths must be absolute simulator paths")
        if path not in normalized:
            normalized.append(path)
    if not normalized:
        raise RuntimeError("at least one --framework path is required")
    return normalized


def _command_result(command: Sequence[str], proc: subprocess.CompletedProcess) -> dict[str, Any]:
    return {
        "ok": proc.returncode == 0,
        "command": list(command),
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[-4000:] if isinstance(proc.stdout, str) else "",
        "stderr": (proc.stderr or "")[-4000:] if isinstance(proc.stderr, str) else "",
    }


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(part) for part in command],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _render_host(frameworks: Sequence[str], *, hold_seconds: int) -> str:
    loads: list[str] = []
    for index, framework in enumerate(frameworks):
        literal = json.dumps(framework)
        loads.extend(
            [
                f"        void *handle{index} = dlopen({literal}, RTLD_NOW);",
                f"        const char *error{index} = dlerror();",
                f"        printf(\" framework_{index}=%p framework_{index}_error=%s\", handle{index}, error{index} ?: \"\");",
                f"        loaded = loaded && handle{index} != NULL;",
            ]
        )
    load_body = "\n".join(loads)
    return f"""// Generated by ghidra-re export simulator-framework-host.
// Safety default: load requested frameworks, emit readiness, and wait for an external probe.
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <unistd.h>

int main(void) {{
    @autoreleasepool {{
        BOOL loaded = YES;
        printf("GHIDRA_RE_SIMULATOR_HOST pid=%d", getpid());
{load_body}
        printf("\\n");
        fflush(stdout);
        if (!loaded) {{
            return 2;
        }}
        sleep({hold_seconds});
    }}
    return 0;
}}
"""
