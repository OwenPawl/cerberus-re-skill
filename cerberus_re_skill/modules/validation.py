"""Local validation report generation for ghidra-re."""

from __future__ import annotations

import json
import os
import signal
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import timestamp, utc_now


@dataclass(frozen=True)
class ValidationProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], Path, float], ValidationProcessResult]


def validate_local(
    *,
    headless_smoke: bool = False,
    live_bridge_smoke: bool = False,
    lldb_smoke: bool = False,
    frida_smoke: bool = False,
    frida_target: str | Path | None = None,
    output_dir: str | Path | None = None,
    timeout_seconds: float = 180.0,
    runner: CommandRunner | None = None,
) -> dict:
    """Run local validation checks and write JSON/Markdown evidence."""
    report_dir = Path(output_dir) if output_dir else cfg.logs_dir / "validation" / f"validation-{timestamp()}"
    report_dir.mkdir(parents=True, exist_ok=True)
    run_command = runner or _run_command
    steps: list[dict] = []

    def add(label: str, command: Sequence[str], timeout: float | None = None) -> dict:
        step = _run_step(label, command, report_dir, run_command, timeout or timeout_seconds)
        steps.append(step)
        return step

    add("compile Python sources", [sys.executable, "-m", "compileall", "cerberus_re_skill", "scripts", "tests"], 300)
    add("unit tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests"], 180)
    add("doctor", [sys.executable, "-m", "cerberus_re_skill", "doctor"], 120)
    add("bridge audit", [sys.executable, "-m", "cerberus_re_skill", "bridge", "audit"], 60)
    if (cfg.skill_root / ".git").exists():
        add("git diff whitespace check", _git_diff_check_command(runner is None), 60)

    if headless_smoke:
        add("headless import /usr/bin/true", [sys.executable, "-m", "cerberus_re_skill", "import", "analyze", "/usr/bin/true", "codex_true_smoke"], 600)
        export_step = add(
            "headless Apple bundle export",
            [
                str(cfg.skill_root / "scripts" / "ghidra_export_apple_bundle"),
                "codex_true_smoke",
                "true",
                f"outdir={report_dir / 'codex_true_export'}",
            ],
            timeout_seconds,
        )
        fallback_step = None
        if runner is None and _should_try_direct_headless_fallback(export_step):
            fallback_step = _run_direct_headless_export_step(
                report_dir=report_dir,
                timeout_seconds=timeout_seconds,
            )
            steps.append(
                fallback_step
            )
        if export_step["ok"]:
            add(
                "headless decompile script",
                [
                    str(cfg.skill_root / "scripts" / "ghidra_run_script"),
                    "codex_true_smoke",
                    "true",
                    "DecompileFunction.java",
                    f"output={report_dir / 'codex_true_decompile.c'}",
                ],
                timeout_seconds,
            )

    if live_bridge_smoke:
        add("live bridge ensure project", [sys.executable, "-m", "cerberus_re_skill", "import", "analyze", "/usr/bin/true", "codex_true_smoke"], 600)
        add("live bridge audit before", [sys.executable, "-m", "cerberus_re_skill", "bridge", "audit"], 60)
        add("live bridge arm", [sys.executable, "-m", "cerberus_re_skill", "bridge", "arm", "codex_true_smoke", "true"], 120)
        add("live bridge health", [sys.executable, "-m", "cerberus_re_skill", "bridge", "health", "--project", "codex_true_smoke", "--program", "true"], 60)
        add(
            "live bridge function search",
            [
                sys.executable,
                "-m",
                "cerberus_re_skill",
                "bridge",
                "call",
                "/functions/search",
                '{"project":"codex_true_smoke","program":"true","query":"entry","limit":3}',
            ],
            60,
        )
        add(
            "live bridge close",
            [
                sys.executable,
                "-m",
                "cerberus_re_skill",
                "bridge",
                "close",
                "--project",
                "codex_true_smoke",
                "--program",
                "true",
                "--terminate-timeout",
                "5",
            ],
            60,
        )
        add("live bridge audit after", [sys.executable, "-m", "cerberus_re_skill", "bridge", "audit"], 60)

    if lldb_smoke:
        fixture = report_dir / "CodexObjCProbe"
        add(
            "LLDB fixture compile",
            ["clang", "-fobjc-arc", "-framework", "Foundation", "tests/fixtures/CodexObjCProbe.m", "-o", str(fixture)],
            120,
        )
        add("LLDB fixture import", [sys.executable, "-m", "cerberus_re_skill", "import", "analyze", str(fixture), "codex_objc_probe_validation"], 600)
        add(
            "LLDB static symbol export",
            [
                str(cfg.skill_root / "scripts" / "ghidra_lldb_symbols"),
                str(fixture),
                "codex_objc_probe_validation",
                "CodexObjCProbe",
            ],
            180,
        )

    if frida_smoke:
        target = str(frida_target or report_dir / "CodexObjCProbe")
        if not frida_target:
            add(
                "Frida fixture compile",
                ["clang", "-fobjc-arc", "-framework", "Foundation", "tests/fixtures/CodexObjCProbe.m", "-o", target],
                120,
            )
        add("Frida diagnostics", [sys.executable, "-m", "cerberus_re_skill", "doctor", "--frida-target", target], 120)
        trace_js = report_dir / "frida_trace.js"
        heap_js = report_dir / "frida_heap.js"
        add(
            "Frida trace script dry run",
            [
                str(cfg.skill_root / "scripts" / "ghidra_frida_trace"),
                "codex_objc_probe_validation",
                "CodexObjCProbe",
                "symbols=-[CodexProbe greet:]",
                f"script_output={trace_js}",
                "dry_run=true",
            ],
            120,
        )
        add(
            "Frida heap script dry run",
            [
                str(cfg.skill_root / "scripts" / "ghidra_frida_heap_scan"),
                "CodexProbe",
                f"script_output={heap_js}",
                "dry_run=true",
            ],
            120,
        )
        add("Frida trace JavaScript syntax", ["node", "--check", str(trace_js)], 60)
        add("Frida heap JavaScript syntax", ["node", "--check", str(heap_js)], 60)

    ok = _validation_ok(steps)
    next_work_items = _extract_next_work_items(steps)
    report = {
        "schema": "ghidra-re.validation.local.v1",
        "ok": ok,
        "created_at": utc_now(),
        "skill_root": str(cfg.skill_root),
        "report_dir": str(report_dir),
        "gates": {
            "headless_smoke": headless_smoke,
            "live_bridge_smoke": live_bridge_smoke,
            "lldb_smoke": lldb_smoke,
            "frida_smoke": frida_smoke,
        },
        "step_count": len(steps),
        "failed_step_count": len([step for step in steps if not step["ok"] and not _recovered_by_fallback(step, steps)]),
        "steps": steps,
        "next_work_items": next_work_items,
    }
    json_path = report_dir / "validation.json"
    markdown_path = report_dir / "validation.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def _run_step(
    label: str,
    command: Sequence[str],
    report_dir: Path,
    runner: CommandRunner,
    timeout_seconds: float,
) -> dict:
    started = time.monotonic()
    started_at = utc_now()
    try:
        result = runner(command, cfg.skill_root, timeout_seconds)
    except Exception as exc:
        result = ValidationProcessResult(127, "", str(exc))
    duration = time.monotonic() - started
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    artifact_name = _step_artifact_name(len(list(report_dir.glob("step-*.json"))) + 1, label)
    artifact_path = report_dir / artifact_name
    step = {
        "label": label,
        "command": [str(part) for part in command],
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "duration_seconds": round(duration, 3),
        "started_at": started_at,
        "stdout_tail": _tail(stdout),
        "stderr_tail": _tail(stderr),
        "artifact": str(artifact_path),
    }
    artifact_path.write_text(
        json.dumps({**step, "stdout": stdout, "stderr": stderr}, indent=2) + "\n",
        encoding="utf-8",
    )
    return step


def _run_command(command: Sequence[str], cwd: Path, timeout_seconds: float) -> ValidationProcessResult:
    try:
        env = os.environ.copy()
        env.setdefault("GIT_OPTIONAL_LOCKS", "0")
        env.setdefault("GIT_PAGER", "cat")
        proc = subprocess.Popen(
            [str(part) for part in command],
            shell=False,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            _terminate_process_group(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            return ValidationProcessResult(124, _decode(stdout), _decode(stderr) or "timed out")
    except subprocess.TimeoutExpired as exc:
        return ValidationProcessResult(124, _decode(exc.stdout), _decode(exc.stderr) or "timed out")
    except OSError as exc:
        return ValidationProcessResult(127, "", str(exc))
    return ValidationProcessResult(proc.returncode, _decode(stdout), _decode(stderr))


def _git_diff_check_command(resolve_changed_files: bool) -> list[str]:
    command = ["git", "-c", "core.fsmonitor=false", "diff", "--check", "--no-ext-diff"]
    override = os.environ.get("GHIDRA_RE_DIFF_CHECK_PATHS", "")
    if override.strip():
        return [*command, "--", *shlex.split(override)]
    if not resolve_changed_files:
        return command
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "diff", "--name-only", "--no-ext-diff"],
            cwd=str(cfg.skill_root),
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _git_diff_check_fallback(command)
    if result.returncode != 0:
        return _git_diff_check_fallback(command)
    changed = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return [*command, "--", *changed] if changed else _git_diff_check_fallback(command)


def _git_diff_check_fallback(command: list[str]) -> list[str]:
    return [
        *command,
        "--",
        "README.md",
        "SKILL.md",
        "cerberus_re_skill",
        "scripts",
        "tests",
        "references",
    ]


def _terminate_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except Exception:
        return


def _should_try_direct_headless_fallback(step: dict) -> bool:
    if step.get("ok"):
        return False
    combined = f"{step.get('stdout_tail', '')}\n{step.get('stderr_tail', '')}".lower()
    if step.get("returncode") == 124:
        return True
    return "launchsupport" in combined or "jdk_home" in combined


def _validation_ok(steps: list[dict]) -> bool:
    return all(step.get("ok") or _recovered_by_fallback(step, steps) for step in steps)


def _recovered_by_fallback(step: dict, steps: list[dict]) -> bool:
    label = step.get("label")
    if not label:
        return False
    return any(
        fallback.get("ok") and fallback.get("fallback_for") == label
        for fallback in steps
    )


def _run_direct_headless_export_step(*, report_dir: Path, timeout_seconds: float) -> dict:
    from cerberus_re_skill.modules.direct_headless import direct_export_apple_bundle

    started = time.monotonic()
    started_at = utc_now()
    result = direct_export_apple_bundle(
        "codex_true_smoke",
        "true",
        report_dir / "codex_true_export_direct",
        timeout_seconds=timeout_seconds,
    )
    duration = time.monotonic() - started
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    artifact_path = report_dir / _step_artifact_name(
        len(list(report_dir.glob("step-*.json"))) + 1,
        "direct headless Apple bundle export fallback",
    )
    step = {
        "label": "direct headless Apple bundle export fallback",
        "command": [str(part) for part in result.get("command", [])],
        "ok": bool(result.get("ok")),
        "returncode": int(result.get("returncode", 127)),
        "duration_seconds": round(duration, 3),
        "started_at": started_at,
        "stdout_tail": _tail(stdout),
        "stderr_tail": _tail(stderr),
        "artifact": str(artifact_path),
        "fallback_for": "headless Apple bundle export",
        "output": result.get("output"),
        "log": result.get("log"),
        "script_log": result.get("script_log"),
    }
    artifact_path.write_text(
        json.dumps({**step, "stdout": stdout, "stderr": stderr}, indent=2) + "\n",
        encoding="utf-8",
    )
    return step


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="replace")


def _tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def _step_artifact_name(index: int, label: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in label).strip("-")
    while "--" in safe:
        safe = safe.replace("--", "-")
    return f"step-{index:02d}-{safe or 'step'}.json"


def _extract_next_work_items(steps: list[dict]) -> list[str]:
    items: list[str] = []
    for step in steps:
        combined = f"{step.get('stdout_tail', '')}\n{step.get('stderr_tail', '')}"
        if not step.get("ok") and not _recovered_by_fallback(step, steps):
            items.append(f"Fix validation failure: {step.get('label')}")
        if "WARN" in combined or '"level": "WARN"' in combined:
            items.append(f"Review warning output from validation step: {step.get('label')}")
        lowered = combined.lower()
        workaround_active = "amfi workaround active" in lowered or '"runtime_attach_blocked": false' in lowered
        if ("frida-helper" in lowered or "amfi_get_out_of_my_way" in lowered) and not workaround_active:
            items.append("Recheck Frida helper/AMFI runtime attach policy")
        if "stale_session_files" in combined and '"stale_session_files": []' not in combined:
            items.append("Investigate stale bridge session files from validation audit")
    unique: list[str] = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return unique


def _render_markdown(report: dict) -> str:
    status = "PASS" if report["ok"] else "FAIL"
    lines = [
        f"# Ghidra RE Local Validation - {status}",
        "",
        f"- Created: `{report['created_at']}`",
        f"- Skill root: `{report['skill_root']}`",
        f"- Report dir: `{report['report_dir']}`",
        f"- Steps: `{report['step_count']}` total, `{report['failed_step_count']}` failed",
        "",
        "## Gates",
        "",
    ]
    for name, enabled in report["gates"].items():
        lines.append(f"- `{name}`: `{enabled}`")
    lines.extend(["", "## Steps", "", "| # | Status | Label | Duration |", "|---|--------|-------|----------|"])
    for index, step in enumerate(report["steps"], 1):
        if step["ok"]:
            step_status = "PASS"
        elif _recovered_by_fallback(step, report["steps"]):
            step_status = f"RECOVERED ({step['returncode']})"
        else:
            step_status = f"FAIL ({step['returncode']})"
        lines.append(f"| {index} | {step_status} | `{step['label']}` | `{step['duration_seconds']}s` |")
    lines.extend(["", "## Next Work Items", ""])
    if report["next_work_items"]:
        for item in report["next_work_items"]:
            lines.append(f"- {item}")
    else:
        lines.append("- No blockers or warnings detected.")
    lines.append("")
    return "\n".join(lines)
