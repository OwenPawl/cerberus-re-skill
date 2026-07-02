"""Frida environment diagnostics for macOS live-attach validation."""

from __future__ import annotations

import platform
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from cerberus_re_skill.core.ghidra_locator import macos_amfi_get_out_of_my_way_enabled
from cerberus_re_skill.core.subprocess_utils import find_python, find_tool


ToolFinder = Callable[[str], str | None]
ProbeRunner = Callable[[Sequence[str]], "ProbeResult"]
DEFAULT_FRIDA_VENV = Path("/opt/cerberus-re/frida-venv")
SUDOERS_FILE = Path("/etc/sudoers.d/cerberus-re-frida")


@dataclass(frozen=True)
class FridaDiagnostic:
    level: str
    label: str
    value: str = ""


@dataclass(frozen=True)
class ProbeResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def collect_frida_diagnostics(
    frida_target: str | Path | None = None,
    *,
    tool_finder: ToolFinder = find_tool,
    runner: ProbeRunner | None = None,
    known_tool_finder: ToolFinder | None = None,
    platform_name: str | None = None,
    machine: str | None = None,
    amfi_enabled: Callable[[], bool] = macos_amfi_get_out_of_my_way_enabled,
) -> list[FridaDiagnostic]:
    """Return actionable diagnostics for local Frida attach readiness.

    The checks are intentionally non-invasive: no target attach is attempted.
    """
    run_probe = runner or _run_probe
    find_known_tool = known_tool_finder or known_frida_tool
    system = platform_name or sys.platform
    arch = machine or platform.machine()
    entries: list[FridaDiagnostic] = []

    frida_cli_from_path = tool_finder("frida")
    frida_cli = frida_cli_from_path or find_known_tool("frida")
    if frida_cli:
        version = run_probe([frida_cli, "--version"])
        if version.returncode == 0:
            source = "" if frida_cli_from_path else "; known venv, not on PATH"
            entries.append(FridaDiagnostic("OK", "Frida CLI", f"{frida_cli} ({_first_line(version.stdout)}{source})"))
        else:
            entries.append(FridaDiagnostic("WARN", "Frida CLI", f"{frida_cli} failed: {_probe_failure(version)}"))
    else:
        entries.append(FridaDiagnostic("WARN", "Frida CLI", "not found on PATH"))

    python_cmd = _sibling_tool(frida_cli, "python3") or _sibling_tool(frida_cli, "python")
    python_cmd = python_cmd or tool_finder("python3") or tool_finder("python") or find_python()
    module = run_probe([python_cmd, "-c", "import frida; print(getattr(frida, '__version__', 'unknown'))"])
    if module.returncode == 0:
        entries.append(FridaDiagnostic("OK", "Frida Python module", _first_line(module.stdout) or "importable"))
    else:
        entries.append(FridaDiagnostic("WARN", "Frida Python module", _probe_failure(module)))

    frida_ps = tool_finder("frida-ps") or _sibling_tool(frida_cli, "frida-ps") or find_known_tool("frida-ps")
    if frida_ps:
        ps_command = frida_cli_command("frida-ps", frida_ps)
        ps_probe = run_probe(ps_command)
        if ps_probe.returncode == 0:
            summary = _first_line(ps_probe.stdout) or "local process list accessible"
            entries.append(FridaDiagnostic("OK", "frida-ps local probe", summary))
        else:
            entries.append(FridaDiagnostic("WARN", "frida-ps local probe", _probe_failure(ps_probe)))
    else:
        entries.append(FridaDiagnostic("WARN", "frida-ps local probe", "frida-ps not found on PATH"))

    if system == "darwin":
        entries.extend(_macos_policy_diagnostics(tool_finder, run_probe, arch, amfi_enabled))
        entries.append(_target_signing_diagnostic(frida_target, tool_finder, run_probe))
    elif frida_target:
        entries.append(FridaDiagnostic("INFO", "Frida target signing", "codesign checks are macOS-only"))
    else:
        entries.append(FridaDiagnostic("INFO", "Frida target signing", "not checked; pass --frida-target on macOS"))

    return entries


def _macos_policy_diagnostics(
    tool_finder: ToolFinder,
    run_probe: ProbeRunner,
    arch: str,
    amfi_enabled: Callable[[], bool],
) -> list[FridaDiagnostic]:
    entries: list[FridaDiagnostic] = []
    devtools = tool_finder("DevToolsSecurity")
    if devtools:
        status = run_probe([devtools, "-status"])
        text = f"{status.stdout}\n{status.stderr}".lower()
        if status.returncode == 0 and "enabled" in text and "disabled" not in text:
            entries.append(FridaDiagnostic("OK", "DevToolsSecurity", "developer mode enabled"))
        elif status.returncode == 0 and "disabled" in text:
            entries.append(
                FridaDiagnostic(
                    "WARN",
                    "DevToolsSecurity",
                    "developer mode disabled; run `sudo DevToolsSecurity -enable` before live attach",
                )
            )
        else:
            entries.append(FridaDiagnostic("WARN", "DevToolsSecurity", _probe_failure(status)))
    else:
        entries.append(FridaDiagnostic("WARN", "DevToolsSecurity", "tool not found"))

    if amfi_enabled():
        entries.append(_amfi_workaround_diagnostic(run_probe))
    elif arch == "arm64":
        entries.append(
            FridaDiagnostic(
                "INFO",
                "Frida helper policy",
                "native arm64 Frida is preferred; use Rosetta/x86_64 only as a diagnostic fallback",
            )
        )
    else:
        entries.append(FridaDiagnostic("INFO", "Frida helper policy", f"host architecture: {arch or 'unknown'}"))

    return entries


def _amfi_workaround_diagnostic(run_probe: ProbeRunner) -> FridaDiagnostic:
    frida_ps = _default_frida_venv() / "bin" / "frida-ps"
    missing = []
    if not frida_ps.exists():
        missing.append(str(frida_ps))
    if not SUDOERS_FILE.exists():
        missing.append(str(SUDOERS_FILE))
    if missing:
        return FridaDiagnostic(
            "WARN",
            "Frida helper policy",
            "amfi_get_out_of_my_way=1 is set; AMFI workaround incomplete; missing: " + ", ".join(missing),
        )

    probe = run_probe(["sudo", "-n", str(frida_ps)])
    if probe.returncode == 0:
        return FridaDiagnostic(
            "OK",
            "Frida helper policy",
            f"AMFI workaround active: sudo -n {frida_ps} works with {SUDOERS_FILE}",
        )
    return FridaDiagnostic(
        "WARN",
        "Frida helper policy",
        f"amfi_get_out_of_my_way=1 is set; AMFI workaround incomplete: sudo -n {frida_ps} failed: {_probe_failure(probe)}",
    )


def _target_signing_diagnostic(
    frida_target: str | Path | None,
    tool_finder: ToolFinder,
    run_probe: ProbeRunner,
) -> FridaDiagnostic:
    if not frida_target:
        return FridaDiagnostic("INFO", "Frida target signing", "not checked; pass --frida-target /path/to/binary")

    target = Path(frida_target)
    if not target.exists():
        return FridaDiagnostic("WARN", "Frida target signing", f"target not found: {target}")

    codesign = tool_finder("codesign")
    if not codesign:
        return FridaDiagnostic("WARN", "Frida target signing", "codesign tool not found")

    signed = run_probe([codesign, "-dv", str(target)])
    if signed.returncode != 0:
        return FridaDiagnostic(
            "WARN",
            "Frida target signing",
            f"{target} is unsigned or unreadable; sign test fixtures with get-task-allow before spawn/attach",
        )
    signed_text = f"{signed.stdout}\n{signed.stderr}"

    entitlements = run_probe([codesign, "-d", "--entitlements", ":-", str(target)])
    ent_text = f"{entitlements.stdout}\n{entitlements.stderr}"
    if entitlements.returncode == 0 and "com.apple.security.get-task-allow" in ent_text and "<true/>" in ent_text:
        return FridaDiagnostic("OK", "Frida target signing", f"{target} has get-task-allow entitlement")

    if "adhoc" in signed_text.lower() and "runtime" not in signed_text.lower():
        return FridaDiagnostic(
            "OK",
            "Frida target signing",
            f"{target} is ad-hoc signed without hardened runtime",
        )

    return FridaDiagnostic(
        "WARN",
        "Frida target signing",
        f"{target} is signed but get-task-allow was not found; hardened targets may reject attach",
    )


def _run_probe(cmd: Sequence[str]) -> ProbeResult:
    try:
        result = subprocess.run(
            [str(part) for part in cmd],
            shell=False,
            check=False,
            capture_output=True,
            timeout=8,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _decode(exc.stdout)
        stderr = _decode(exc.stderr)
        return ProbeResult(124, stdout, stderr or "timed out")
    except OSError as exc:
        return ProbeResult(127, "", str(exc))
    return ProbeResult(
        result.returncode,
        _decode(result.stdout),
        _decode(result.stderr),
    )


def _sibling_tool(primary: str | None, name: str) -> str | None:
    if not primary:
        return None
    candidate = Path(primary).with_name(name)
    return str(candidate) if candidate.exists() else None


def known_frida_tool(name: str) -> str | None:
    roots: list[Path] = []
    if os.environ.get("GHIDRA_RE_FRIDA_BIN"):
        roots.append(Path(os.environ["GHIDRA_RE_FRIDA_BIN"]))
    if os.environ.get("GHIDRA_RE_FRIDA_VENV"):
        roots.append(Path(os.environ["GHIDRA_RE_FRIDA_VENV"]) / "bin")
    roots.extend(
        [
            DEFAULT_FRIDA_VENV / "bin",
            Path("/tmp/cerberus-re-frida-venv/bin"),
            Path("/tmp/cerberus-re-frida-x86-venv/bin"),
        ]
    )
    for root in roots:
        candidate = root / name
        if candidate.exists():
            return str(candidate)
    return None


def frida_cli_command(name: str, tool: str | None = None) -> list[str]:
    resolved = tool or known_frida_tool(name)
    if not resolved:
        return []
    if _should_sudo_frida_tool(Path(resolved)):
        return ["sudo", "-n", resolved]
    return [resolved]


def _should_sudo_frida_tool(tool: Path) -> bool:
    setting = os.environ.get("GHIDRA_RE_FRIDA_SUDO", "auto").lower()
    if setting in {"0", "false", "no", "off"}:
        return False
    if setting in {"1", "true", "yes", "on"}:
        return True
    if not macos_amfi_get_out_of_my_way_enabled():
        return False
    venv = _default_frida_venv()
    try:
        tool.resolve().relative_to(venv.resolve())
        return True
    except ValueError:
        return False


def _default_frida_venv() -> Path:
    return Path(os.environ.get("GHIDRA_RE_FRIDA_VENV", str(DEFAULT_FRIDA_VENV)))


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _probe_failure(result: ProbeResult, limit: int = 260) -> str:
    text = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
    text = " ".join(text.split())
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return text


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="replace")
