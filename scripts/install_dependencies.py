#!/usr/bin/env python3
"""Plan or install Cerberus RE dependencies for a fresh checkout.

The script is intentionally conservative: it prints a plan by default and only
executes commands when --execute is supplied.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Step:
    id: str
    description: str
    command: list[str]
    status: str
    reason: str
    execute_ok: bool = True
    returncode: int | None = None


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _which(name: str) -> str | None:
    return shutil.which(name)


def _first_tool(names: list[str]) -> tuple[str, str] | None:
    for name in names:
        path = _which(name)
        if path:
            return name, path
    return None


def _detect_ghidra() -> bool:
    try:
        from cerberus_re_skill.core.ghidra_locator import detect_ghidra_dir
    except Exception:
        return _which("ghidra") is not None
    return detect_ghidra_dir() is not None


def _detect_jdk21() -> bool:
    try:
        from cerberus_re_skill.core.ghidra_locator import detect_jdk_dir
    except Exception:
        return _which("java") is not None
    return detect_jdk_dir() is not None


def _add_step(
    steps: list[Step],
    step_id: str,
    description: str,
    command: list[str],
    status: str,
    reason: str,
    execute_ok: bool = True,
) -> None:
    steps.append(
        Step(
            id=step_id,
            description=description,
            command=command,
            status=status,
            reason=reason,
            execute_ok=execute_ok,
        )
    )


def _add_linux_system_steps(steps: list[Step], include_node: bool) -> None:
    manager = _first_tool(["apt-get", "dnf", "pacman", "zypper"])
    package_sets = {
        "apt-get": ["openjdk-21-jdk", "lldb", "nodejs", "npm"],
        "dnf": ["java-21-openjdk-devel", "lldb", "nodejs", "npm"],
        "pacman": ["jdk21-openjdk", "lldb", "nodejs", "npm"],
        "zypper": ["java-21-openjdk-devel", "lldb", "nodejs", "npm"],
    }
    command_prefixes = {
        "apt-get": ["sudo", "apt-get", "install", "-y"],
        "dnf": ["sudo", "dnf", "install", "-y"],
        "pacman": ["sudo", "pacman", "-S", "--needed"],
        "zypper": ["sudo", "zypper", "install", "-y"],
    }
    if manager:
        name, _path = manager
        packages = package_sets[name]
        if not include_node:
            packages = [pkg for pkg in packages if pkg not in {"nodejs", "npm"}]
        _add_step(
            steps,
            f"linux_{name.replace('-', '_')}_dependencies",
            "Install Java 21, LLDB, and optional Node.js with the detected Linux package manager.",
            command_prefixes[name] + packages,
            "manual",
            "Linux package-manager commands require review for the target distribution.",
            execute_ok=False,
        )
    else:
        _add_step(
            steps,
            "linux_package_manager_required",
            "Install Java 21, LLDB, and optional Node.js with the distribution package manager.",
            [],
            "manual",
            "No supported Linux package manager was found on PATH.",
            execute_ok=False,
        )
    _add_step(
        steps,
        "linux_ghidra_manual",
        "Install Ghidra 12.x from the official release archive or a trusted distribution package.",
        [],
        "manual",
        "Ghidra package availability varies across Linux distributions.",
        execute_ok=False,
    )


def _add_windows_system_steps(steps: list[Step], include_node: bool) -> None:
    manager = _first_tool(["winget", "choco"])
    if manager:
        name, _path = manager
        if name == "winget":
            packages = ["Ghidra.Ghidra", "Microsoft.OpenJDK.21", "LLVM.LLVM"]
            if include_node:
                packages.append("OpenJS.NodeJS")
            command = ["winget", "install", *packages]
        else:
            packages = ["ghidra", "openjdk", "llvm"]
            if include_node:
                packages.append("nodejs")
            command = ["choco", "install", *packages, "-y"]
        _add_step(
            steps,
            f"windows_{name}_dependencies",
            "Install Ghidra, Java 21, LLDB/LLVM tooling, and optional Node.js with the detected Windows package manager.",
            command,
            "manual",
            "Windows package-manager commands require an elevated shell and operator review.",
            execute_ok=False,
        )
    else:
        _add_step(
            steps,
            "windows_package_manager_required",
            "Install Ghidra, Java 21, LLDB/LLVM tooling, and optional Node.js with winget, Chocolatey, or manual installers.",
            [],
            "manual",
            "No supported Windows package manager was found on PATH.",
            execute_ok=False,
        )


def build_plan(args: argparse.Namespace) -> list[Step]:
    steps: list[Step] = []
    system = platform.system().lower()
    venv = Path(args.venv).expanduser()
    venv_python = _venv_python(venv)

    if not args.skip_system:
        if system == "darwin":
            brew = _which("brew")
            if brew:
                if not _detect_ghidra():
                    _add_step(
                        steps,
                        "macos_brew_ghidra",
                        "Install Ghidra and its Homebrew-managed Java dependency.",
                        [brew, "install", "ghidra"],
                        "pending",
                        "No Ghidra installation was detected.",
                    )
                else:
                    _add_step(
                        steps,
                        "macos_brew_ghidra",
                        "Ghidra is already detectable.",
                        [brew, "install", "ghidra"],
                        "satisfied",
                        "Detected Ghidra via existing configuration or PATH.",
                    )
                if args.include_node:
                    if _which("node"):
                        node_status = "satisfied"
                        node_reason = "node is already on PATH."
                    else:
                        node_status = "pending"
                        node_reason = "Node is useful for JavaScript syntax checks in validation."
                    _add_step(
                        steps,
                        "macos_brew_node",
                        "Install Node.js for optional generated JavaScript validation.",
                        [brew, "install", "node"],
                        node_status,
                        node_reason,
                    )
            else:
                _add_step(
                    steps,
                    "macos_homebrew_required",
                    "Install Homebrew or install Ghidra/Java/Node manually.",
                    [],
                    "manual",
                    "Homebrew was not found on PATH.",
                    execute_ok=False,
                )

            if _which("lldb"):
                lldb_status = "satisfied"
                lldb_reason = "lldb is already on PATH."
            else:
                lldb_status = "manual"
                lldb_reason = "LLDB is provided by Xcode or Xcode Command Line Tools."
            _add_step(
                steps,
                "macos_xcode_lldb",
                "Install Xcode Command Line Tools if LLDB is missing.",
                ["xcode-select", "--install"],
                lldb_status,
                lldb_reason,
                execute_ok=False,
            )
        elif system == "windows":
            _add_windows_system_steps(steps, args.include_node)
        else:
            _add_linux_system_steps(steps, args.include_node)

    if not venv_python.exists():
        _add_step(
            steps,
            "python_create_venv",
            f"Create Python virtual environment at {venv}.",
            [sys.executable, "-m", "venv", str(venv)],
            "pending",
            "The requested virtual environment does not exist.",
        )
    else:
        _add_step(
            steps,
            "python_create_venv",
            f"Virtual environment already exists at {venv}.",
            [sys.executable, "-m", "venv", str(venv)],
            "satisfied",
            "The requested virtual environment already has a Python executable.",
        )

    _add_step(
        steps,
        "python_upgrade_pip",
        "Upgrade pip in the Cerberus RE virtual environment.",
        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
        "pending",
        "Keeps editable install behavior predictable across fresh hosts.",
    )
    _add_step(
        steps,
        "python_install_project",
        "Install Cerberus RE into the virtual environment.",
        [str(venv_python), "-m", "pip", "install", "-e", "."],
        "pending",
        "Installs the cerberus-re console entry point.",
    )
    if args.include_frida:
        _add_step(
            steps,
            "python_install_frida",
            "Install Frida Python bindings and command-line tools into the virtual environment.",
            [str(venv_python), "-m", "pip", "install", "--upgrade", "frida", "frida-tools"],
            "pending",
            "Frida workflows need both the Python package and CLI tools.",
        )
    if not _detect_jdk21():
        _add_step(
            steps,
            "post_install_jdk_check",
            "Run cerberus-re doctor after system installs.",
            [str(venv_python), "-m", "cerberus_re_skill", "doctor"],
            "pending",
            "No Java 21 installation was detected before setup.",
            execute_ok=False,
        )
    return steps


def execute_plan(steps: list[Step], quiet: bool = False) -> int:
    exit_code = 0
    for step in steps:
        if step.status == "satisfied" or not step.command or not step.execute_ok:
            continue
        result = subprocess.run(
            step.command,
            cwd=ROOT,
            shell=False,
            text=True,
            capture_output=quiet,
        )
        step.returncode = result.returncode
        if result.returncode == 0:
            step.status = "completed"
        else:
            if quiet:
                if result.stdout:
                    print(result.stdout, file=sys.stderr, end="")
                if result.stderr:
                    print(result.stderr, file=sys.stderr, end="")
            step.status = "failed"
            exit_code = result.returncode or 1
            break
    return exit_code


def _activation_command(venv: Path) -> str:
    if os.name == "nt":
        return f"{venv}\\Scripts\\Activate.ps1"
    return f"source {venv}/bin/activate"


def print_plan(steps: list[Step], as_json: bool, execute: bool, venv: Path) -> None:
    payload = {
        "ok": all(step.status not in {"failed"} for step in steps),
        "execute": execute,
        "repo": str(ROOT),
        "steps": [asdict(step) for step in steps],
        "next_commands": [
            _activation_command(venv),
            "cerberus-re bootstrap",
            "cerberus-re doctor",
        ],
    }
    if as_json:
        print(json.dumps(payload, indent=2))
        return

    mode = "execute" if execute else "dry-run"
    print(f"Cerberus RE dependency setup ({mode})")
    print(f"Repo: {ROOT}")
    for step in steps:
        command = " ".join(step.command) if step.command else "(manual)"
        print(f"- [{step.status}] {step.id}: {step.description}")
        print(f"  reason: {step.reason}")
        print(f"  command: {command}")
    print("\nAfter successful setup:")
    for command in payload["next_commands"]:
        print(f"  {command}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Run pending executable steps.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable setup plan.")
    parser.add_argument("--venv", default=".venv", help="Virtual environment path to create/use.")
    parser.add_argument("--skip-system", action="store_true", help="Skip system package-manager steps.")
    parser.add_argument("--no-frida", dest="include_frida", action="store_false", help="Do not install Frida Python packages.")
    parser.add_argument("--no-node", dest="include_node", action="store_false", help="Do not plan Node.js installation.")
    parser.set_defaults(include_frida=True, include_node=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    steps = build_plan(args)
    exit_code = execute_plan(steps, quiet=args.json) if args.execute else 0
    print_plan(steps, args.json, args.execute, Path(args.venv).expanduser())
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
