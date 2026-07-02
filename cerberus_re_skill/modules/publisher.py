"""Share-package builders: cross-platform, macOS-desktop, Windows-desktop."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.ghidra_locator import detect_ghidra_dir, detect_ghidra_version
from cerberus_re_skill.core.utils import timestamp


def _get_ghidra_version() -> str:
    d = detect_ghidra_dir()
    if d:
        return detect_ghidra_version(d) or "unknown"
    return "unknown"


_EXCLUDE_NAMES = {
    ".git",
    ".DS_Store",
    "__MACOSX",
    ".gradle",
    "build",
    "cerberus_re.egg-info",
    "development",
    "cerberus_re_skill.egg-info",
}
_EXCLUDE_SUFFIXES = {".pyc"}


def _ignore_func(directory: str, contents: list[str]) -> set[str]:
    """shutil.copytree ignore callback: skip build artefacts and VCS dirs."""
    ignored: set[str] = set()
    for name in contents:
        if name in _EXCLUDE_NAMES:
            ignored.add(name)
            continue
        path = Path(directory) / name
        if path.is_file() and path.suffix in _EXCLUDE_SUFFIXES:
            ignored.add(name)
    return ignored


def _copy_tree(src: Path, dst: Path) -> None:
    """Copy *src* to *dst* using shutil.copytree, skipping build artefacts."""
    shutil.copytree(
        src,
        dst,
        ignore=_ignore_func,
        dirs_exist_ok=True,
    )


def _zip_dir(source_dir: Path, output_zip: Path) -> None:
    """Zip *source_dir* into *output_zip* (the top-level dir in the archive is source_dir.name)."""
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file in source_dir.rglob("*"):
            zf.write(file, file.relative_to(source_dir.parent))


# ---------------------------------------------------------------------------
# Generic share package
# ---------------------------------------------------------------------------

def build_share_package(output_path: Optional[Path] = None) -> Path:
    """Build a cross-platform share zip.

    Returns the path to the built zip file.
    """
    if output_path is None:
        ts = timestamp()
        output_path = Path.cwd() / f"cerberus-re-skill-share-{ts}.zip"

    with tempfile.TemporaryDirectory(prefix="cerberus-re-share-") as tmp:
        tmp_root = Path(tmp)
        package_root = tmp_root / "cerberus-re-share"
        skill_dst = package_root / "cerberus-re"

        _copy_tree(cfg.skill_root, skill_dst)

        # Cross-platform Python install script
        installer = package_root / "install-cerberus-re.py"
        installer.write_text(
            _GENERIC_INSTALLER_PY,
            encoding="utf-8",
        )

        readme = package_root / "README.txt"
        readme.write_text(_GENERIC_README, encoding="utf-8")

        _zip_dir(package_root, output_path)

    return output_path


# ---------------------------------------------------------------------------
# macOS desktop share package
# ---------------------------------------------------------------------------

def build_mac_desktop_share_package(
    output_path: Optional[Path] = None,
    include_ghidra_payload: bool = True,
) -> Path:
    """Build a macOS-friendly desktop share zip."""
    if output_path is None:
        ts = timestamp()
        output_path = Path.cwd() / f"cerberus-re-mac-desktop-share-{ts}.zip"

    ghidra_version = _get_ghidra_version()
    embedded_ghidra = False
    embedded_launcher = False

    with tempfile.TemporaryDirectory(prefix="cerberus-re-mac-share-") as tmp:
        tmp_root = Path(tmp)
        package_root = tmp_root / "cerberus-re-mac-desktop-share"
        skill_dst = package_root / "cerberus-re"
        payload_dir = package_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        _copy_tree(cfg.skill_root, skill_dst)

        if include_ghidra_payload:
            ghidra_src = detect_ghidra_dir()
            if not ghidra_src:
                raise RuntimeError(
                    "requested embedded Ghidra payload but no local Ghidra install was detected"
                )
            tarball = payload_dir / "Ghidra.tar.gz"
            import subprocess
            subprocess.run(
                ["tar", "-C", str(ghidra_src.parent), "-czf", str(tarball), ghidra_src.name],
                shell=False,
                check=True,
            )
            embedded_ghidra = True

            app_src = Path("/Applications/Ghidra.app")
            if app_src.is_dir():
                app_tarball = payload_dir / "Ghidra.app.tar.gz"
                subprocess.run(
                    ["tar", "-C", "/Applications", "-czf", str(app_tarball), "Ghidra.app"],
                    shell=False,
                    check=True,
                )
                embedded_launcher = True

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        package_info = {
            "package_name": "cerberus-re-mac-desktop-share",
            "built_at": now_iso,
            "skill_name": "cerberus-re",
            "ghidra_version": ghidra_version,
            "embedded_ghidra_payload": embedded_ghidra,
            "embedded_ghidra_launcher": embedded_launcher,
        }
        (package_root / "package-info.json").write_text(
            json.dumps(package_info, indent=2), encoding="utf-8"
        )

        # macOS .command installer
        cmd_file = package_root / "Install Ghidra RE.command"
        cmd_file.write_text(_MAC_COMMAND_INSTALLER, encoding="utf-8")
        cmd_file.chmod(0o755)

        readme = package_root / "README.txt"
        readme.write_text(_MAC_README, encoding="utf-8")

        _zip_dir(package_root, output_path)

    return output_path


# ---------------------------------------------------------------------------
# Windows desktop share package
# ---------------------------------------------------------------------------

def build_windows_desktop_share_package(
    output_path: Optional[Path] = None,
    ghidra_zip: Optional[Path] = None,
) -> Path:
    """Build a Windows-friendly desktop share zip."""
    if output_path is None:
        ts = timestamp()
        output_path = Path.cwd() / f"cerberus-re-windows-desktop-share-{ts}.zip"

    if ghidra_zip and not ghidra_zip.exists():
        raise FileNotFoundError(f"ghidra zip not found: {ghidra_zip}")

    embedded_ghidra = ghidra_zip is not None

    with tempfile.TemporaryDirectory(prefix="cerberus-re-win-share-") as tmp:
        tmp_root = Path(tmp)
        package_root = tmp_root / "cerberus-re-windows-desktop-share"
        skill_dst = package_root / "cerberus-re"
        payload_dir = package_root / "payload"
        payload_dir.mkdir(parents=True, exist_ok=True)

        _copy_tree(cfg.skill_root, skill_dst)

        if ghidra_zip:
            shutil.copy2(ghidra_zip, payload_dir / "Ghidra.zip")

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        package_info = {
            "package_name": "cerberus-re-windows-desktop-share",
            "built_at": now_iso,
            "skill_name": "cerberus-re",
            "embedded_ghidra_payload": embedded_ghidra,
        }
        (package_root / "package-info.json").write_text(
            json.dumps(package_info, indent=2), encoding="utf-8"
        )

        # Windows .cmd launcher that calls the PowerShell installer
        cmd_launcher = package_root / "Install Ghidra RE.cmd"
        cmd_launcher.write_text(
            "@echo off\r\nsetlocal\r\n"
            'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install Ghidra RE.ps1"\r\n'
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )

        ps1_file = package_root / "Install Ghidra RE.ps1"
        ps1_file.write_text(_WINDOWS_PS1_INSTALLER, encoding="utf-8")

        readme = package_root / "README.txt"
        readme.write_text(_WINDOWS_README, encoding="utf-8")

        _zip_dir(package_root, output_path)

    return output_path


# ---------------------------------------------------------------------------
# Skill install (copy to AI host dirs)
# ---------------------------------------------------------------------------

def install_skill(
    host: str = "auto",
    source_dir: Optional[Path] = None,
    run_bootstrap: bool = True,
    skip_smoke_test: bool = False,
    skip_bridge_install: bool = False,
) -> list[Path]:
    """Install the skill into AI host directories.

    host: 'auto' | 'codex' | 'claude' | 'both' | comma-separated list
    Returns list of installed target directories.
    """
    import os

    src = source_dir or cfg.skill_root

    # Resolve host targets
    home = Path.home()

    host_map = {
        "codex": home / ".codex" / "skills" / "cerberus-re",
        "claude": home / ".claude" / "skills" / "cerberus-re",
    }

    if host in ("auto", ""):
        targets = [p for h, p in host_map.items() if p.parent.parent.exists()]
        if not targets:
            targets = [host_map["codex"]]
    elif host in ("both", "all"):
        targets = list(host_map.values())
    elif "," in host:
        parts = [h.strip() for h in host.split(",")]
        targets = [host_map[h] for h in parts if h in host_map]
    elif host in host_map:
        targets = [host_map[host]]
    else:
        raise ValueError(f"unknown host: {host!r} (expected codex | claude | both | auto)")

    installed: list[Path] = []
    backup_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    for target in targets:
        target_parent = target.parent
        target_parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            backup = target.parent / f"{target.name}.backup-{backup_ts}"
            # If the backup path already exists (e.g. two installs in the same
            # second), remove it first to avoid unintended nesting.
            if backup.exists():
                shutil.rmtree(backup)
            shutil.move(str(target), str(backup))
            print(f"install_skill: backed up existing skill to {backup}")

        target.mkdir(parents=True, exist_ok=True)
        _copy_tree(src, target)
        print(f"install_skill: installed {target}")
        installed.append(target)

        if run_bootstrap:
            _bootstrap_target(target, skip_smoke_test, skip_bridge_install)

    return installed


def _bootstrap_target(
    target: Path,
    skip_smoke_test: bool,
    skip_bridge_install: bool,
) -> None:
    """Run Cerberus RE bootstrap inside an installed target directory."""
    import subprocess

    python = sys.executable
    cmd = [python, "-m", "cerberus_re_skill", "bootstrap"]
    if skip_smoke_test:
        cmd.append("--skip-smoke-test")
    if skip_bridge_install:
        cmd.append("--skip-bridge-install")
    result = subprocess.run(cmd, shell=False, cwd=str(target))
    if result.returncode != 0:
        print(f"install_skill: bootstrap failed for {target} (run 'cerberus-re doctor')", file=sys.stderr)


# ---------------------------------------------------------------------------
# Installer script templates
# ---------------------------------------------------------------------------

_GENERIC_INSTALLER_PY = '''\
#!/usr/bin/env python3
"""Cross-platform Cerberus RE share-package installer."""
import subprocess, sys, pathlib

pkg_dir = pathlib.Path(__file__).parent / "cerberus-re"
result = subprocess.run(
    [sys.executable, "-m", "cerberus_re_skill", "install"] + sys.argv[1:],
    cwd=str(pkg_dir),
)
raise SystemExit(result.returncode)
'''

_GENERIC_README = """\
Cerberus RE share package

1. Unzip this archive.
2. Run: python install-cerberus-re.py
3. The installer copies the skill into every detected skill host and runs bootstrap.

To force a single host:
  python install-cerberus-re.py --host codex
  python install-cerberus-re.py --host claude
  python install-cerberus-re.py --host both

If bootstrap cannot auto-detect Ghidra or Java 21, run:
  python -m cerberus_re_skill doctor
"""

_MAC_COMMAND_INSTALLER = """\
#!/usr/bin/env python3
\"\"\"macOS .command installer for Cerberus RE.\"\"\"
import os, sys, subprocess, pathlib

script_dir = pathlib.Path(__file__).resolve().parent
pkg_dir = script_dir / "cerberus-re"
env = os.environ.copy()
env.setdefault("GHIDRA_RE_HOST", "auto")

result = subprocess.run(
    [sys.executable, "-m", "cerberus_re_skill", "install",
     "--host", env["GHIDRA_RE_HOST"],
     "--source", str(pkg_dir)],
    cwd=str(pkg_dir),
    env=env,
)
raise SystemExit(result.returncode)
"""

_MAC_README = """\
Cerberus RE mac desktop share package

Fast path:
1. Unzip this archive.
2. Double-click "Install Ghidra RE.command" or run it from Terminal:
   python3 "Install Ghidra RE.command"
3. The installer will copy Cerberus RE into every detected skill host and run bootstrap.

To force a single host:
  GHIDRA_RE_HOST=codex  python3 "Install Ghidra RE.command"
  GHIDRA_RE_HOST=claude python3 "Install Ghidra RE.command"
  GHIDRA_RE_HOST=both   python3 "Install Ghidra RE.command"
"""

_WINDOWS_PS1_INSTALLER = """\
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PkgDir    = Join-Path $ScriptDir "cerberus-re"
$HostChoice = if ($env:GHIDRA_RE_HOST) { $env:GHIDRA_RE_HOST } else { "auto" }

& python -m cerberus_re_skill install --host $HostChoice --source $PkgDir
exit $LASTEXITCODE
"""

_WINDOWS_README = """\
Cerberus RE Windows desktop share package

1. Unzip this archive on the Windows machine.
2. Double-click "Install Ghidra RE.cmd".
3. The installer will:
   - copy the skill into every detected skill host
   - install the GhidraRe PowerShell module
   - run bootstrap

To force a specific host, set GHIDRA_RE_HOST before launching:
  set GHIDRA_RE_HOST=codex && "Install Ghidra RE.cmd"
  set GHIDRA_RE_HOST=claude && "Install Ghidra RE.cmd"
  set GHIDRA_RE_HOST=both && "Install Ghidra RE.cmd"
"""
