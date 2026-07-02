"""subprocess.run wrappers (shell=False) and tool detection via shutil.which."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence


def find_tool(name: str) -> str | None:
    """Return the full path of *name* via shutil.which, or None if not found."""
    return shutil.which(name)


def require_tool(name: str) -> str:
    """Return the full path of *name* or raise RuntimeError."""
    path = find_tool(name)
    if not path:
        raise RuntimeError(f"required tool not found on PATH: {name}")
    return path


def run(
    cmd: Sequence[str | Path],
    *,
    check: bool = True,
    capture_output: bool = False,
    env: dict[str, str] | None = None,
    cwd: Path | str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    """Run a command with shell=False.

    Merges *env* on top of the current environment when provided.
    """
    full_env = None
    if env is not None:
        full_env = {**os.environ, **env}
    return subprocess.run(
        [str(c) for c in cmd],
        shell=False,
        check=check,
        capture_output=capture_output,
        env=full_env,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
    )


def run_output(
    cmd: Sequence[str | Path],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | str | None = None,
    timeout: float | None = None,
) -> str:
    """Run a command and return its stdout as a stripped string."""
    result = run(
        cmd,
        check=True,
        capture_output=True,
        env=env,
        cwd=cwd,
        timeout=timeout,
    )
    return result.stdout.decode(errors="replace").strip()


def find_python() -> str:
    """Return the path to the Python interpreter (python3 or python)."""
    for candidate in ("python3", "python"):
        found = find_tool(candidate)
        if found:
            return found
    return sys.executable


def check_pid_alive(pid: int) -> bool:
    """Return True if a process with *pid* is alive.

    On Windows, opens the process with PROCESS_QUERY_LIMITED_INFORMATION,
    then calls GetExitCodeProcess to confirm the process is still running
    (exit code == STILL_ACTIVE / 259).  The handle is always closed.

    On POSIX, sends signal 0 to test for process existence.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == STILL_ACTIVE
        except Exception:
            return False
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def is_ghidra_running() -> bool:
    """Return True if a Ghidra JVM process appears to be running."""
    if sys.platform == "win32":
        try:
            result = run(
                ["tasklist", "/FI", "IMAGENAME eq java.exe", "/FO", "CSV"],
                check=False,
                capture_output=True,
            )
            output = result.stdout.decode(errors="replace")
            return "java" in output.lower()
        except Exception:
            return False
    else:
        try:
            result = run(
                ["pgrep", "-f", "java.*ghidra.GhidraRun"],
                check=False,
                capture_output=True,
            )
            return result.returncode == 0
        except Exception:
            return False
