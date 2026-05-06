"""Ghidra installation and JDK detection for Windows, macOS, and Linux."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ghidra_re_skill.core.platform_helpers import get_platform, is_macos, is_windows
from ghidra_re_skill.core.subprocess_utils import find_tool, run_output


# ---------------------------------------------------------------------------
# Ghidra directory validation
# ---------------------------------------------------------------------------

def analyze_headless_path(ghidra_dir: Path) -> Path | None:
    """Return the analyzeHeadless executable path within *ghidra_dir*, or None."""
    names = (
        ("support/analyzeHeadless.bat", "support/analyzeHeadless")
        if is_windows()
        else ("support/analyzeHeadless", "support/analyzeHeadless.bat")
    )
    for name in names:
        candidate = ghidra_dir / name
        if candidate.exists():
            return candidate
    return None


def ghidra_run_path(ghidra_dir: Path) -> Path | None:
    """Return the ghidraRun executable path within *ghidra_dir*, or None."""
    if is_windows():
        for name in ("ghidraRun.bat", "ghidraRun"):
            candidate = ghidra_dir / name
            if candidate.exists():
                return candidate
    else:
        for name in ("ghidraRun", "ghidraRun.bat"):
            candidate = ghidra_dir / name
            if candidate.exists():
                return candidate
    return None


def _windows_short_path(path: Path) -> Path:
    """Return the Windows 8.3 short path when available."""
    if not is_windows():
        return path
    try:
        import ctypes

        get_short_path_name = ctypes.windll.kernel32.GetShortPathNameW
        source = str(path)
        size = get_short_path_name(source, None, 0)
        if size <= 0:
            return path
        buffer = ctypes.create_unicode_buffer(size)
        if get_short_path_name(source, buffer, size) <= 0:
            return path
        short = Path(buffer.value)
        return short if short.exists() else path
    except Exception:
        return path


def gradle_wrapper_path(ghidra_dir: Path) -> Path | None:
    """Return the Gradle wrapper path bundled with Ghidra, or None."""
    names = (
        ("support/gradle/gradlew.bat", "support/gradle/gradlew")
        if is_windows()
        else ("support/gradle/gradlew", "support/gradle/gradlew.bat")
    )
    for name in names:
        candidate = ghidra_dir / name
        if candidate.exists():
            if is_windows() and " " in str(candidate):
                return _windows_short_path(candidate)
            return candidate
    return None


def is_valid_ghidra_dir(d: Path) -> bool:
    """Return True if *d* looks like a Ghidra installation directory."""
    if not d or not d.is_dir():
        return False
    return analyze_headless_path(d) is not None and ghidra_run_path(d) is not None


def resolve_ghidra_dir(d: Path) -> Path | None:
    """Resolve *d* to a valid Ghidra directory, searching one level of subdirs."""
    if not d or not d.is_dir():
        return None
    if is_valid_ghidra_dir(d):
        return d
    for sub in sorted(d.iterdir()):
        name_lower = sub.name.lower()
        if sub.is_dir() and (name_lower.startswith("ghidra_") or name_lower.startswith("ghidra")):
            if is_valid_ghidra_dir(sub):
                return sub
    return None


# ---------------------------------------------------------------------------
# JDK validation
# ---------------------------------------------------------------------------

def is_valid_jdk_dir(d: Path | str | None) -> bool:
    """Return True if *d* looks like a JDK home directory."""
    if not d:
        return False
    p = Path(d)
    if not p.is_dir():
        return False
    has_java = (p / "bin" / "java").exists() or (p / "bin" / "java.exe").exists()
    has_javac = (p / "bin" / "javac").exists() or (p / "bin" / "javac.exe").exists()
    return has_java and has_javac


def _detect_jdk_from_path() -> Path | None:
    """Try to detect a JDK by following the javac/java symlinks on PATH."""
    import shutil

    for binary in ("javac", "java"):
        cmd = shutil.which(binary)
        if not cmd:
            continue
        try:
            resolved = Path(cmd).resolve()
            candidate = resolved.parent.parent
            if is_valid_jdk_dir(candidate):
                return candidate
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Auto-detection: Ghidra
# ---------------------------------------------------------------------------

def detect_ghidra_dir() -> Path | None:
    """Detect a Ghidra installation directory on the current platform."""
    env_val = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
    if env_val:
        resolved = resolve_ghidra_dir(Path(env_val))
        if resolved:
            return resolved

    plat = get_platform()
    home = Path.home()
    candidates: list[Path] = []

    if plat == "macos":
        candidates = [
            Path("/Applications/Ghidra"),
            home / "Applications" / "Ghidra",
            Path("/Applications"),
            home / "Applications",
            home / "Downloads",
        ]
    elif plat == "windows":
        pf = Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))
        local_app_data = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
        candidates = [
            local_app_data / "Programs" / "Ghidra",
            Path("C:/Tools/Ghidra"),
            pf / "Ghidra",
            home / "Downloads",
            home / "Desktop",
        ]
    else:
        candidates = [
            Path("/opt/ghidra"),
            Path("/opt"),
            home / "Downloads",
        ]

    for candidate in candidates:
        if not candidate.exists():
            continue
        resolved = resolve_ghidra_dir(candidate)
        if resolved:
            return resolved
        # Search one level deep for versioned subdirectories
        try:
            if not candidate.is_dir():
                continue
            for sub in sorted(candidate.iterdir()):
                name_lower = sub.name.lower()
                if sub.is_dir() and (
                    name_lower.startswith("ghidra_")
                    or name_lower.startswith("ghidra")
                ):
                    resolved = resolve_ghidra_dir(sub)
                    if resolved:
                        return resolved
        except PermissionError:
            continue

    return None


# ---------------------------------------------------------------------------
# Auto-detection: JDK
# ---------------------------------------------------------------------------

def detect_jdk_dir() -> Path | None:
    """Detect a JDK home directory on the current platform."""
    # 1. Explicit env
    for env_key in ("GHIDRA_JDK", "JAVA_HOME"):
        val = os.environ.get(env_key)
        if val and is_valid_jdk_dir(Path(val)):
            return Path(val)

    # 2. Follow symlinks from PATH
    found = _detect_jdk_from_path()
    if found:
        return found

    # 3. macOS java_home helper
    if is_macos():
        try:
            jh = run_output(["/usr/libexec/java_home", "-v", "21"], timeout=5)
            if jh and is_valid_jdk_dir(Path(jh)):
                return Path(jh)
        except Exception:
            pass

    # 4. Well-known paths
    plat = get_platform()
    home = Path.home()
    candidates: list[Path] = []

    if plat == "macos":
        candidates = [
            Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"),
            Path("/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"),
            Path("/usr/lib/jvm/java-21-openjdk"),
            Path("/usr/lib/jvm/jdk-21"),
        ]
    elif plat == "windows":
        pf = Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))
        candidates = [
            pf / "Eclipse Adoptium" / "jdk-21",
            pf / "Java" / "jdk-21",
            home / "AppData" / "Local" / "Programs" / "Eclipse Adoptium" / "jdk-21",
        ]
        # Search versioned subdirs
        for parent in [pf / "Eclipse Adoptium", pf / "Java"]:
            if parent.exists():
                try:
                    for sub in sorted(parent.iterdir(), reverse=True):
                        if sub.is_dir() and is_valid_jdk_dir(sub):
                            return sub
                except PermissionError:
                    pass
    else:
        candidates = [
            Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"),
            Path("/usr/lib/jvm/java-21-openjdk-amd64"),
            Path("/usr/lib/jvm/java-21-openjdk"),
            Path("/usr/lib/jvm/jdk-21"),
            Path("/usr/lib/jvm/default-java"),
        ]

    for candidate in candidates:
        if is_valid_jdk_dir(candidate):
            return candidate

    return None


# ---------------------------------------------------------------------------
# Ghidra version detection
# ---------------------------------------------------------------------------

def detect_ghidra_version(ghidra_dir: Path) -> str | None:
    """Read the Ghidra version from application.properties."""
    props = ghidra_dir / "Ghidra" / "application.properties"
    if not props.exists():
        return None
    for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("application.version="):
            return line.split("=", 1)[1].strip()
    return None


# ---------------------------------------------------------------------------
# Ghidra settings directory
# ---------------------------------------------------------------------------

def bridge_settings_dir(ghidra_dir: Path) -> Path | None:
    """Return the user's Ghidra settings directory (where extensions live)."""
    env_override = os.environ.get("GHIDRA_RE_GHIDRA_SETTINGS_DIR")
    if env_override:
        return Path(env_override)

    plat = get_platform()
    home = Path.home()
    roots: list[Path] = []

    if plat == "macos":
        roots = [home / "Library" / "Ghidra"]
    elif plat == "windows":
        appdata = os.environ.get("APPDATA")
        roots = []
        if appdata:
            roots.append(Path(appdata) / "Ghidra")
        roots.append(home / "AppData" / "Roaming" / "Ghidra")
        roots.append(home / ".ghidra")
    else:
        roots = [home / ".ghidra", home / ".config" / "ghidra"]

    for root in roots:
        if not root.exists():
            continue
        try:
            matches = sorted(
                p
                for p in root.iterdir()
                if p.is_dir()
                and (p.name.startswith("ghidra_") or p.name.startswith(".ghidra_"))
                and p.name.endswith("_PUBLIC")
            )
            if matches:
                return matches[-1]
        except PermissionError:
            continue

    # Fall back to guessing from version
    version = detect_ghidra_version(ghidra_dir) if ghidra_dir else None
    if version:
        if plat == "macos":
            return home / "Library" / "Ghidra" / f"ghidra_{version}_PUBLIC"
        if plat == "windows":
            appdata = os.environ.get("APPDATA")
            base = Path(appdata) if appdata else home / "AppData" / "Roaming"
            return base / "Ghidra" / f"ghidra_{version}_PUBLIC"
        return home / ".ghidra" / f".ghidra_{version}_PUBLIC"

    return None
