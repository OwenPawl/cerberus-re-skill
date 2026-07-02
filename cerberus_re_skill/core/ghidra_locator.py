"""Ghidra installation and JDK detection for Windows, macOS, and Linux."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from cerberus_re_skill.core.platform_helpers import get_platform, is_macos, is_windows
from cerberus_re_skill.core.subprocess_utils import find_tool, run_output


# ---------------------------------------------------------------------------
# Ghidra directory validation
# ---------------------------------------------------------------------------

def analyze_headless_path(ghidra_dir: Path) -> Path | None:
    """Return the analyzeHeadless executable path within *ghidra_dir*, or None."""
    for name in ("support/analyzeHeadless", "support/analyzeHeadless.bat"):
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


def gradle_wrapper_path(ghidra_dir: Path) -> Path | None:
    """Return the Gradle wrapper path bundled with Ghidra, or None."""
    for name in ("support/gradle/gradlew", "support/gradle/gradlew.bat"):
        candidate = ghidra_dir / name
        if candidate.exists():
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
    if is_macos() and p.resolve() == Path("/usr"):
        return False
    has_java = (p / "bin" / "java").exists() or (p / "bin" / "java.exe").exists()
    has_javac = (p / "bin" / "javac").exists() or (p / "bin" / "javac.exe").exists()
    return has_java and has_javac


def _java_path(jdk_dir: Path | str | None) -> Path | None:
    if not jdk_dir:
        return None
    p = Path(jdk_dir)
    for name in ("java", "java.exe"):
        candidate = p / "bin" / name
        if candidate.exists():
            return candidate
    return None


def _macos_boot_args() -> str:
    try:
        result = subprocess.run(
            ["nvram", "boot-args"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return ""
    return (result.stdout or "") + (result.stderr or "")


def macos_amfi_get_out_of_my_way_enabled() -> bool:
    """Return True when the macOS AMFI-disabling boot arg is active."""
    return is_macos() and "amfi_get_out_of_my_way=1" in _macos_boot_args()


def jdk_archs(jdk_dir: Path | str | None) -> set[str]:
    """Return binary architectures for a JDK's java launcher when available."""
    java = _java_path(jdk_dir)
    if not java:
        return set()
    if is_macos():
        try:
            result = subprocess.run(
                ["lipo", "-archs", str(java)],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                return set(result.stdout.strip().split())
        except Exception:
            pass
    return set()


def _should_skip_jdk_start_smoke(jdk_dir: Path | str | None) -> bool:
    """Avoid known-crashing arm64 HotSpot startup when AMFI is disabled."""
    if not macos_amfi_get_out_of_my_way_enabled():
        return False
    archs = jdk_archs(jdk_dir)
    return "arm64" in archs and "x86_64" not in archs


def can_start_jdk(jdk_dir: Path | str | None) -> bool:
    """Return True only if *jdk_dir* looks valid and `java -version` starts."""
    if not is_valid_jdk_dir(jdk_dir):
        return False
    if _should_skip_jdk_start_smoke(jdk_dir):
        return False
    java = _java_path(jdk_dir)
    if not java:
        return False
    try:
        result = subprocess.run(
            [str(java), "-version"],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except Exception:
        return False
    return result.returncode == 0


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
            if can_start_jdk(candidate):
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
        candidates = [
            pf / "Ghidra",
            Path("C:/Tools/Ghidra"),
            home / "AppData" / "Local" / "Programs" / "Ghidra",
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
        if val and can_start_jdk(Path(val)):
            return Path(val)

    # 2. Follow symlinks from PATH
    found = _detect_jdk_from_path()
    if found:
        return found

    # 3. macOS java_home helper
    if is_macos():
        try:
            jh = run_output(["/usr/libexec/java_home", "-v", "21"], timeout=5)
            if jh and can_start_jdk(Path(jh)):
                return Path(jh)
        except Exception:
            pass

    # 4. Well-known paths
    plat = get_platform()
    home = Path.home()
    candidates: list[Path] = []

    if plat == "macos":
        candidates = [
            home / ".local" / "jdks" / "temurin-21-x64.jdk" / "Contents" / "Home",
            home / ".local" / "jdks" / "zulu-21-x64.jdk" / "Contents" / "Home",
            home / "Library" / "Java" / "JavaVirtualMachines" / "temurin-21-x64.jdk" / "Contents" / "Home",
            home / "Library" / "Java" / "JavaVirtualMachines" / "zulu-21-x64.jdk" / "Contents" / "Home",
            Path("/Library/Java/JavaVirtualMachines/temurin-21-x64.jdk/Contents/Home"),
            Path("/Library/Java/JavaVirtualMachines/zulu-21-x64.jdk/Contents/Home"),
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
                        if sub.is_dir() and can_start_jdk(sub):
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

    if plat == "macos":
        for parent in [
            home / ".local" / "jdks",
            home / "Library" / "Java" / "JavaVirtualMachines",
            Path("/Library/Java/JavaVirtualMachines"),
        ]:
            if not parent.exists():
                continue
            try:
                for sub in sorted(parent.iterdir(), reverse=True):
                    if not sub.is_dir():
                        continue
                    if "x64" not in sub.name.lower() and "x86" not in sub.name.lower():
                        continue
                    candidate = sub / "Contents" / "Home"
                    if can_start_jdk(candidate):
                        return candidate
            except PermissionError:
                pass

    for candidate in candidates:
        if can_start_jdk(candidate):
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
