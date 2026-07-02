"""Community plugin management: install and update third-party Ghidra extensions.

Currently managed plugins:
  - GhidraApple  https://github.com/ReverseApple/GhidraApple
    Provides ObjC type layout, msgSend rewriting, MRO propagation, NSBlock
    analysis and selector-based parameter renaming inside the Ghidra model.
    These improvements cascade into every downstream export script.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg

# ---------------------------------------------------------------------------
# GhidraApple metadata
# ---------------------------------------------------------------------------

GHIDRA_APPLE_REPO = "https://github.com/ReverseApple/GhidraApple"

# Pinned commit — chosen as the latest stable HEAD (2025-07-28) that fixes
# the "log as hex" diagnostics without introducing known regressions.
# Issues to watch: #62 (infinite loop on combined analyses), #73 (C++ crash).
GHIDRA_APPLE_PINNED_COMMIT = "828847d8e705e1373ac87620adeeef448edecd54"

# Pre-built release ZIP (Ghidra 11.3.1).  Works with 12.x because
# extension.properties carries no ghidraVersion constraint.
GHIDRA_APPLE_RELEASE_URL = (
    "https://github.com/ReverseApple/GhidraApple/releases/download/"
    "v0.0.1-alpha1/ghidra_11.3.1_PUBLIC_20250313_GhidraApple.zip"
)
GHIDRA_APPLE_RELEASE_VERSION = "v0.0.1-alpha1"
GHIDRA_APPLE_EXTENSION_NAME = "GhidraApple"

# State file lives next to the bridge install-state file.
_PLUGINS_STATE_FILE = cfg.bridge_config_dir / "plugins-state.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _plugins_state() -> dict[str, Any]:
    try:
        if _PLUGINS_STATE_FILE.exists():
            return json.loads(_PLUGINS_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _write_plugins_state(state: dict[str, Any]) -> None:
    _PLUGINS_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PLUGINS_STATE_FILE.write_text(
        json.dumps(state, indent=2), encoding="utf-8"
    )


def _ghidra_settings_dir() -> Path | None:
    """Return the user-level Ghidra settings directory (same logic as bridge)."""
    from cerberus_re_skill.core.ghidra_locator import bridge_settings_dir
    s = bridge_settings_dir(cfg.ghidra_install_dir)
    return s


def _extension_install_dirs() -> tuple[Path, Path | None]:
    """Return (user_extensions_dir, optional_app_extensions_dir)."""
    settings = _ghidra_settings_dir()
    if not settings:
        raise RuntimeError(
            "Could not determine Ghidra settings directory. "
            "Run 'cerberus-re bootstrap' first."
        )
    user_ext = settings / "Extensions" / "Ghidra"
    app_ext = cfg.ghidra_install_dir / "Ghidra" / "Extensions"
    app_ext_opt: Path | None = app_ext if app_ext.parent.exists() else None
    return user_ext, app_ext_opt


def _is_installed(extension_name: str) -> bool:
    """Check whether *extension_name* is already installed in either location."""
    try:
        user_ext, app_ext = _extension_install_dirs()
    except Exception:
        return False
    if (user_ext / extension_name).exists():
        return True
    if app_ext and (app_ext / extension_name).exists():
        return True
    return False


def _install_zip(zip_path: Path, extension_name: str) -> dict[str, Any]:
    """Extract *zip_path* into both extension dirs; return install info."""
    user_ext, app_ext = _extension_install_dirs()
    user_ext.mkdir(parents=True, exist_ok=True)

    tmp_root = cfg.bridge_config_dir / f"plugin-install-{extension_name}-tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    installed_dirs: list[str] = []
    try:
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(tmp_root)

        # The ZIP should contain a single top-level directory named after the extension.
        extracted_dirs = [d for d in tmp_root.iterdir() if d.is_dir()]
        if not extracted_dirs:
            raise RuntimeError(f"ZIP {zip_path} contains no top-level directory")
        extracted_root = extracted_dirs[0]

        # Install to user Extensions/Ghidra/<name>
        dest = user_ext / extension_name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(extracted_root, dest)
        installed_dirs.append(str(dest))

        # Also install to app Extensions/<name> if the directory is writable
        if app_ext and os.access(app_ext.parent, os.W_OK):
            app_ext.mkdir(parents=True, exist_ok=True)
            dest_app = app_ext / extension_name
            if dest_app.exists():
                shutil.rmtree(dest_app)
            shutil.copytree(extracted_root, dest_app)
            installed_dirs.append(str(dest_app))

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    return {"installed_dirs": installed_dirs}


def _find_gradle() -> str | None:
    """Return a usable 'gradle' or 'gradlew' executable, or None."""
    # 1. System gradle
    if shutil.which("gradle"):
        return "gradle"
    # 2. Homebrew-installed gradle
    for candidate in [
        "/opt/homebrew/bin/gradle",
        "/usr/local/bin/gradle",
    ]:
        if Path(candidate).exists():
            return candidate
    # 3. Gradle wrapper cached by Ghidra itself (same version: 9.3.1)
    import glob as _glob
    pattern = str(Path.home() / ".gradle" / "wrapper" / "dists" / "gradle-*" / "*" / "bin" / "gradle")
    matches = sorted(_glob.glob(pattern))
    if matches:
        return matches[-1]
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def install_ghidra_apple(
    force: bool = False,
    build_from_source: bool = False,
) -> dict[str, Any]:
    """Download (or build) and install the GhidraApple Ghidra extension.

    Parameters
    ----------
    force:
        Re-install even if already present.
    build_from_source:
        Clone the repo at the pinned commit and build with Gradle instead of
        using the pre-built release ZIP.  Requires git + Gradle (or a cached
        Gradle 9.3.1 distribution) and produces a JAR compiled against the
        exact Ghidra version installed on this machine.
    """
    if not force and _is_installed(GHIDRA_APPLE_EXTENSION_NAME):
        return {
            "ok": True,
            "status": "already_installed",
            "extension": GHIDRA_APPLE_EXTENSION_NAME,
        }

    from cerberus_re_skill.modules.bridge import auto_configure
    auto_configure()

    if build_from_source:
        result = _install_ghidra_apple_from_source()
    else:
        result = _install_ghidra_apple_prebuilt()

    # Persist state
    state = _plugins_state()
    state[GHIDRA_APPLE_EXTENSION_NAME] = {
        "installed_method": "source" if build_from_source else "prebuilt",
        "pinned_commit": GHIDRA_APPLE_PINNED_COMMIT,
        "release_version": GHIDRA_APPLE_RELEASE_VERSION,
        "ghidra_version": str(cfg.ghidra_install_dir),
        "installed_dirs": result.get("installed_dirs", []),
    }
    _write_plugins_state(state)

    return {
        "ok": True,
        "status": "installed",
        "extension": GHIDRA_APPLE_EXTENSION_NAME,
        "method": "source" if build_from_source else "prebuilt",
        "installed_dirs": result.get("installed_dirs", []),
        "note": (
            "Restart Ghidra and enable GhidraApple analyzers via "
            "Analysis > Analyze All Open Files > (check GhidraApple entries)."
        ),
    }


def _install_ghidra_apple_prebuilt() -> dict[str, Any]:
    """Download the pre-built release ZIP and install it."""
    with tempfile.TemporaryDirectory(prefix="ghidra-apple-download-") as tmp:
        zip_dest = Path(tmp) / "GhidraApple.zip"
        print(f"Downloading GhidraApple {GHIDRA_APPLE_RELEASE_VERSION} …")
        try:
            urllib.request.urlretrieve(GHIDRA_APPLE_RELEASE_URL, zip_dest)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to download GhidraApple release ZIP: {exc}\n"
                f"URL: {GHIDRA_APPLE_RELEASE_URL}\n"
                "Try --build-from-source or download manually and place the "
                f"ZIP at {zip_dest}."
            ) from exc

        return _install_zip(zip_dest, GHIDRA_APPLE_EXTENSION_NAME)


def _install_ghidra_apple_from_source() -> dict[str, Any]:
    """Clone the repo at the pinned commit and build with Gradle."""
    gradle = _find_gradle()
    if not gradle:
        raise RuntimeError(
            "Gradle not found. Install via 'brew install gradle' (macOS) or "
            "'sdk install gradle' (SDKMAN) then retry.\n"
            "Alternatively, run without --build-from-source to use the "
            "pre-built release ZIP."
        )

    git = shutil.which("git")
    if not git:
        raise RuntimeError("git not found on PATH; required for --build-from-source.")

    java_home = str(cfg.ghidra_jdk)
    env = {
        **os.environ,
        "JAVA_HOME": java_home,
        "PATH": str(Path(java_home) / "bin") + os.pathsep + os.environ.get("PATH", ""),
        "GHIDRA_INSTALL_DIR": str(cfg.ghidra_install_dir),
    }

    with tempfile.TemporaryDirectory(prefix="ghidra-apple-build-") as tmp:
        clone_dir = Path(tmp) / "GhidraApple"

        print(f"Cloning GhidraApple at {GHIDRA_APPLE_PINNED_COMMIT[:12]} …")
        subprocess.run(
            [git, "clone", GHIDRA_APPLE_REPO, str(clone_dir)],
            check=True, env=env,
        )
        subprocess.run(
            [git, "-C", str(clone_dir), "checkout", GHIDRA_APPLE_PINNED_COMMIT],
            check=True, env=env,
        )

        print(f"Building GhidraApple against Ghidra {cfg.ghidra_install_dir} …")
        gradle_cmd = [gradle, "buildExtension",
                      f"-PGHIDRA_INSTALL_DIR={cfg.ghidra_install_dir}"]
        subprocess.run(gradle_cmd, check=True, cwd=str(clone_dir), env=env)

        # Find the built ZIP under dist/
        dist_dir = clone_dir / "dist"
        zips = sorted(dist_dir.glob("*.zip")) if dist_dir.exists() else []
        if not zips:
            raise RuntimeError(
                f"Gradle build succeeded but no ZIP found under {dist_dir}."
            )
        built_zip = zips[-1]
        print(f"Built: {built_zip.name}")

        return _install_zip(built_zip, GHIDRA_APPLE_EXTENSION_NAME)


def plugin_status() -> dict[str, Any]:
    """Return install status for all managed plugins."""
    state = _plugins_state()
    plugins = []

    installed = _is_installed(GHIDRA_APPLE_EXTENSION_NAME)
    entry = state.get(GHIDRA_APPLE_EXTENSION_NAME, {})
    plugins.append({
        "name": GHIDRA_APPLE_EXTENSION_NAME,
        "repo": GHIDRA_APPLE_REPO,
        "pinned_commit": GHIDRA_APPLE_PINNED_COMMIT[:12],
        "release_version": GHIDRA_APPLE_RELEASE_VERSION,
        "installed": installed,
        "install_method": entry.get("installed_method"),
        "installed_dirs": entry.get("installed_dirs", []),
    })

    return {"plugins": plugins}
