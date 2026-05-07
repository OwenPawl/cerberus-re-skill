"""Community plugin management: install and update third-party Ghidra extensions.

Currently managed plugins:
  - GhidraApple  https://github.com/ReverseApple/GhidraApple
    Provides ObjC type layout, msgSend rewriting, MRO propagation, NSBlock
    analysis and selector-based parameter renaming inside the Ghidra model.
    These improvements cascade into every downstream export script.
"""

from __future__ import annotations

import json
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg
from ghidra_re_skill.core.ghidra_locator import gradle_wrapper_path
from ghidra_re_skill.core.platform_helpers import is_macos

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

GHIDRA_SOURCE_REPO = "https://github.com/NationalSecurityAgency/ghidra.git"
SLEIGH_DEV_TOOLS_EXTENSION_NAME = "SleighDevTools"
GNU_DISASSEMBLER_EXTENSION_NAME = "GnuDisassembler"
GNU_DISASSEMBLER_BINUTILS = "binutils-2.41"
GNU_DISASSEMBLER_BINUTILS_URL = (
    f"https://ftp.gnu.org/pub/gnu/binutils/{GNU_DISASSEMBLER_BINUTILS}.tar.bz2"
)
GNU_DISASSEMBLER_BINUTILS_SHA256 = (
    "a4c4bec052f7b8370024e60389e194377f3f48b56618418ea51067f67aaab30b"
)

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
    from ghidra_re_skill.core.ghidra_locator import bridge_settings_dir
    s = bridge_settings_dir(cfg.ghidra_install_dir)
    return s


def _extension_install_dirs() -> tuple[Path, Path | None]:
    """Return (user_extensions_dir, optional_app_extensions_dir)."""
    settings = _ghidra_settings_dir()
    if not settings:
        raise RuntimeError(
            "Could not determine Ghidra settings directory. "
            "Run 'ghidra-re bootstrap' first."
        )
    user_ext = settings / "Extensions" / "Ghidra"
    app_ext = cfg.ghidra_install_dir / "Ghidra" / "Extensions"
    app_ext_opt: Path | None = app_ext if app_ext.parent.exists() else None
    return user_ext, app_ext_opt


def _ghidra_application_version() -> str:
    props = cfg.ghidra_install_dir / "Ghidra" / "application.properties"
    if not props.exists():
        return ""
    for line in props.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("application.version="):
            return line.split("=", 1)[1].strip()
    return ""


def _ghidra_source_tag() -> str:
    version = _ghidra_application_version()
    if not version:
        raise RuntimeError("could not determine Ghidra application.version")
    return f"Ghidra_{version}_build"


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts[:3])


def _version_at_least(version: str, minimum: str) -> bool:
    left = _version_tuple(version)
    right = _version_tuple(minimum)
    if not left or not right:
        return False
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) >= right + (0,) * (width - len(right))


def _extension_properties(path: Path) -> dict[str, str]:
    props = path / "extension.properties"
    values: dict[str, str] = {}
    if not props.exists():
        return values
    for line in props.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _extension_version(extension_name: str) -> str | None:
    try:
        user_ext, app_ext = _extension_install_dirs()
    except Exception:
        return None
    for parent in [user_ext, app_ext]:
        if not parent:
            continue
        version = _extension_properties(parent / extension_name).get("version")
        if version:
            return version
    return None


def _installed_extension_dirs(extension_name: str) -> list[Path]:
    try:
        user_ext, app_ext = _extension_install_dirs()
    except Exception:
        return []
    paths: list[Path] = []
    for parent in [user_ext, app_ext]:
        if not parent:
            continue
        path = parent / extension_name
        if path.exists():
            paths.append(path)
    return paths


def _is_compatible_installed(extension_name: str) -> bool:
    if not _is_installed(extension_name):
        return False
    installed_version = _extension_version(extension_name)
    ghidra_version = _ghidra_application_version()
    if not (installed_version and ghidra_version and installed_version == ghidra_version):
        return False
    if extension_name == GNU_DISASSEMBLER_EXTENSION_NAME and is_macos():
        return _gnu_disassembler_native_provider_ready()
    return True


def _gnu_disassembler_native_provider_ready() -> bool:
    platform_name = _native_platform_name()
    extension_dirs = _installed_extension_dirs(GNU_DISASSEMBLER_EXTENSION_NAME)
    if not extension_dirs:
        return False
    for path in extension_dirs:
        gdis = path / "os" / platform_name / "gdis"
        if not _native_gdis_ready(gdis):
            return False
    return True


def _native_gdis_ready(gdis: Path) -> bool:
    if not (gdis.is_file() and os.access(gdis, os.X_OK)):
        return False
    file_tool = shutil.which("file") or "/usr/bin/file"
    result = subprocess.run(
        [file_tool, str(gdis)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False
    return _native_arch_token() in result.stdout


def _native_arch_token() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    raise RuntimeError(f"unsupported macOS architecture for GnuDisassembler: {machine}")


def _gnu_disassembler_skip_details() -> dict[str, Any]:
    platform_name = _native_platform_name()
    return {
        "native_platform": platform_name,
        "native_providers": [
            str(path / "os" / platform_name / "gdis")
            for path in _installed_extension_dirs(GNU_DISASSEMBLER_EXTENSION_NAME)
        ],
    }


def _gnu_disassembler_status_details() -> dict[str, Any]:
    platform_name = _native_platform_name() if is_macos() else None
    native_providers: list[dict[str, Any]] = []
    if platform_name:
        for path in _installed_extension_dirs(GNU_DISASSEMBLER_EXTENSION_NAME):
            gdis = path / "os" / platform_name / "gdis"
            native_providers.append({
                "path": str(gdis),
                "exists": gdis.is_file(),
                "executable": gdis.is_file() and os.access(gdis, os.X_OK),
                "matches_arch": _native_gdis_ready(gdis),
            })
    return {
        "native_platform": platform_name,
        "native_provider_ready": (
            _gnu_disassembler_native_provider_ready() if is_macos() else None
        ),
        "native_providers": native_providers,
    }


def _patch_installed_extension_properties(extension_name: str, **updates: str) -> None:
    if not updates:
        return
    user_ext, app_ext = _extension_install_dirs()
    for parent in [user_ext, app_ext]:
        if not parent:
            continue
        if parent == app_ext and not _extension_dir_writable(parent):
            continue
        props = parent / extension_name / "extension.properties"
        if not props.exists():
            continue
        original_text = props.read_text(encoding="utf-8")
        text = original_text
        for key, value in updates.items():
            replacement = f"{key}={value}"
            if re.search(rf"^{re.escape(key)}=", text, flags=re.MULTILINE):
                text = re.sub(
                    rf"^{re.escape(key)}=.*$",
                    replacement,
                    text,
                    flags=re.MULTILINE,
                )
            else:
                if text and not text.endswith("\n"):
                    text += "\n"
                text += f"{replacement}\n"
        if text != original_text:
            _atomic_write_text(props, text)


def _atomic_write_text(path: Path, text: str) -> None:
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
    ) as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _extension_dir_writable(path: Path) -> bool:
    if path.exists():
        return path.is_dir() and os.access(path, os.W_OK)
    return path.parent.exists() and os.access(path.parent, os.W_OK)


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

    installed_dirs: list[str] = []
    with tempfile.TemporaryDirectory(prefix=f"plugin-install-{extension_name}-") as tmp:
        tmp_root = Path(tmp)
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
        if app_ext and _extension_dir_writable(app_ext):
            app_ext.mkdir(parents=True, exist_ok=True)
            dest_app = app_ext / extension_name
            if dest_app.exists():
                shutil.rmtree(dest_app)
            shutil.copytree(extracted_root, dest_app)
            installed_dirs.append(str(dest_app))

    return {"installed_dirs": installed_dirs}


def _find_gradle() -> str | None:
    """Return a usable 'gradle' or 'gradlew' executable, or None."""
    # 1. Ghidra's bundled Gradle wrapper, which matches the target Ghidra build.
    wrapper = gradle_wrapper_path(cfg.ghidra_install_dir)
    if wrapper and wrapper.exists():
        return str(wrapper)
    # 2. System gradle
    if shutil.which("gradle"):
        return "gradle"
    # 3. Homebrew-installed gradle
    for candidate in [
        "/opt/homebrew/bin/gradle",
        "/usr/local/bin/gradle",
    ]:
        if Path(candidate).exists():
            return candidate
    # 4. Gradle wrapper cached by Ghidra itself.
    import glob as _glob
    pattern = str(Path.home() / ".gradle" / "wrapper" / "dists" / "gradle-*" / "*" / "bin" / "gradle")
    matches = sorted(_glob.glob(pattern))
    if matches:
        return matches[-1]
    return None


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> None:
    subprocess.run(cmd, check=True, cwd=str(cwd) if cwd else None, env=env, timeout=timeout)


def _java_env() -> dict[str, str]:
    java_home = str(cfg.ghidra_jdk)
    return {
        **os.environ,
        "JAVA_HOME": java_home,
        "PATH": str(Path(java_home) / "bin") + os.pathsep + os.environ.get("PATH", ""),
        "GHIDRA_INSTALL_DIR": str(cfg.ghidra_install_dir),
    }


def _clone_ghidra_source_modules(root: Path, modules: list[str]) -> Path:
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git not found on PATH; required to fetch Ghidra source modules.")
    tag = _ghidra_source_tag()
    src = root / "ghidra-source"
    _run(
        [
            git,
            "clone",
            "--depth",
            "1",
            "--branch",
            tag,
            "--filter=blob:none",
            "--sparse",
            GHIDRA_SOURCE_REPO,
            str(src),
        ],
        env=_java_env(),
    )
    _run([git, "-C", str(src), "sparse-checkout", "set", *modules], env=_java_env())
    return src


def _minimal_extension_build_gradle(module_dir: Path) -> None:
    module_dir.joinpath("build.gradle").write_text(
        'apply from: file(System.getenv("GHIDRA_INSTALL_DIR") + "/support/buildExtension.gradle")\n',
        encoding="utf-8",
    )
    module_dir.joinpath("settings.gradle").write_text(
        f"rootProject.name = '{module_dir.name}'\n",
        encoding="utf-8",
    )


def _enable_ghidra_apple_in_codebrowser() -> None:
    """Enable the GhidraApple plugin package in the user's CodeBrowser tool."""
    import xml.etree.ElementTree as ET

    settings = _ghidra_settings_dir()
    if not settings:
        return
    tool_file = settings / "tools" / "_code_browser.tcd"
    if not tool_file.exists():
        return
    plugin_classes = [
        "lol.fairplay.ghidraapple.plugins.ObjectiveCDynamicDispatchPlugin",
        "lol.fairplay.ghidraapple.plugins.ObjCInheritanceGraphPlugin",
        "lol.fairplay.ghidraapple.plugins.ClassParserTestingPlugin",
    ]
    try:
        tree = ET.parse(tool_file)
        root = tree.getroot()
        tool = root.find("TOOL")
        if tool is None:
            return
        packages = list(tool.findall("PACKAGE"))
        core = next((p for p in packages if p.get("NAME") == "Ghidra Core"), None)
        if core is None:
            core = ET.Element("PACKAGE", {"NAME": "Ghidra Core"})
            tool.insert(0, core)
        included = {node.get("CLASS") for node in core.findall("INCLUDE")}
        for cls in plugin_classes:
            if cls not in included:
                ET.SubElement(core, "INCLUDE", {"CLASS": cls})
        if not any(p.get("NAME") == "GhidraApple" for p in packages):
            tool.insert(list(tool).index(core) + 1, ET.Element("PACKAGE", {"NAME": "GhidraApple"}))
        ET.indent(tree, space="    ")
        tmp_file = tool_file.with_suffix(tool_file.suffix + ".tmp")
        tree.write(tmp_file, encoding="UTF-8", xml_declaration=True)
        tmp_file.replace(tool_file)
    except Exception:
        # Tool XML is user-owned state; never fail plugin installation because
        # a customized or malformed tool config could not be patched.
        return


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
    from ghidra_re_skill.modules.bridge import auto_configure
    auto_configure()

    ghidra_version = _ghidra_application_version()
    if not build_from_source and _version_at_least(ghidra_version, "12.0"):
        build_from_source = True

    if not force and _is_compatible_installed(GHIDRA_APPLE_EXTENSION_NAME):
        _enable_ghidra_apple_in_codebrowser()
        return {
            "ok": True,
            "status": "already_installed",
            "extension": GHIDRA_APPLE_EXTENSION_NAME,
        }

    if build_from_source:
        result = _install_ghidra_apple_from_source()
    else:
        result = _install_ghidra_apple_prebuilt()
    _patch_installed_extension_properties(
        GHIDRA_APPLE_EXTENSION_NAME,
        version=ghidra_version,
    )
    _enable_ghidra_apple_in_codebrowser()

    # Persist state
    state = _plugins_state()
    state[GHIDRA_APPLE_EXTENSION_NAME] = {
        "installed_method": "source" if build_from_source else "prebuilt",
        "pinned_commit": GHIDRA_APPLE_PINNED_COMMIT,
        "release_version": GHIDRA_APPLE_RELEASE_VERSION,
        "ghidra_version": ghidra_version,
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

    env = _java_env()

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
        if _version_at_least(_ghidra_application_version(), "12.0"):
            _patch_ghidra_apple_source_for_ghidra_12(clone_dir)

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


def _patch_ghidra_apple_source_for_ghidra_12(clone_dir: Path) -> None:
    """Apply the small source compatibility patch needed for Ghidra 12.x APIs."""
    loader = clone_dir / "src/main/java/lol/fairplay/ghidraapple/loading/UniversalBinaryLoader.kt"
    if loader.exists():
        text = loader.read_text(encoding="utf-8")
        text = text.replace("import ghidra.app.util.Option\n", "")
        text = text.replace("import ghidra.app.util.importer.MessageLog\n", "")
        text = text.replace("import ghidra.framework.model.Project\n", "")
        text = text.replace("import ghidra.util.task.TaskMonitor\n", "")
        if "import ghidra.app.util.opinion.Loader\n" not in text:
            text, import_count = re.subn(
                "import ghidra.app.util.opinion.Loaded\n",
                "import ghidra.app.util.opinion.Loaded\nimport ghidra.app.util.opinion.Loader\n",
                text,
                count=1,
            )
            if import_count != 1:
                raise RuntimeError("failed to patch GhidraApple Loader import for Ghidra 12")
        new = """    override fun postLoadProgramFixups(
        loadedPrograms: MutableList<Loaded<Program>>,
        settings: Loader.ImporterSettings,
    ) {
        super.postLoadProgramFixups(loadedPrograms, settings)
        val project = settings.project()
        for (loaded in loadedPrograms) {
            // The actual program is wrapped, so we need to unwrap it.
            val program = loaded.domainObject

            // This will trigger [getPreferredFileName] above.
            val preferredName = loaded.name

            // If the preferred name is the same as the given name, this probably wasn't
            // part of a universal binary. Thus, we skip any operations.
            if (program.name == preferredName) continue

            // Otherwise, we rename with the preferred name.
            program.withTransaction<Exception>("rename") {
                program.name = preferredName
            }

            // After renaming, the programs will be in folders named after their original
            // names. To reduce redundancy, we move the programs to the parent folder.
            val originalFolderPath = loaded.projectFolderPath
            val newFolderPath =
                originalFolderPath
                    .split("/")
                    // Filter out, potentially, the last, empty, element (if the path ended in "/").
                    .filterNot(String::isEmpty)
                    .dropLast(1) // Drop the last path component, leaving a path to the parent folder.
                    .joinToString("/")
            loaded.projectFolderPath = newFolderPath
            // Now that the program is up one folder, we can delete the original one.
            project?.projectData?.getFolder(originalFolderPath)?.delete()
        }
    }
"""
        text, method_count = re.subn(
            r"    override fun postLoadProgramFixups\(\n.*?\n    }\n(?=})",
            new,
            text,
            count=1,
            flags=re.DOTALL,
        )
        if method_count != 1:
            raise RuntimeError("failed to patch GhidraApple postLoadProgramFixups for Ghidra 12")
        loader.write_text(text, encoding="utf-8")

    patched_signature_setters = False
    for relative_path in [
        "src/main/java/lol/fairplay/ghidraapple/analysis/passes/objcclasses/OCTypeInjectorAnalyzer.kt",
        "src/main/java/lol/fairplay/ghidraapple/analysis/passes/objcclasses/ApplyAllocTypeOverrideCommand.kt",
    ]:
        type_injector = clone_dir / relative_path
        if not type_injector.exists():
            continue
        text = type_injector.read_text(encoding="utf-8")
        original_text = text
        text = text.replace("fsig.returnType = type", "fsig.setReturnType(type)")
        text = text.replace(
            'fsig.arguments = arrayOf(ParameterDefinitionImpl("cls", type, null))',
            'fsig.setArguments(ParameterDefinitionImpl("cls", type, null))',
        )
        if text != original_text:
            type_injector.write_text(text, encoding="utf-8")
            patched_signature_setters = True
    if not patched_signature_setters:
        raise RuntimeError("failed to patch GhidraApple function signature setters for Ghidra 12")


def install_sleigh_dev_tools(force: bool = False) -> dict[str, Any]:
    """Build and install the matching SleighDevTools extension from Ghidra source."""
    from ghidra_re_skill.modules.bridge import auto_configure
    auto_configure()
    ghidra_version = _ghidra_application_version()
    if not force and _is_compatible_installed(SLEIGH_DEV_TOOLS_EXTENSION_NAME):
        return {
            "ok": True,
            "status": "already_installed",
            "extension": SLEIGH_DEV_TOOLS_EXTENSION_NAME,
        }
    gradle = _find_gradle()
    if not gradle:
        raise RuntimeError("Gradle not found; cannot build SleighDevTools.")
    with tempfile.TemporaryDirectory(prefix="sleigh-dev-tools-build-") as tmp:
        tmp_root = Path(tmp)
        source_root = _clone_ghidra_source_modules(
            tmp_root,
            ["Ghidra/Extensions/SleighDevTools"],
        )
        module = tmp_root / SLEIGH_DEV_TOOLS_EXTENSION_NAME
        shutil.copytree(source_root / "Ghidra/Extensions/SleighDevTools", module)
        _minimal_extension_build_gradle(module)
        _run([gradle, "buildExtension"], cwd=module, env=_java_env())
        zips = sorted((module / "dist").glob(f"*_{SLEIGH_DEV_TOOLS_EXTENSION_NAME}.zip"))
        if not zips:
            raise RuntimeError(f"SleighDevTools build succeeded but no ZIP found under {module / 'dist'}")
        result = _install_zip(zips[-1], SLEIGH_DEV_TOOLS_EXTENSION_NAME)
    _patch_installed_extension_properties(SLEIGH_DEV_TOOLS_EXTENSION_NAME, version=ghidra_version)
    _record_extension_state(SLEIGH_DEV_TOOLS_EXTENSION_NAME, "source", result.get("installed_dirs", []))
    return {
        "ok": True,
        "status": "installed",
        "extension": SLEIGH_DEV_TOOLS_EXTENSION_NAME,
        "method": "source",
        "installed_dirs": result.get("installed_dirs", []),
    }


def install_gnu_disassembler(
    force: bool = False,
    ensure_dependencies: bool = True,
) -> dict[str, Any]:
    """Build and install Ghidra's GPL GnuDisassembler native provider on macOS."""
    from ghidra_re_skill.modules.bridge import auto_configure
    auto_configure()
    if not is_macos():
        return {
            "ok": True,
            "status": "skipped",
            "extension": GNU_DISASSEMBLER_EXTENSION_NAME,
            "reason": "GnuDisassembler auto-build is currently implemented for macOS only.",
        }
    dependencies: list[dict[str, Any]] = []
    if ensure_dependencies:
        dependencies.append(install_sleigh_dev_tools(force=force))
    ghidra_version = _ghidra_application_version()
    if not force and _is_compatible_installed(GNU_DISASSEMBLER_EXTENSION_NAME):
        return {
            "ok": True,
            "status": "already_installed",
            "extension": GNU_DISASSEMBLER_EXTENSION_NAME,
            "dependencies": dependencies,
            **_gnu_disassembler_skip_details(),
        }
    _ensure_gnu_disassembler_build_tools()
    gradle = _find_gradle()
    if not gradle:
        raise RuntimeError("Gradle not found; cannot build GnuDisassembler.")
    platform_name = _native_platform_name()
    with tempfile.TemporaryDirectory(prefix="gnu-disassembler-build-") as tmp:
        tmp_root = Path(tmp)
        source_root = _clone_ghidra_source_modules(
            tmp_root,
            ["GPL/GnuDisassembler"],
        )
        module = tmp_root / GNU_DISASSEMBLER_EXTENSION_NAME
        shutil.copytree(source_root / "GPL/GnuDisassembler", module)
        _download_verified(
            GNU_DISASSEMBLER_BINUTILS_URL,
            module / f"{GNU_DISASSEMBLER_BINUTILS}.tar.bz2",
            GNU_DISASSEMBLER_BINUTILS_SHA256,
        )
        _patch_gnu_disassembler_build(module)
        env = {
            **_java_env(),
            "AR": "/usr/bin/ar",
            "RANLIB": "/usr/bin/ranlib",
            "NM": "/usr/bin/nm",
            "PATH": _homebrew_build_path(_java_env()["PATH"]),
            "CPPFLAGS": _homebrew_cppflags(),
            "LDFLAGS": _homebrew_ldflags(),
        }
        _run([gradle, "binutilsUnpack"], cwd=module, env=env)
        _patch_binutils_zlib(module)
        _run([gradle, f"buildNatives_{platform_name}"], cwd=module, env=env)
        gdis = module / "build" / "os" / platform_name / "gdis"
        if not gdis.exists():
            raise RuntimeError(f"GnuDisassembler build succeeded but {gdis} was not found")
        result = _install_gnu_disassembler_tree(module, gdis, platform_name)
    _record_extension_state(GNU_DISASSEMBLER_EXTENSION_NAME, "source", result.get("installed_dirs", []))
    return {
        "ok": True,
        "status": "installed",
        "extension": GNU_DISASSEMBLER_EXTENSION_NAME,
        "method": "source",
        "dependencies": dependencies,
        "installed_dirs": result.get("installed_dirs", []),
        "native_platform": platform_name,
    }


def install_macos_disassembly_extensions(force: bool = False) -> dict[str, Any]:
    """Install SleighDevTools plus the native GPL GnuDisassembler on macOS."""
    if not is_macos():
        return {"ok": True, "status": "skipped", "reason": "not macOS"}
    sleigh = install_sleigh_dev_tools(force=force)
    gnu = install_gnu_disassembler(force=force, ensure_dependencies=False)
    return {
        "ok": True,
        "status": "installed",
        "extensions": [sleigh, gnu],
    }


def _native_platform_name() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "mac_arm_64"
    if machine in {"x86_64", "amd64"}:
        return "mac_x86_64"
    raise RuntimeError(f"unsupported macOS architecture for GnuDisassembler: {machine}")


def _homebrew_build_path(existing_path: str) -> str:
    prefixes = [
        "/opt/homebrew/opt/flex/bin",
        "/opt/homebrew/opt/bison/bin",
        "/opt/homebrew/opt/texinfo/bin",
        "/opt/homebrew/opt/binutils/bin",
        "/usr/local/opt/flex/bin",
        "/usr/local/opt/bison/bin",
        "/usr/local/opt/texinfo/bin",
        "/usr/local/opt/binutils/bin",
    ]
    return os.pathsep.join([p for p in prefixes if Path(p).exists()] + [existing_path])


def _download_verified(url: str, destination: Path, sha256: str) -> None:
    urllib.request.urlretrieve(url, destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest.lower() != sha256.lower():
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"checksum mismatch for {url}: expected {sha256}, got {digest}"
        )


def _ensure_gnu_disassembler_build_tools() -> None:
    path = _homebrew_build_path(os.environ.get("PATH", ""))
    missing = [
        tool
        for tool in ["flex", "bison", "makeinfo", "objdump"]
        if not shutil.which(tool, path=path)
    ]
    missing.extend(_missing_dependency_files())
    if missing:
        raise RuntimeError(
            "missing build tools for GnuDisassembler: "
            + ", ".join(missing)
            + ". On macOS install them with: brew install flex bison texinfo zlib binutils zstd"
        )


def _missing_dependency_files() -> list[str]:
    checks = {
        "flex headers": [
            "/opt/homebrew/opt/flex/include/FlexLexer.h",
            "/usr/local/opt/flex/include/FlexLexer.h",
        ],
        "zlib headers": [
            "/opt/homebrew/opt/zlib/include/zlib.h",
            "/usr/local/opt/zlib/include/zlib.h",
        ],
        "zstd headers": [
            "/opt/homebrew/include/zstd.h",
            "/opt/homebrew/opt/zstd/include/zstd.h",
            "/usr/local/include/zstd.h",
            "/usr/local/opt/zstd/include/zstd.h",
        ],
        "zstd library": [
            "/opt/homebrew/lib/libzstd.dylib",
            "/opt/homebrew/opt/zstd/lib/libzstd.dylib",
            "/usr/local/lib/libzstd.dylib",
            "/usr/local/opt/zstd/lib/libzstd.dylib",
        ],
    }
    return [name for name, paths in checks.items() if not any(Path(p).exists() for p in paths)]


def _homebrew_cppflags() -> str:
    includes = [
        "/opt/homebrew/opt/flex/include",
        "/opt/homebrew/opt/zlib/include",
        "/usr/local/opt/flex/include",
        "/usr/local/opt/zlib/include",
    ]
    return " ".join(f"-I{p}" for p in includes if Path(p).exists())


def _homebrew_ldflags() -> str:
    libs = [
        "/opt/homebrew/opt/flex/lib",
        "/opt/homebrew/opt/bison/lib",
        "/opt/homebrew/opt/zlib/lib",
        "/opt/homebrew/opt/zstd/lib",
        "/opt/homebrew/lib",
        "/usr/local/opt/flex/lib",
        "/usr/local/opt/bison/lib",
        "/usr/local/opt/zlib/lib",
        "/usr/local/opt/zstd/lib",
        "/usr/local/lib",
    ]
    return " ".join(f"-L{p}" for p in libs if Path(p).exists())


def _patch_gnu_disassembler_build(module: Path) -> None:
    build = module / "buildGdis.gradle"
    text = build.read_text(encoding="utf-8")
    if '"-lzstd"' not in text:
        text, zstd_count = re.subn(r'("-lz"\s*,)', r'\1 "-lzstd",', text, count=1)
        if zstd_count != 1:
            raise RuntimeError("failed to patch GnuDisassembler zstd linker argument")
    for lib_dir in ["/opt/homebrew/lib", "/usr/local/lib"]:
        if Path(lib_dir).exists() and f'"-L{lib_dir}"' not in text:
            text, lib_count = re.subn(
                r'(linker\.args\s+"-L\$\{binutilsArtifactsDir\}/lib")',
                rf'\1, "-L{lib_dir}"',
                text,
                count=1,
            )
            if lib_count != 1:
                raise RuntimeError("failed to patch GnuDisassembler Homebrew linker path")
            break
    build.write_text(text, encoding="utf-8")


def _patch_binutils_zlib(module: Path) -> None:
    zutil = module / "build" / GNU_DISASSEMBLER_BINUTILS / "zlib" / "zutil.h"
    if not zutil.exists():
        raise RuntimeError(f"expected binutils zlib header not found at {zutil}")
    text = zutil.read_text(encoding="utf-8", errors="ignore")
    target = "#if defined(MACOS) || defined(TARGET_OS_MAC)"
    replacement = (
        "#if !defined(__APPLE__) && (defined(MACOS) || defined(TARGET_OS_MAC))"
    )
    if target not in text:
        raise RuntimeError("failed to patch binutils zlib macOS fdopen guard")
    text = text.replace(target, replacement, 1)
    zutil.write_text(text, encoding="utf-8")


def _install_gnu_disassembler_tree(module: Path, gdis: Path, platform_name: str) -> dict[str, Any]:
    user_ext, app_ext = _extension_install_dirs()
    installed_dirs: list[str] = []
    ghidra_version = _ghidra_application_version()
    for parent in [user_ext, app_ext]:
        if not parent:
            continue
        if parent == app_ext and not _extension_dir_writable(parent):
            continue
        parent.mkdir(parents=True, exist_ok=True)
        dest = parent / GNU_DISASSEMBLER_EXTENSION_NAME
        if dest.exists():
            shutil.rmtree(dest)
        ignore = shutil.ignore_patterns(
            ".git",
            ".gradle",
            "build",
            "dist",
            f"{GNU_DISASSEMBLER_BINUTILS}.tar.bz2",
        )
        shutil.copytree(module, dest, ignore=ignore)
        native_dir = dest / "os" / platform_name
        native_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(gdis, native_dir / "gdis")
        (native_dir / "gdis").chmod(0o755)
        installed_dirs.append(str(dest))
    _patch_installed_extension_properties(
        GNU_DISASSEMBLER_EXTENSION_NAME,
        version=ghidra_version,
        description="GNU Disassembler provider built for macOS. Depends on SleighDevTools.",
    )
    return {"installed_dirs": installed_dirs}


def _record_extension_state(extension_name: str, method: str, installed_dirs: list[str]) -> None:
    state = _plugins_state()
    state[extension_name] = {
        "installed_method": method,
        "ghidra_version": _ghidra_application_version(),
        "installed_dirs": installed_dirs,
    }
    _write_plugins_state(state)


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
        "installed_version": _extension_version(GHIDRA_APPLE_EXTENSION_NAME),
        "compatible": _is_compatible_installed(GHIDRA_APPLE_EXTENSION_NAME),
        "installed_dirs": entry.get("installed_dirs", []),
    })

    for extension_name in [SLEIGH_DEV_TOOLS_EXTENSION_NAME, GNU_DISASSEMBLER_EXTENSION_NAME]:
        entry = state.get(extension_name, {})
        plugin = {
            "name": extension_name,
            "installed": _is_installed(extension_name),
            "install_method": entry.get("installed_method"),
            "installed_version": _extension_version(extension_name),
            "compatible": _is_compatible_installed(extension_name),
            "installed_dirs": entry.get("installed_dirs", []),
        }
        if extension_name == GNU_DISASSEMBLER_EXTENSION_NAME:
            plugin.update(_gnu_disassembler_status_details())
        plugins.append(plugin)

    return {"plugins": plugins}
