"""Central configuration object derived from environment variables and config files."""

from __future__ import annotations

import os
from pathlib import Path

from ghidra_re_skill.core.platform_helpers import (
    get_config_home,
    get_platform,
    get_skill_root,
    get_workspace_root,
)


_CONFIG_FILE_VALUES: dict[str, str] = {}


def _load_config_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key) or _CONFIG_FILE_VALUES.get(key, default)


def _flag(key: str, default: str = "1") -> str:
    return os.environ.get(key, default)


class Config:
    """Centralised runtime configuration.

    Values are read from environment variables (mirroring common.sh) with
    sensible defaults. Load once per process, or call :meth:`reload` to
    pick up environment changes.
    """

    def __init__(self) -> None:
        self.reload()

    def reload(self) -> None:
        platform = get_platform()
        config_home = Path(os.environ.get("GHIDRA_RE_CONFIG_HOME", str(get_config_home())))
        global _CONFIG_FILE_VALUES
        _CONFIG_FILE_VALUES = _load_config_env(config_home / "config.env")
        skill_root = get_skill_root()
        workspace = get_workspace_root()

        self.platform: str = _env("GHIDRA_RE_PLATFORM", platform)
        self.config_home: Path = Path(_env("GHIDRA_RE_CONFIG_HOME", str(config_home)))
        self.skill_root: Path = Path(_env("GHIDRA_RE_ROOT", str(skill_root)))

        # Workspace dirs
        self.workspace: Path = Path(_env("GHIDRA_WORKSPACE", str(workspace)))
        self.projects_dir: Path = Path(_env("GHIDRA_PROJECTS_DIR", str(self.workspace / "projects")))
        self.exports_dir: Path = Path(_env("GHIDRA_EXPORTS_DIR", str(self.workspace / "exports")))
        self.logs_dir: Path = Path(_env("GHIDRA_LOGS_DIR", str(self.workspace / "logs")))
        self.investigations_dir: Path = Path(
            _env("GHIDRA_INVESTIGATIONS_DIR", str(self.workspace / "investigations"))
        )
        self.sources_cache_dir: Path = Path(
            _env("GHIDRA_SOURCES_CACHE_DIR", str(self.workspace / "sources"))
        )

        # Ghidra tool paths (populated by ghidra_locator at runtime)
        _default_ghidra = self._default_ghidra_install()
        _default_jdk = self._default_jdk()
        self.ghidra_install_dir: Path = Path(
            _env("GHIDRA_INSTALL_DIR", _default_ghidra)
        )
        self.ghidra_jdk: Path = Path(_env("GHIDRA_JDK", _default_jdk))

        self.custom_scripts_dir: Path = Path(
            _env(
                "GHIDRA_CUSTOM_SCRIPTS_DIR",
                str(self.skill_root / "scripts" / "ghidra_scripts"),
            )
        )
        self.templates_dir: Path = Path(
            _env("GHIDRA_TEMPLATES_DIR", str(self.skill_root / "templates"))
        )
        self.bug_hunt_manifest: Path = Path(
            _env(
                "GHIDRA_RE_BUG_HUNT_MANIFEST",
                str(self.skill_root / "references" / "bug-hunt-patterns.json"),
            )
        )

        # Bridge dirs
        bridge_ext_dir = self.skill_root / "bridge-extension" / "CodexGhidraBridge"
        self.bridge_extension_dir: Path = Path(
            _env("GHIDRA_RE_BRIDGE_EXTENSION_DIR", str(bridge_ext_dir))
        )
        self.bridge_dist_dir: Path = Path(
            _env("GHIDRA_RE_BRIDGE_DIST_DIR", str(self.bridge_extension_dir / "dist"))
        )
        self.bridge_config_dir: Path = Path(
            _env("GHIDRA_RE_BRIDGE_CONFIG_DIR", str(self.config_home))
        )
        self.bridge_sessions_dir: Path = Path(
            _env("GHIDRA_RE_BRIDGE_SESSIONS_DIR", str(self.bridge_config_dir / "bridge-sessions"))
        )
        self.bridge_requests_dir: Path = Path(
            _env("GHIDRA_RE_BRIDGE_REQUESTS_DIR", str(self.bridge_config_dir / "bridge-requests"))
        )
        self.bridge_current_file: Path = Path(
            _env("GHIDRA_RE_BRIDGE_CURRENT_FILE", str(self.bridge_config_dir / "bridge-current.json"))
        )
        self.bridge_legacy_session_file: Path = Path(
            _env(
                "GHIDRA_RE_BRIDGE_LEGACY_SESSION_FILE",
                str(self.bridge_config_dir / "bridge-session.json"),
            )
        )
        self.bridge_legacy_control_file: Path = Path(
            _env(
                "GHIDRA_RE_BRIDGE_LEGACY_CONTROL_FILE",
                str(self.bridge_config_dir / "bridge-control.json"),
            )
        )
        self.bridge_install_state_file: Path = Path(
            _env(
                "GHIDRA_RE_BRIDGE_INSTALL_STATE_FILE",
                str(self.bridge_config_dir / "bridge-install-state.json"),
            )
        )

        # Source registry
        self.source_registry_file: Path = Path(
            _env("GHIDRA_RE_SOURCE_REGISTRY_FILE", str(self.config_home / "sources.json"))
        )

        # Notes
        self.notes_enable_shared: str = _flag("GHIDRA_NOTES_ENABLE_SHARED", "1")
        self.notes_auto_sync: str = _flag("GHIDRA_NOTES_AUTO_SYNC", "1")
        self.notes_repo: str = _env("GHIDRA_NOTES_REPO", "OwenPawl/ghidra-re-skill")
        self.notes_issue_title: str = _env("GHIDRA_NOTES_ISSUE_TITLE", "Global Use-Case Driven Notes")
        self.notes_issue_number: str = _env("GHIDRA_NOTES_ISSUE_NUMBER", "5")
        notes_root = self.config_home / "shared-notes"
        self.notes_root: Path = Path(_env("GHIDRA_NOTES_ROOT", str(notes_root)))
        self.notes_config_file: Path = Path(
            _env("GHIDRA_NOTES_CONFIG_FILE", str(self.notes_root / "config.json"))
        )
        self.notes_queue_dir: Path = Path(
            _env("GHIDRA_NOTES_QUEUE_DIR", str(self.notes_root / "queue"))
        )
        self.notes_cache_dir: Path = Path(
            _env("GHIDRA_NOTES_CACHE_DIR", str(self.notes_root / "cache"))
        )
        self.notes_state_file: Path = Path(
            _env("GHIDRA_NOTES_STATE_FILE", str(self.notes_root / "state.json"))
        )
        self.notes_cache_json: Path = Path(
            _env("GHIDRA_NOTES_CACHE_JSON", str(self.notes_cache_dir / "notes.json"))
        )
        self.notes_cache_md: Path = Path(
            _env("GHIDRA_NOTES_CACHE_MD", str(self.notes_cache_dir / "issue.md"))
        )

        # Import flags
        self.import_demangle: str = _flag("GHIDRA_IMPORT_DEMANGLE", "1")
        self.analysis_timeout_per_file: str = _env("GHIDRA_ANALYSIS_TIMEOUT_PER_FILE", "")
        self.max_cpu: str = _env("GHIDRA_MAX_CPU", "")

        # Headless script dirs (rebuilt after ghidra dir is resolved)
        self._refresh_script_dirs()

    def _default_ghidra_install(self) -> str:
        if self.platform == "macos":
            return "/Applications/Ghidra"
        if self.platform == "windows":
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                return str(Path(local_app_data) / "Programs" / "Ghidra")
            return str(Path.home() / "AppData" / "Local" / "Programs" / "Ghidra")
        return "/opt/ghidra"

    def _default_jdk(self) -> str:
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            return java_home
        if self.platform == "macos":
            return "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
        if self.platform == "windows":
            return "C:/Program Files/Eclipse Adoptium/jdk-21"
        return "/usr/lib/jvm/default-java"

    def _refresh_script_dirs(self) -> None:
        ghidra = str(self.ghidra_install_dir)
        self.default_script_dirs: list[Path] = [
            self.custom_scripts_dir,
            Path(ghidra) / "Ghidra" / "Features" / "Base" / "ghidra_scripts",
            Path(ghidra) / "Ghidra" / "Features" / "Decompiler" / "ghidra_scripts",
            Path(ghidra) / "Ghidra" / "Features" / "PyGhidra" / "ghidra_scripts",
            Path(ghidra) / "Ghidra" / "Features" / "SwiftDemangler" / "ghidra_scripts",
            Path(ghidra) / "Ghidra" / "Features" / "Jython" / "ghidra_scripts",
        ]

    def script_path_str(self, extra: list[Path] | None = None) -> str:
        """Return a semicolon-joined script path string for analyzeHeadless."""
        dirs = list(self.default_script_dirs)
        if extra:
            dirs.extend(extra)
        return ";".join(str(d) for d in dirs if d)

    def project_location(self, project_name: str) -> Path:
        return self.projects_dir / project_name

    def project_file(self, project_name: str) -> Path:
        return self.projects_dir / project_name / f"{project_name}.gpr"

    def log_dir(self, project_name: str) -> Path:
        return self.logs_dir / project_name

    def export_dir(self, project_name: str, program_name: str) -> Path:
        return self.exports_dir / project_name / program_name

    def investigation_dir(self, mission_name: str) -> Path:
        from ghidra_re_skill.core.utils import sanitize_name

        return self.investigations_dir / sanitize_name(mission_name)

    def notes_backend(self) -> Path:
        return self.skill_root / "scripts" / "ghidra_notes_backend.py"

    def mission_backend(self) -> Path:
        return self.skill_root / "scripts" / "ghidra_mission_backend.py"


# Module-level singleton; callers import and use `cfg`.
cfg = Config()
