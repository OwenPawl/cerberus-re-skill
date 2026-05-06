"""Shared notes management: add, sync, pull, status, remediate, open_shared."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from ghidra_re_skill.core.config import cfg
from ghidra_re_skill.core.subprocess_utils import find_tool, run, run_output
from ghidra_re_skill.core.utils import flag_enabled, load_json, utc_now, write_json


def _python() -> str:
    from ghidra_re_skill.core.subprocess_utils import find_python
    return find_python()


def _backend() -> Path:
    return cfg.notes_backend()


def _gh_authenticated() -> bool:
    gh = find_tool("gh")
    if not gh:
        return False
    try:
        result = run([gh, "auth", "status"], check=False, capture_output=True)
        return result.returncode == 0
    except Exception:
        return False


def _notes_enabled() -> bool:
    return flag_enabled(cfg.notes_enable_shared)


def _auto_sync_enabled() -> bool:
    return flag_enabled(cfg.notes_auto_sync)


def ensure_notes_dirs() -> None:
    cfg.notes_root.mkdir(parents=True, exist_ok=True)
    cfg.notes_queue_dir.mkdir(parents=True, exist_ok=True)
    cfg.notes_cache_dir.mkdir(parents=True, exist_ok=True)


def init_files() -> None:
    """Ensure all notes state/config/cache files exist."""
    ensure_notes_dirs()

    if not cfg.notes_config_file.exists():
        issue_number = cfg.notes_issue_number
        payload = {
            "version": 1,
            "repo": cfg.notes_repo,
            "issue_title": cfg.notes_issue_title,
            "issue_number": issue_number,
            "issue_url": (
                f"https://github.com/{cfg.notes_repo}/issues/{issue_number}"
                if issue_number
                else ""
            ),
            "enabled": _notes_enabled(),
            "auto_sync": _auto_sync_enabled(),
        }
        write_json(cfg.notes_config_file, payload)

    if not cfg.notes_state_file.exists():
        write_json(
            cfg.notes_state_file,
            {
                "version": 1,
                "last_sync_at": "",
                "last_pull_at": "",
                "last_error": "",
                "pending_queue_count": 0,
                "issue_url": "",
                "issue_number": "",
            },
        )

    if not cfg.notes_cache_json.exists():
        write_json(cfg.notes_cache_json, {"version": 1, "notes": [], "recently_seen": []})

    if not cfg.notes_cache_md.exists():
        cfg.notes_cache_md.write_text(
            "# Shared Use-Case Notes\n\nNo shared notes have been pulled yet.\n",
            encoding="utf-8",
        )


def add(
    title: str,
    body: str,
    category: str = "workflow",
    target: str = "",
    mission_name: str = "",
    project_name: str = "",
    program_name: str = "",
    program_path: str = "",
    context_mode: str = "",
    platform: str = "",
    status: str = "open",
) -> dict:
    """Add a shared note."""
    if not title or not body:
        raise ValueError("title and body are required")

    init_files()

    platform_value = platform or cfg.platform
    skill_version = _get_skill_version()

    session_metadata = {
        "mission_name": mission_name,
        "project_name": project_name,
        "program_name": program_name,
        "program_path": program_path,
        "context_mode": context_mode,
        "session_id": "",
    }

    if not target and project_name and program_name:
        target = f"{project_name}:{program_name}"

    py = _python()
    result = run(
        [
            py, str(_backend()), "add",
            "--config-file", str(cfg.notes_config_file),
            "--state-file", str(cfg.notes_state_file),
            "--queue-dir", str(cfg.notes_queue_dir),
            "--event-kind", "observe",
            "--title", title,
            "--body", body,
            "--category", category,
            "--target", target,
            "--platform", platform_value,
            "--skill-version", skill_version,
            "--status", status,
            "--session-metadata-json", json.dumps(session_metadata),
        ],
        capture_output=True,
        check=True,
    )

    added = json.loads(result.stdout.decode())

    # Auto-sync if configured
    if _notes_enabled() and _auto_sync_enabled() and _gh_authenticated():
        try:
            sync_result = sync()
            added["synced"] = True
            added["sync"] = sync_result
        except Exception:
            added["synced"] = False
            added["warning"] = "note queued locally but auto-sync failed"
    else:
        added["synced"] = False

    return added


def sync() -> dict:
    """Push queued notes to the GitHub issue and pull the latest state."""
    init_files()
    if not _gh_authenticated():
        raise RuntimeError("GitHub CLI is not authenticated; run gh auth login first")
    py = _python()
    result = run(
        [
            py, str(_backend()), "sync",
            "--config-file", str(cfg.notes_config_file),
            "--state-file", str(cfg.notes_state_file),
            "--queue-dir", str(cfg.notes_queue_dir),
            "--cache-json", str(cfg.notes_cache_json),
            "--cache-md", str(cfg.notes_cache_md),
        ],
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout.decode())


def pull() -> dict:
    """Pull the latest shared notes from GitHub."""
    init_files()
    if not _gh_authenticated():
        raise RuntimeError("GitHub CLI is not authenticated; run gh auth login first")
    py = _python()
    result = run(
        [
            py, str(_backend()), "pull",
            "--config-file", str(cfg.notes_config_file),
            "--state-file", str(cfg.notes_state_file),
            "--cache-json", str(cfg.notes_cache_json),
            "--cache-md", str(cfg.notes_cache_md),
        ],
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout.decode())


def notes_status() -> dict:
    """Return the current notes status."""
    init_files()
    py = _python()
    result = run(
        [
            py, str(_backend()), "status",
            "--config-file", str(cfg.notes_config_file),
            "--state-file", str(cfg.notes_state_file),
            "--queue-dir", str(cfg.notes_queue_dir),
            "--cache-json", str(cfg.notes_cache_json),
            "--cache-md", str(cfg.notes_cache_md),
        ],
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout.decode())


def remediate(note_id: str, resolution: str = "", comment: str = "") -> dict:
    """Mark a note as remediated."""
    init_files()
    py = _python()
    skill_version = _get_skill_version()
    cmd = [
        py, str(_backend()), "remediate",
        "--config-file", str(cfg.notes_config_file),
        "--state-file", str(cfg.notes_state_file),
        "--queue-dir", str(cfg.notes_queue_dir),
        "--note-id", note_id,
        "--platform", cfg.platform,
        "--skill-version", skill_version,
    ]
    if resolution:
        cmd.extend(["--resolution", resolution])
    if comment:
        cmd.extend(["--comment", comment])
    result = run(cmd, capture_output=True, check=True)
    return json.loads(result.stdout.decode())


def open_shared(*, browse: bool = True) -> str:
    """Return the shared notes issue URL, optionally opening it."""
    init_files()
    config = load_json(cfg.notes_config_file, {})
    url = config.get("issue_url", "")
    if not url and cfg.notes_issue_number:
        url = f"https://github.com/{cfg.notes_repo}/issues/{cfg.notes_issue_number}"
    if not url:
        raise RuntimeError("shared notes issue URL not configured")
    if browse:
        import webbrowser
        webbrowser.open(url)
    return url


def _get_skill_version() -> str:
    skill_root = cfg.skill_root
    if (skill_root / ".git").exists():
        try:
            out = subprocess.check_output(
                ["git", "-C", str(skill_root), "rev-parse", "--short", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            return out.strip() or "unknown"
        except Exception:
            pass
    return "unknown"
