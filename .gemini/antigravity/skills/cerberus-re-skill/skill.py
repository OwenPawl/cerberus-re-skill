"""Gemini antigravity skill implementation for cerberus-re-skill.

Technical notes (see cerberus_re_skill/ package for implementation):
- Bridge XML patching uses xml.etree.ElementTree — not regex — for robust, idempotent
  patching of Ghidra tool config files (.tcd / FrontEndTool.xml).
- The bridge-current.lock directory lock has stale-lock detection: if the lock is older
  than 30 s (st_mtime), it is removed automatically to prevent hangs after a crash.
- Windows process liveness check uses PROCESS_QUERY_LIMITED_INFORMATION (0x1000) +
  GetExitCodeProcess (expected value 259 / STILL_ACTIVE); handle is closed in a finally.
- Share-package installs use shutil.copytree with an ignore callback; backup paths are
  removed before move to prevent nesting like ghidra-re.backup-TS/ghidra-re.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def run_command(command: str, args: dict[str, Any] | None = None) -> Any:
    """Dispatch a ghidra-re command and return the result.

    This is the primary entry point called by the Gemini antigravity host.
    All commands delegate to the cerberus_re_skill Python package.
    """
    args = args or {}

    if command == "bootstrap":
        from cerberus_re_skill.core.ghidra_locator import detect_ghidra_dir, detect_jdk_dir
        from cerberus_re_skill.core.config import cfg
        ghidra = detect_ghidra_dir()
        jdk = detect_jdk_dir()
        return {
            "detected_ghidra": str(ghidra) if ghidra else None,
            "detected_jdk": str(jdk) if jdk else None,
            "config_home": str(cfg.config_home),
            "workspace": str(cfg.workspace),
        }

    if command == "install":
        from cerberus_re_skill.modules.publisher import install_skill
        from pathlib import Path
        installed = install_skill(
            host=args.get("host", "auto"),
            source_dir=Path(args["source"]) if args.get("source") else None,
            run_bootstrap=not args.get("no_bootstrap", False),
            skip_smoke_test=args.get("skip_smoke_test", False),
            skip_bridge_install=args.get("skip_bridge_install", False),
        )
        return {"installed": [str(p) for p in installed]}

    if command == "doctor":
        from cerberus_re_skill.core.ghidra_locator import (
            detect_ghidra_dir, detect_jdk_dir, is_valid_ghidra_dir, is_valid_jdk_dir
        )
        from cerberus_re_skill.core.config import cfg
        from cerberus_re_skill.core.subprocess_utils import find_tool
        return {
            "platform": cfg.platform,
            "ghidra_valid": is_valid_ghidra_dir(cfg.ghidra_install_dir),
            "jdk_valid": is_valid_jdk_dir(cfg.ghidra_jdk),
            "detected_ghidra": str(detect_ghidra_dir() or ""),
            "detected_jdk": str(detect_jdk_dir() or ""),
            "python": sys.executable,
            "gh_cli": find_tool("gh"),
        }

    if command == "bridge.arm":
        from cerberus_re_skill.modules.bridge import arm
        return arm(args["project"], args.get("program", ""))

    if command == "bridge.disarm":
        from cerberus_re_skill.modules.bridge import disarm
        return disarm(
            args.get("session", ""),
            args.get("project", ""),
            args.get("program", ""),
        )

    if command == "bridge.call":
        from cerberus_re_skill.modules.bridge import call_bridge
        return call_bridge(
            args["endpoint"],
            args.get("body", {}),
        )

    if command == "bridge.status":
        from cerberus_re_skill.modules.bridge import bridge_status
        return bridge_status(args.get("body", {}))

    if command == "bridge.sessions":
        from cerberus_re_skill.modules.bridge import list_sessions
        return list_sessions()

    if command == "bridge.build":
        from cerberus_re_skill.modules.bridge import build
        path = build()
        return {"zip_path": str(path)}

    if command == "bridge.install":
        from cerberus_re_skill.modules.bridge import install
        return install()

    if command == "notes.add":
        from cerberus_re_skill.modules.notes import add
        return add(
            title=args["title"],
            body=args["body"],
            category=args.get("category", "workflow"),
            target=args.get("target", ""),
            mission_name=args.get("mission", ""),
            project_name=args.get("project", ""),
            program_name=args.get("program", ""),
            status=args.get("status", "open"),
        )

    if command == "notes.sync":
        from cerberus_re_skill.modules.notes import sync
        return sync()

    if command == "notes.pull":
        from cerberus_re_skill.modules.notes import pull
        return pull()

    if command == "notes.status":
        from cerberus_re_skill.modules.notes import notes_status
        return notes_status()

    if command == "import.analyze":
        from cerberus_re_skill.modules.importer import import_analyze
        return import_analyze(args["binary"], args.get("project"))

    if command == "import.macos_framework":
        from cerberus_re_skill.modules.importer import import_macos_framework
        return import_macos_framework(args["framework"], args.get("project"))

    if command == "import.run_script":
        from cerberus_re_skill.modules.importer import run_script
        return run_script(
            args["script"],
            args["project"],
            args.get("program"),
            args.get("script_args"),
        )

    raise ValueError(f"unknown command: {command!r}")


if __name__ == "__main__":
    # Simple CLI shim: skill.py <command> [json_args]
    if len(sys.argv) < 2:
        print("Usage: skill.py <command> [json_args]", file=sys.stderr)
        sys.exit(1)
    cmd = sys.argv[1]
    a = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    result = run_command(cmd, a)
    print(json.dumps(result, indent=2, default=str))
