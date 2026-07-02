"""Swift outlined/authstub resolver orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


def resolve_swift_outlined(
    project: str,
    program: str,
    *,
    output_dir: str | Path | None = None,
    dry_run: bool = False,
    inline: bool = True,
    skip_stubs: bool = False,
    verbose: bool = False,
    scan_fun_stubs: bool = True,
    second_pass: bool = True,
    authstub_map: str | Path | None = None,
) -> dict[str, Any]:
    """Run ResolveSwiftOutlined.java and return its report with artifact status."""
    from cerberus_re_skill.modules.importer import run_script

    out_dir = Path(output_dir) if output_dir else cfg.export_dir(project, program)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "swift_outlined_resolved.json"

    script_args = [
        f"output_dir={out_dir}",
        f"dry_run={_bool_arg(dry_run)}",
        f"inline={_bool_arg(inline)}",
        f"skip_stubs={_bool_arg(skip_stubs)}",
        f"verbose={_bool_arg(verbose)}",
        f"scan_fun_stubs={_bool_arg(scan_fun_stubs)}",
        f"second_pass={_bool_arg(second_pass)}",
    ]
    if authstub_map:
        script_args.append(f"authstub_map={Path(authstub_map)}")

    step = run_script("ResolveSwiftOutlined.java", project, program, script_args=script_args)
    report = _read_report(report_path)
    return {
        "ok": True,
        "project_name": project,
        "program_name": program,
        "output_dir": str(out_dir),
        "report": str(report_path),
        "artifact_status": _artifact_status(report_path),
        "summary": {
            "dry_run": report.get("dry_run", dry_run),
            "total_outlined_functions": _int(report.get("total_outlined_functions")),
            "renamed": _int(report.get("renamed")),
            "inlined": _int(report.get("inlined")),
            "skipped_stubs": _int(report.get("skipped_stubs")),
            "pactail_updated_pass2": _int(report.get("pactail_updated_pass2")),
            "pactail_slot_resolved_pass3": _int(report.get("pactail_slot_resolved_pass3")),
            "categories": report.get("categories", {}),
        },
        "step": step,
    }


def _bool_arg(value: bool) -> str:
    return "true" if value else "false"


def _int(value: object) -> int:
    return value if isinstance(value, int) else 0


def _read_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _artifact_status(path: Path) -> dict[str, int | bool | str]:
    exists = path.exists()
    return {
        "path": str(path),
        "exists": exists,
        "byte_size": path.stat().st_size if exists else 0,
    }
