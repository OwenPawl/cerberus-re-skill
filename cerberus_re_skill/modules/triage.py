"""Triage bundle and function dossier orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import sanitize_name


def export_triage_bundle(
    project: str,
    program: str,
    *,
    output_dir: str | Path | None = None,
    manifest: str | Path | None = None,
    sample_limit: int = 20,
    max_depth: int = 4,
    max_visited_functions: int = 1500,
    top_candidates: int = 50,
    xref_limit: int = 25,
    entrypoint_limit: int = 40,
) -> dict[str, Any]:
    """Run the triage export scripts and return a compact output manifest."""
    from cerberus_re_skill.modules.importer import run_script

    manifest_path = _manifest_path(manifest)
    bundle_dir = Path(output_dir) if output_dir else cfg.export_dir(project, program) / "triage"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    entrypoints = bundle_dir / "entrypoints.json"
    sinks = bundle_dir / "sinks.json"
    candidates = bundle_dir / "candidate_paths.json"
    summary = bundle_dir / "summary.md"

    steps = [
        run_script(
            "ExportEntrypoints.java",
            project,
            program,
            [f"manifest={manifest_path}", f"output={entrypoints}", f"sample_limit={sample_limit}"],
        ),
        run_script(
            "ExportSinks.java",
            project,
            program,
            [f"manifest={manifest_path}", f"output={sinks}", f"sample_limit={sample_limit}"],
        ),
        run_script(
            "TriagePaths.java",
            project,
            program,
            [
                f"manifest={manifest_path}",
                f"output={candidates}",
                f"summary={summary}",
                f"max_depth={max_depth}",
                f"max_visited_functions={max_visited_functions}",
                f"top_candidates={top_candidates}",
                f"xref_limit={xref_limit}",
                f"entrypoint_limit={entrypoint_limit}",
            ],
        ),
    ]

    entrypoint_match_count = _json_count(entrypoints, "entrypoint_count")
    sink_match_count = _json_count(sinks, "sink_count")
    counts = {
        # Legacy aliases kept for callers that consumed the original script keys.
        "entrypoint_count": entrypoint_match_count,
        "sink_count": sink_match_count,
        "candidate_count": _json_count(candidates, "candidate_count"),
        "entrypoint_match_count": entrypoint_match_count,
        "sink_match_count": sink_match_count,
        "triage_entrypoints_considered": _json_count(candidates, "entrypoints_considered"),
        "triage_sink_function_count": _json_count(candidates, "sink_function_count"),
    }
    return {
        "ok": True,
        "project_name": project,
        "program_name": program,
        "manifest": str(manifest_path),
        "output_dir": str(bundle_dir),
        "outputs": {
            "entrypoints": str(entrypoints),
            "sinks": str(sinks),
            "candidate_paths": str(candidates),
            "summary": str(summary),
        },
        "artifact_status": _artifact_status([entrypoints, sinks, candidates, summary]),
        "counts": counts,
        "steps": steps,
    }


def export_function_dossier(
    project: str,
    program: str,
    *,
    function: str = "",
    address: str = "",
    output_dir: str | Path | None = None,
    manifest: str | Path | None = None,
    sample_limit: int = 25,
    linear_instruction_limit: int = 96,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run ExportFunctionDossier.java for a function name or entry address."""
    from cerberus_re_skill.modules.importer import run_script

    if not function and not address:
        raise RuntimeError("either function or address is required")

    manifest_path = _manifest_path(manifest)
    target_label = function or address
    dossier_dir = (
        Path(output_dir)
        if output_dir
        else cfg.export_dir(project, program) / "dossiers" / sanitize_name(target_label)
    )
    dossier_dir.mkdir(parents=True, exist_ok=True)

    script_args = [
        f"manifest={manifest_path}",
        f"output_dir={dossier_dir}",
        f"sample_limit={sample_limit}",
        f"linear_instruction_limit={linear_instruction_limit}",
        f"timeout={timeout}",
    ]
    if function:
        script_args.append(f"function={function}")
    if address:
        script_args.append(f"address={address}")

    step = run_script("ExportFunctionDossier.java", project, program, script_args)
    artifact_paths = [
        dossier_dir / "context.json",
        dossier_dir / "decompile.c",
        dossier_dir / "linear_instructions.txt",
        dossier_dir / "summary.md",
    ]
    artifact_status = _artifact_status(artifact_paths)
    missing_artifacts = [
        name
        for name, status in artifact_status.items()
        if not status["exists"] or int(status["byte_size"]) == 0
    ]
    ok = not missing_artifacts
    return {
        "ok": ok,
        "project_name": project,
        "program_name": program,
        "manifest": str(manifest_path),
        "target": {"function": function, "address": address},
        "output_dir": str(dossier_dir),
        "outputs": {
            "context": str(dossier_dir / "context.json"),
            "decompile": str(dossier_dir / "decompile.c"),
            "linear_instructions": str(dossier_dir / "linear_instructions.txt"),
            "summary": str(dossier_dir / "summary.md"),
        },
        "artifact_status": artifact_status,
        "missing_artifacts": missing_artifacts,
        "failure_reason": f"function dossier script did not produce required artifacts: {', '.join(missing_artifacts)}" if missing_artifacts else "",
        "step": step,
    }


def _manifest_path(manifest: str | Path | None) -> Path:
    path = Path(manifest) if manifest else cfg.triage_manifest
    if not path.exists():
        raise RuntimeError(f"triage manifest not found: {path}")
    return path


def _json_count(path: Path, key: str) -> int:
    if not path.exists():
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    value = payload.get(key, 0)
    return int(value) if isinstance(value, int) else 0


def _artifact_status(paths: list[Path]) -> dict[str, dict[str, int | bool | str]]:
    status: dict[str, dict[str, int | bool | str]] = {}
    for path in paths:
        exists = path.exists()
        status[path.name] = {
            "path": str(path),
            "exists": exists,
            "byte_size": path.stat().st_size if exists else 0,
        }
    return status
