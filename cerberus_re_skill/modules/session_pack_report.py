"""Session-pack validation and report assembly."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.utils import utc_now
from cerberus_re_skill.modules.session_pack_manifest import (
    ARTIFACT_KINDS,
    SECTION_FOR_KIND,
    SESSION_PACK_REPORT_SCHEMA,
    SESSION_PACK_SCHEMA,
)
from cerberus_re_skill.modules.session_pack_render import _load_json, _render_markdown
from cerberus_re_skill.modules.session_pack_sections import (
    _finding_summaries,
    _friction,
    _has_classified_private_api_runtime_evidence,
    _has_private_api_invocation_evidence,
    _next_work,
    _target_inventory,
)
from cerberus_re_skill.modules.session_pack_summary import _artifact_summary

ARTIFACT_KIND_ALIASES = {
    "frida": "instrumentation",
    "frida-recheck": "instrumentation",
    "ghidra": "static",
    "ghidra-static": "static",
    "lldb": "runtime-status",
    "runtime-hits": "runtime",
}


def render_session_pack_report(
    manifest_path: str | Path,
    *,
    artifacts: list[str] | None = None,
    output_dir: str | Path | None = None,
    report_name: str = "re-session-pack-report",
) -> dict[str, Any]:
    """Render a session-pack report from a manifest and artifacts."""
    manifest_file = Path(manifest_path)
    manifest = _load_json(manifest_file, "session pack manifest")
    out_dir = Path(output_dir) if output_dir else manifest_file.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    validation = validate_session_pack(manifest, manifest_file=manifest_file, artifact_specs=artifacts or [])
    report = _build_report(manifest, manifest_file=manifest_file, validation=validation)
    json_path = out_dir / f"{report_name}.json"
    md_path = out_dir / f"{report_name}.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return {
        "ok": validation["ok"],
        "schema": SESSION_PACK_REPORT_SCHEMA,
        "report_json": str(json_path),
        "report_markdown": str(md_path),
        "artifact_count": len(validation["artifacts"]),
        "error_count": len(validation["errors"]),
        "warning_count": len(validation["warnings"]),
        "sections": sorted(report["sections"].keys()),
    }


def validate_session_pack(
    manifest: dict[str, Any],
    *,
    manifest_file: str | Path | None = None,
    artifact_specs: list[str] | None = None,
) -> dict[str, Any]:
    """Validate a session-pack manifest plus artifact references."""
    errors: list[str] = []
    warnings: list[str] = []
    if manifest.get("schema") != SESSION_PACK_SCHEMA:
        errors.append(f"unexpected manifest schema: {manifest.get('schema')!r}")
    targets = manifest.get("targets", [])
    if not isinstance(targets, list) or not targets:
        errors.append("manifest must define at least one target")
        targets = []
    target_ids = {str(t.get("id", "")) for t in targets if isinstance(t, dict) and t.get("id")}
    report_sections = manifest.get("report_sections", [])
    if not isinstance(report_sections, list):
        errors.append("manifest report_sections must be a list")
        report_sections = []
    for required in (
        "target_inventory",
        "static_evidence",
        "runtime_evidence",
        "instrumentation_evidence",
        "private_api_invocation_evidence",
        "framework_friction",
        "analysis_findings",
        "next_framework_work",
    ):
        if required not in report_sections:
            warnings.append(f"recommended report section missing: {required}")

    artifacts = [_artifact_from_spec(spec, target_ids) for spec in (artifact_specs or [])]
    for artifact in artifacts:
        errors.extend(artifact.pop("errors"))
        warnings.extend(artifact.pop("warnings"))

    if not any(
        a["exists"]
        and a["kind"]
        in {
            "static",
            "xpc-surface",
            "xpc-graph",
            "xpc-interface-dossier",
            "xpc-interface-factory",
            "xpc-method-inventory",
            "xpc-safe-read-dossier",
            "xpc-allowed-class-focus",
            "xpc-completion-shapes",
            "nsxpc-interface-config",
            "xpc-connection-evidence",
            "objc-method-shape",
        }
        for a in artifacts
    ):
        warnings.append("no static/XPC artifact was supplied")
    if not any(
        a["exists"]
        and a["kind"] in {
            "runtime",
            "runtime-status",
            "trigger-attempt",
            "trigger-attempt-index",
            "xpc-allowed-class-focus",
            "objc-method-shape",
        }
        for a in artifacts
    ):
        warnings.append("no runtime-hit artifact was supplied")
    if not any(
        a["exists"]
        and (_has_private_api_invocation_evidence(a) or _has_classified_private_api_runtime_evidence(a))
        for a in artifacts
    ):
        warnings.append("no private-API invocation or classified observe-only evidence was recognized")

    return {
        "ok": not errors,
        "manifest": str(manifest_file) if manifest_file else "",
        "target_ids": sorted(target_ids),
        "artifacts": artifacts,
        "errors": errors,
        "warnings": warnings,
    }


def _build_report(manifest: dict[str, Any], *, manifest_file: Path, validation: dict[str, Any]) -> dict[str, Any]:
    sections: dict[str, Any] = {
        "target_inventory": _target_inventory(manifest),
        "static_evidence": [],
        "runtime_evidence": [],
        "instrumentation_evidence": [],
        "private_api_invocation_evidence": [],
        "framework_friction": [],
        "analysis_findings": [],
        "next_framework_work": [],
    }
    for artifact in validation["artifacts"]:
        if not artifact["exists"]:
            sections["framework_friction"].append(_friction("missing_artifact", artifact["path"], artifact["target_id"]))
            continue
        record = {
            "target_id": artifact["target_id"],
            "kind": artifact["kind"],
            "path": artifact["path"],
            "schema": artifact.get("schema"),
            "summary": artifact["summary"],
        }
        for section in artifact["sections"]:
            sections.setdefault(section, []).append(record)
        if _has_private_api_invocation_evidence(artifact) and "private_api_invocation_evidence" not in artifact["sections"]:
            sections["private_api_invocation_evidence"].append(record)
        friction = artifact["summary"].get("friction")
        if friction:
            sections["framework_friction"].append({"target_id": artifact["target_id"], "path": artifact["path"], "items": friction})
        elif artifact["kind"] == "report" and artifact["summary"].get("mentions_friction"):
            sections["framework_friction"].append(
                {
                    "target_id": artifact["target_id"],
                    "path": artifact["path"],
                    "items": [{"kind": "friction_report_available"}],
                }
            )

    sections["analysis_findings"].extend(_finding_summaries(sections))
    sections["next_framework_work"].extend(_next_work(validation, sections))
    return {
        "schema": SESSION_PACK_REPORT_SCHEMA,
        "created_at": utc_now(),
        "manifest": str(manifest_file),
        "session_pack": {
            "schema": manifest.get("schema"),
            "name": manifest.get("name"),
            "goal": manifest.get("goal"),
            "success_criteria": manifest.get("success_criteria", []),
            "seeds": manifest.get("seeds", []),
        },
        "validation": validation,
        "sections": sections,
    }


def _artifact_from_spec(spec: str, target_ids: set[str]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    kind = ""
    target_id = ""
    path_text = ""
    parts = spec.split(":", 2)
    if len(parts) == 3 and (parts[0] in ARTIFACT_KINDS or parts[0] in ARTIFACT_KIND_ALIASES):
        kind, target_id, path_text = ARTIFACT_KIND_ALIASES.get(parts[0], parts[0]), parts[1], parts[2]
    elif "=" in spec:
        target_id, path_text = spec.split("=", 1)
    else:
        errors.append(f"artifact spec must be kind:target:path or target=path: {spec}")
        path_text = spec

    target_id = target_id.strip()
    path = Path(path_text).expanduser()
    payload: Any = None
    fmt = "missing"
    schema = None
    summary: dict[str, Any] = {}
    if target_id and target_id not in target_ids:
        errors.append(f"artifact references unknown target {target_id!r}: {spec}")
    if path.exists():
        if path.suffix.lower() == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                fmt = "json"
                schema = payload.get("schema") if isinstance(payload, dict) else None
            except json.JSONDecodeError as e:
                fmt = "json-error"
                errors.append(f"malformed JSON artifact {path}: {e}")
        else:
            fmt = "text"
            payload = path.read_text(encoding="utf-8", errors="replace")
    else:
        errors.append(f"artifact path does not exist: {path}")

    if not kind:
        kind = _infer_artifact_kind(path, payload)
    if kind not in ARTIFACT_KINDS:
        warnings.append(f"unknown artifact kind {kind!r}; treating as report")
        kind = "report"
    if payload is not None:
        summary = _artifact_summary(path, payload, kind=kind)
    return {
        "target_id": target_id,
        "kind": kind,
        "path": str(path),
        "exists": path.exists(),
        "format": fmt,
        "schema": schema,
        "sections": SECTION_FOR_KIND.get(kind, ["analysis_findings"]),
        "summary": summary,
        "errors": errors,
        "warnings": warnings,
    }


def _infer_artifact_kind(path: Path, payload: Any) -> str:
    name = path.name
    schema = payload.get("schema") if isinstance(payload, dict) else ""
    schema_version = payload.get("schema_version") if isinstance(payload, dict) else ""
    schema_text = str(schema or schema_version or "")
    if schema == "ghidra-re.runtime-hits.v1":
        return "runtime"
    if schema == "ghidra-re.lldb-trace-validation.v1" or name == "lldb-trace-validation.json":
        return "runtime-status"
    if schema == "ghidra-re.trigger-attempt.v1" or name.endswith("-trigger-attempt.json"):
        return "trigger-attempt"
    if schema == "ghidra-re.trigger-attempt-index.v1" or name in {"trigger_attempt_index.json", "trigger-attempt-index.json"}:
        return "trigger-attempt-index"
    if schema == "ghidra-re.breakpoint-plan-preflight.v1" or name in {
        "breakpoint_plan_preflight.json",
        "breakpoint-plan-preflight.json",
    }:
        return "breakpoint-plan-preflight"
    if schema == "ghidra-re.nil-selector-triage.v1" or name in {"nil_selector_triage.json", "nil-selector-triage.json"}:
        return "nil-selector-triage"
    if schema == "ghidra-re.frida-capture-plan.v1" or name in {"frida_capture_plan.json", "frida-capture-plan.json"}:
        return "frida-capture-plan"
    if schema == "ghidra-re.frida-diagnostics.v1" or name in {"frida-diagnostics.json"}:
        return "frida-diagnostics"
    if (
        str(schema).endswith(".method-shape.v1")
    ):
        return "objc-method-shape"
    if schema in {"ghidra-re.frida-runtime-recheck.v1", "ghidra-re.frida-live-attach.v1"} or name in {
        "frida-runtime-recheck.json",
        "frida-live-attach.json",
    }:
        return "instrumentation"
    if schema_text.endswith(".static-summary.v1"):
        return "static"
    if schema_text.endswith(".live-validation.v1"):
        return "runtime-status"
    if schema_text.endswith(".runtime-probe.v1"):
        return "runtime"
    if name in {"xpc_surface.json"} or name.endswith("-xpc-surface.json"):
        return "xpc-surface"
    if name in {"xpc_graph.json"} or name.endswith("-xpc-graph.json"):
        return "xpc-graph"
    if schema == "ghidra-re.xpc-interface-dossier.v1" or name in {"xpc_interface_dossier.json"} or name.endswith("-xpc-interface-dossier.json"):
        return "xpc-interface-dossier"
    if schema == "ghidra-re.xpc-interface-factory.v1" or name in {"xpc_interface_factory.json", "xpc-interface-factory.json"} or name.endswith("-xpc-interface-factory.json"):
        return "xpc-interface-factory"
    if schema == "ghidra-re.xpc-method-inventory.v1" or name in {"xpc_method_inventory.json"} or name.endswith("-xpc-method-inventory.json"):
        return "xpc-method-inventory"
    if schema == "ghidra-re.xpc-safe-read-dossier.v1" or name in {"xpc_safe_read_dossier.json", "xpc-safe-read-dossier.json"} or name.endswith("-xpc-safe-read-dossier.json"):
        return "xpc-safe-read-dossier"
    if schema == "ghidra-re.xpc-allowed-class-focus.v1" or name in {"xpc_allowed_class_focus.json", "xpc-allowed-class-focus.json"} or name.endswith("-xpc-allowed-class-focus.json"):
        return "xpc-allowed-class-focus"
    if schema == "ghidra-re.xpc-completion-shapes.v1" or name in {"xpc_completion_shapes.json", "xpc-completion-shapes.json"} or name.endswith("-xpc-completion-shapes.json"):
        return "xpc-completion-shapes"
    if schema == "ghidra-re.nsxpc-interface-config.v1" or name in {"nsxpc_interface_config.json"} or name.endswith("-nsxpc-interface-config.json"):
        return "nsxpc-interface-config"
    if schema == "ghidra-re.xpc-connection-evidence.v1" or name in {"xpc_connection_evidence.json"} or name.endswith("-xpc-connection-evidence.json"):
        return "xpc-connection-evidence"
    if name in {"function_inventory.json", "objc_metadata.json", "swift_outlined_resolved.json", "authstub_map.json"}:
        return "static"
    if path.suffix.lower() in {".md", ".txt", ".log"}:
        return "report"
    return "report"
