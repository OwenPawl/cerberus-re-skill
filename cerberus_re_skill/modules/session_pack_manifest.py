"""Reusable RE session pack manifests and reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.utils import utc_now


SESSION_PACK_SCHEMA = "ghidra-re.re-session-pack.v1"
SESSION_PACK_REPORT_SCHEMA = "ghidra-re.re-session-pack-report.v1"

ARTIFACT_KINDS = {
    "static",
    "runtime",
    "runtime-status",
    "trigger-attempt",
    "trigger-attempt-index",
    "breakpoint-plan-preflight",
    "nil-selector-triage",
    "frida-capture-plan",
    "frida-diagnostics",
    "instrumentation",
    "objc-method-shape",
    "private-api",
    "friction",
    "report",
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
}

SECTION_FOR_KIND = {
    "static": ["static_evidence"],
    "runtime": ["runtime_evidence"],
    "runtime-status": ["runtime_evidence"],
    "trigger-attempt": ["runtime_evidence", "next_framework_work"],
    "trigger-attempt-index": ["runtime_evidence", "next_framework_work"],
    "breakpoint-plan-preflight": ["static_evidence", "runtime_evidence", "framework_friction", "next_framework_work"],
    "nil-selector-triage": ["static_evidence", "runtime_evidence", "framework_friction", "next_framework_work"],
    "frida-capture-plan": ["instrumentation_evidence", "framework_friction", "next_framework_work"],
    "frida-diagnostics": ["instrumentation_evidence", "framework_friction", "next_framework_work"],
    "instrumentation": ["instrumentation_evidence"],
    "objc-method-shape": ["static_evidence", "runtime_evidence", "next_framework_work"],
    "private-api": ["private_api_invocation_evidence"],
    "friction": ["framework_friction"],
    "report": ["analysis_findings"],
    "xpc-surface": ["static_evidence"],
    "xpc-graph": ["static_evidence"],
    "xpc-interface-dossier": ["static_evidence", "next_framework_work"],
    "xpc-interface-factory": ["static_evidence", "next_framework_work"],
    "xpc-method-inventory": ["static_evidence", "next_framework_work"],
    "xpc-safe-read-dossier": ["static_evidence", "runtime_evidence", "next_framework_work"],
    "xpc-allowed-class-focus": ["static_evidence", "runtime_evidence", "framework_friction", "next_framework_work"],
    "xpc-completion-shapes": ["static_evidence", "runtime_evidence", "next_framework_work"],
    "nsxpc-interface-config": ["static_evidence", "next_framework_work"],
    "xpc-connection-evidence": ["runtime_evidence", "framework_friction", "next_framework_work"],
}


def default_session_pack_manifest() -> dict[str, Any]:
    """Return the public default RE session pack template."""
    return {
        "schema": SESSION_PACK_SCHEMA,
        "created_at": utc_now(),
        "name": "apple-re-session-pack",
        "goal": (
            "Correlate static Apple binary exports with LLDB/Frida runtime evidence "
            "and controlled private-API harnesses."
        ),
        "targets": [
            {
                "id": "primary",
                "kind": "framework-or-binary",
                "project": "primary_analysis",
                "program": "PrimaryBinary",
                "path_candidates": [
                    "/path/to/PrimaryBinary",
                    "source:macos:/System/Library/PrivateFrameworks/Example.framework/Example",
                ],
                "static_checks": [
                    "export apple-bundle",
                    "export xpc-surface",
                    "export function-dossier for the selected selector or symbol",
                ],
                "runtime_checks": [
                    "lldb trace the selected selector or symbol in an owned host",
                    "frida recheck-attach in a controlled harness with --allow-runtime",
                ],
            },
            {
                "id": "related-service",
                "kind": "xpc-service-or-helper",
                "project": "related_service_analysis",
                "program": "RelatedService",
                "path_candidates": [
                    "/path/to/RelatedService",
                    "source:macos:/System/Library/PrivateFrameworks/Example.framework/XPCServices/ExampleService.xpc/Contents/MacOS/ExampleService",
                ],
                "static_checks": [
                    "export apple-bundle",
                    "export xpc-surface",
                    "export xpc-graph with the primary target",
                ],
                "runtime_checks": [
                    "classify attach/launch blockers without treating them as hidden failures",
                ],
            },
            {
                "id": "owned-host",
                "kind": "controlled-harness",
                "project": "",
                "program": "owned_host",
                "path_candidates": [
                    "run-dir:owned_host",
                ],
                "static_checks": [
                    "compile harness",
                    "record invoked class/symbol, input object shape, and result/error",
                ],
                "runtime_checks": [
                    "frida recheck-attach --target owned_host --capture-returns",
                ],
            },
        ],
        "seeds": [
            "selector:<selected selector>",
            "symbol:<selected symbol>",
            "string:com.apple.example.service",
            "xpc:com.apple.example.service",
        ],
        "report_sections": [
            "target_inventory",
            "static_evidence",
            "runtime_evidence",
            "instrumentation_evidence",
            "private_api_invocation_evidence",
            "framework_friction",
            "analysis_findings",
            "next_framework_work",
        ],
        "success_criteria": [
            "At least one static export or existing export reference is recorded for the primary target.",
            "At least one runtime or instrumentation artifact is recorded as runtime_hits.json.",
            "Private API invocation evidence includes class, selector, input object, and result/error.",
            "Framework friction is separated from target behavior findings.",
        ],
    }


def write_default_session_pack_manifest(path: str | Path) -> dict[str, Any]:
    manifest = default_session_pack_manifest()
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "manifest": str(out), "schema": manifest["schema"], "targets": len(manifest["targets"])}
