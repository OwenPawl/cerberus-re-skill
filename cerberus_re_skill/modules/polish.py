"""Release-polish checks for command surface and packaging drift."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import timestamp, utc_now
from cerberus_re_skill.modules.validation import validate_local


DOC_PATHS = [
    "README.md",
    "SKILL.md",
    "references/local-validation-matrix.md",
    "references/raw-bridge-recipes.md",
    "references/output-files.md",
]

REQUIRED_PACKAGE_FILES = [
    "README.md",
    "SKILL.md",
    "pyproject.toml",
    "cerberus_re_skill/cli.py",
    "cerberus_re_skill/modules/bridge.py",
    "cerberus_re_skill/modules/validation.py",
    "cerberus_re_skill/modules/lldb_validation.py",
    "cerberus_re_skill/modules/lldb_enrich.py",
    "cerberus_re_skill/modules/authstub_map.py",
    "bridge-extension/CodexGhidraBridge/build.gradle",
    "bridge-extension/CodexGhidraBridge/extension.properties",
    "bridge-extension/CodexGhidraBridge/ghidra_scripts/EnableCodexBridge.java",
    "bridge-extension/CodexGhidraBridge/src/main/java/codexghidrabridge/CodexBridgeService.java",
    "powershell/GhidraRe.psm1",
    "powershell/GhidraRe.psd1",
    "scripts/common.sh",
    "scripts/ghidra_import_analyze",
    "scripts/ghidra_export_apple_bundle",
    "scripts/ghidra_export_triage_bundle",
    "scripts/ghidra_function_dossier",
    "scripts/ghidra_resolve_swift_outlined",
    "scripts/ghidra_build_authstub_map",
    "scripts/ghidra_lldb_trace",
    "scripts/ghidra_lldb_symbols",
    "scripts/ghidra_lldb_enrich",
    "scripts/ghidra_polish_release",
    "references/triage-patterns.json",
    "scripts/ghidra_scripts/TriageSupport.java",
    "scripts/ghidra_scripts/ExportEntrypoints.java",
    "scripts/ghidra_scripts/ExportSinks.java",
    "scripts/ghidra_scripts/TriagePaths.java",
    "scripts/ghidra_scripts/ExportFunctionDossier.java",
    "scripts/ghidra_scripts/ResolveSwiftOutlined.java",
    "scripts/ghidra_scripts/BuildAuthStubMap.java",
    "tests/test_validation.py",
    "tests/test_lldb_validation.py",
    "tests/test_authstub_map.py",
    "tests/test_command_surface.py",
]


def polish_release(
    *,
    mode: str = "quick",
    output_dir: str | Path | None = None,
    live_bridge: bool = False,
    strict_command_surface: bool = False,
) -> dict[str, Any]:
    """Run release-polish checks and write a compact evidence bundle."""
    if mode not in {"quick", "release"}:
        raise RuntimeError("mode must be 'quick' or 'release'")

    report_dir = Path(output_dir) if output_dir else cfg.logs_dir / "polish" / f"polish-{timestamp()}"
    report_dir.mkdir(parents=True, exist_ok=True)

    validation = validate_local(
        output_dir=report_dir / "validation",
        headless_smoke=mode == "release",
        live_bridge_smoke=live_bridge,
        lldb_smoke=mode == "release",
        frida_smoke=mode == "release",
    )
    command_surface = build_command_surface_inventory()
    package_surface = check_package_surface()
    ok = (
        validation["ok"]
        and not command_surface["missing_cli_references"]
        and (not strict_command_surface or not command_surface["missing_script_references"])
        and not package_surface["missing_required_files"]
    )
    report = {
        "schema": "ghidra-re.polish.v1",
        "ok": ok,
        "created_at": utc_now(),
        "mode": mode,
        "live_bridge": live_bridge,
        "strict_command_surface": strict_command_surface,
        "report_dir": str(report_dir),
        "validation": {
            "ok": validation["ok"],
            "json_report": validation["json_report"],
            "markdown_report": validation["markdown_report"],
            "failed_step_count": validation["failed_step_count"],
            "next_work_items": validation["next_work_items"],
        },
        "command_surface": command_surface,
        "package_surface": package_surface,
        "next_work_items": _merge_work_items(validation, command_surface, package_surface),
    }
    json_path = report_dir / "polish.json"
    markdown_path = report_dir / "polish.md"
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return report


def build_command_surface_inventory() -> dict[str, Any]:
    root = cfg.skill_root
    actual_cli = _actual_cli_commands(root / "cerberus_re_skill" / "cli.py")
    actual_scripts = sorted(path.name for path in (root / "scripts").iterdir())
    doc_refs = _collect_doc_references(root)

    missing_scripts = []
    for ref in doc_refs["scripts"]:
        if ref["name"] not in actual_scripts:
            missing_scripts.append(ref)

    missing_cli = []
    actual_cli_set = set(actual_cli)
    top_level = {command.split()[0] for command in actual_cli}
    for ref in doc_refs["cli"]:
        tokens = ref["tokens"]
        if not tokens or _has_placeholder(tokens):
            continue
        candidate_two = " ".join(tokens[:2]) if len(tokens) >= 2 else ""
        candidate_one = tokens[0]
        if candidate_two in actual_cli_set or candidate_one in actual_cli_set or candidate_one in top_level:
            continue
        missing_cli.append(ref)

    return {
        "actual_cli_commands": actual_cli,
        "actual_scripts": actual_scripts,
        "doc_paths": [str(root / rel) for rel in DOC_PATHS if (root / rel).exists()],
        "script_reference_count": len(doc_refs["scripts"]),
        "cli_reference_count": len(doc_refs["cli"]),
        "missing_script_references": missing_scripts,
        "missing_cli_references": missing_cli,
    }


def check_package_surface() -> dict[str, Any]:
    root = cfg.skill_root
    missing = [path for path in REQUIRED_PACKAGE_FILES if not (root / path).exists()]
    bridge_zips = sorted((root / "bridge-extension" / "CodexGhidraBridge" / "dist").glob("ghidra_*_CodexGhidraBridge.zip"))
    test_files = sorted((root / "tests").glob("test_*.py"))
    return {
        "required_file_count": len(REQUIRED_PACKAGE_FILES),
        "missing_required_files": missing,
        "bridge_zip_count": len(bridge_zips),
        "latest_bridge_zip": str(bridge_zips[-1]) if bridge_zips else "",
        "test_file_count": len(test_files),
    }


def _actual_cli_commands(cli_path: Path) -> list[str]:
    files = [cli_path]
    runtime_path = cli_path.with_name("cli_runtime.py")
    if runtime_path.exists():
        files.append(runtime_path)
    commands_dir = cli_path.with_name("commands")
    if commands_dir.is_dir():
        files.extend(sorted(commands_dir.glob("*.py")))

    text = "\n".join(path.read_text(encoding="utf-8") for path in files if path.exists())
    app_names = {"app": ""}
    for var_name, exposed_name in re.findall(r'app\.add_typer\((\w+), name="([^"]+)"\)', text):
        app_names[var_name] = exposed_name
    commands: set[str] = set()
    for app_var, command_name in re.findall(r"@(\w+)\.command\(\"([^\"]+)\"\)", text):
        prefix = app_names.get(app_var)
        if prefix is None:
            continue
        commands.add(f"{prefix} {command_name}".strip())
    for app_var, func_name in re.findall(r"@(\w+)\.command\(\)\s*\ndef\s+(\w+)\(", text):
        prefix = app_names.get(app_var)
        if prefix is None:
            continue
        command_name = func_name.replace("_", "-")
        commands.add(f"{prefix} {command_name}".strip())
    for name in app_names.values():
        if name:
            commands.add(name)
    return sorted(commands)


def _collect_doc_references(root: Path) -> dict[str, list[dict[str, Any]]]:
    script_refs: list[dict[str, Any]] = []
    cli_refs: list[dict[str, Any]] = []
    script_re = re.compile(r"(?:\./)?scripts/([A-Za-z0-9_.-]+)")
    cli_re = re.compile(
        r"(?m)(?:^|[`$]\s*)(?:python3\s+-m\s+cerberus_re_skill|python\s+-m\s+cerberus_re_skill|cerberus-re)\s+([^\n`]+)"
    )
    for rel in DOC_PATHS:
        path = root / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for match in script_re.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line = text[line_start: line_end if line_end >= 0 else len(text)].lower()
            if "old " in line or "legacy" in line:
                continue
            script_refs.append({"path": str(path), "name": match.group(1), "text": match.group(0)})
        for match in cli_re.finditer(text):
            tail = match.group(1).strip()
            tokens = _clean_cli_tokens(tail)
            cli_refs.append({"path": str(path), "tokens": tokens, "text": match.group(0).strip()})
    return {"scripts": script_refs, "cli": cli_refs}


def _clean_cli_tokens(raw: str) -> list[str]:
    tokens = []
    for token in raw.split():
        cleaned = token.strip("`'\",).")
        if not cleaned:
            continue
        if cleaned in {"+", "&"}:
            return []
        if cleaned.startswith("-"):
            break
        tokens.append(cleaned)
        if len(tokens) >= 2:
            break
    return tokens


def _has_placeholder(tokens: list[str]) -> bool:
    return any(any(ch in token for ch in "<>[]{}...") for token in tokens)


def _merge_work_items(validation: dict, command_surface: dict, package_surface: dict) -> list[str]:
    items = list(validation.get("next_work_items", []))
    for ref in command_surface.get("missing_script_references", []):
        items.append(f"Add or remove stale script reference: scripts/{ref['name']}")
    for ref in command_surface.get("missing_cli_references", []):
        items.append(f"Add or remove stale CLI reference: {ref['text']}")
    for path in package_surface.get("missing_required_files", []):
        items.append(f"Restore required package file: {path}")
    unique: list[str] = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return unique


def _render_markdown(report: dict[str, Any]) -> str:
    status = "PASS" if report["ok"] else "FAIL"
    lines = [
        f"# Ghidra RE Release Polish - {status}",
        "",
        f"- Created: `{report['created_at']}`",
        f"- Mode: `{report['mode']}`",
        f"- Live bridge: `{report['live_bridge']}`",
        f"- Report dir: `{report['report_dir']}`",
        f"- Validation report: `{report['validation']['markdown_report']}`",
        "",
        "## Command Surface",
        "",
        f"- CLI references: `{report['command_surface']['cli_reference_count']}`",
        f"- Script references: `{report['command_surface']['script_reference_count']}`",
        f"- Missing CLI references: `{len(report['command_surface']['missing_cli_references'])}`",
        f"- Missing script references: `{len(report['command_surface']['missing_script_references'])}`",
        "",
        "## Package Surface",
        "",
        f"- Required files: `{report['package_surface']['required_file_count']}`",
        f"- Missing required files: `{len(report['package_surface']['missing_required_files'])}`",
        f"- Bridge zip count: `{report['package_surface']['bridge_zip_count']}`",
        f"- Test file count: `{report['package_surface']['test_file_count']}`",
        "",
        "## Next Work Items",
        "",
    ]
    if report["next_work_items"]:
        lines.extend(f"- {item}" for item in report["next_work_items"])
    else:
        lines.append("- No blockers or warnings detected.")
    lines.append("")
    return "\n".join(lines)
