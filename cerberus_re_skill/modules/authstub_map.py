"""Build dyld-backed authstub maps for Swift outlined resolution."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg
from cerberus_re_skill.core.utils import utc_now


_AUTHSTUB_NAME_RE = re.compile(r"outlined\$(?:pactail\$)?authstub\$(?P<name>.+)$")
_SLOT_RE = re.compile(r"slot_([0-9a-fA-F]+)")
_INDIRECT_HEADER_RE = re.compile(r"Indirect symbols for \((?P<segment>[^,]+),(?P<section>[^)]+)\)")
_INDIRECT_LINE_RE = re.compile(r"^\s*(?P<address>0x[0-9a-fA-F]+)\s+(?:(?P<index>\d+)\s+(?P<name>.+)|LOCAL ABSOLUTE)\s*$")
_IMPORT_LINE_RE = re.compile(r"^\s*(?P<symbol>\S+)(?:\s+\[weak-import\])?\s+\(from (?P<library>[^)]+)\)")


def build_authstub_map(
    project: str,
    program: str,
    *,
    output_dir: str | Path | None = None,
    output: str | Path | None = None,
    binary: str | Path | None = None,
    dyld_source: str | Path | None = None,
    swift_outlined_report: str | Path | None = None,
    generate_report: bool = True,
    ghidra_probe: bool = True,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Build ``authstub_map.json`` from Ghidra and dyld-backed Mach-O metadata."""

    default_export_dir = cfg.export_dir(project, program)
    out_dir = Path(output_dir) if output_dir else default_export_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = Path(output) if output else out_dir / "authstub_map.json"
    report_path = Path(swift_outlined_report) if swift_outlined_report else out_dir / "swift_outlined_resolved.json"

    if swift_outlined_report and not report_path.exists():
        raise FileNotFoundError(f"swift outlined report does not exist: {report_path}")

    if generate_report and not report_path.exists():
        from cerberus_re_skill.modules.swift_outlined import resolve_swift_outlined

        resolve_swift_outlined(
            project,
            program,
            output_dir=out_dir,
            dry_run=True,
            inline=False,
            skip_stubs=False,
            verbose=False,
            scan_fun_stubs=True,
            second_pass=False,
        )

    ghidra_probe_path = out_dir / "authstub_map_ghidra_slots.json"
    ghidra_probe_step: dict[str, Any] | None = None
    ghidra_probe_payload: dict[str, Any] = {}
    if ghidra_probe:
        ghidra_probe_step = _run_ghidra_probe(project, program, ghidra_probe_path)
        ghidra_probe_payload = _read_json(ghidra_probe_path)

    binary_path = _resolve_binary_path(
        project,
        program,
        explicit_binary=binary,
        dyld_source=dyld_source,
        export_dirs=[out_dir, default_export_dir],
    )
    imports = _collect_imports(binary_path, timeout=timeout) if binary_path else {}
    indirect = _collect_indirect_authstubs(binary_path, imports, timeout=timeout) if binary_path else {}
    ghidra_stubs = _collect_ghidra_probe_stubs(ghidra_probe_payload)
    report_stubs = _collect_report_authstubs(report_path)

    stubs: dict[str, dict[str, Any]] = {}
    slots: dict[str, dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []

    for stub_addr, entry in indirect.items():
        stubs[stub_addr] = dict(entry)

    for stub_addr, entry in ghidra_stubs.items():
        stub = stubs.setdefault(stub_addr, {"address": stub_addr})
        _merge_stub(stub, entry)

    for stub_addr, report_entry in report_stubs.items():
        stub = stubs.setdefault(
            stub_addr,
            {
                "name": "",
                "raw_symbol": "",
                "source": "swift-outlined-report",
                "address": stub_addr,
                "dyld_library": "",
            },
        )
        stub.setdefault("address", stub_addr)
        if report_entry.get("slot"):
            stub["slot"] = report_entry["slot"]
        if not stub.get("name") and report_entry.get("name"):
            _merge_stub(
                stub,
                {
                    "name": report_entry["name"],
                    "raw_symbol": report_entry.get("raw_symbol", report_entry["name"]),
                    "source": "swift-outlined-report",
                },
            )
        if report_entry.get("old_name"):
            stub["old_name"] = report_entry["old_name"]
        if report_entry.get("new_name"):
            stub["new_name"] = report_entry["new_name"]

    for stub_addr, stub in sorted(stubs.items()):
        name = str(stub.get("name") or "")
        slot = stub.get("slot")
        if slot:
            slot_entry = {
                "name": name,
                "stub": stub_addr,
                "raw_symbol": stub.get("raw_symbol", ""),
                "source": stub.get("source", ""),
                "dyld_library": stub.get("dyld_library", ""),
            }
            slots[str(slot)] = slot_entry
        if not name:
            unresolved.append(
                {
                    "stub": stub_addr,
                    "slot": slot or "",
                    "reason": "dyld metadata exposed no imported symbol name",
                    "source": stub.get("source", ""),
                }
            )

    resolved_stubs = sum(1 for item in stubs.values() if item.get("name"))
    resolved_slots = sum(1 for item in slots.values() if item.get("name"))
    payload = {
        "schema": "ghidra-re.authstub-map.v1",
        "created_at": utc_now(),
        "project_name": project,
        "program_name": program,
        "inputs": {
            "binary": str(binary_path) if binary_path else "",
            "dyld_source": str(Path(dyld_source).expanduser()) if dyld_source else "",
            "swift_outlined_report": str(report_path),
            "ghidra_probe": str(ghidra_probe_path) if ghidra_probe else "",
        },
        "stats": {
            "ghidra_probe_stub_count": len(ghidra_stubs),
            "ghidra_probe_resolved_stub_count": sum(1 for item in ghidra_stubs.values() if item.get("name")),
            "dyld_import_count": len(imports),
            "otool_auth_stub_count": len(indirect),
            "otool_named_auth_stub_count": sum(1 for item in indirect.values() if item.get("name")),
            "report_auth_stub_count": len(report_stubs),
            "stub_count": len(stubs),
            "resolved_stub_count": resolved_stubs,
            "unresolved_stub_count": len(stubs) - resolved_stubs,
            "slot_count": len(slots),
            "resolved_slot_count": resolved_slots,
            "unresolved_slot_count": len(slots) - resolved_slots,
        },
        "stubs": stubs,
        "slots": slots,
        "unresolved": unresolved,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "project_name": project,
        "program_name": program,
        "output": str(output_path),
        "output_dir": str(out_dir),
        "binary": str(binary_path) if binary_path else "",
        "swift_outlined_report": str(report_path),
        "ghidra_probe": str(ghidra_probe_path) if ghidra_probe else "",
        "ghidra_probe_step": ghidra_probe_step,
        "stats": payload["stats"],
        "artifact_status": _artifact_status(output_path),
    }


def _resolve_binary_path(
    project: str,
    program: str,
    *,
    explicit_binary: str | Path | None,
    dyld_source: str | Path | None,
    export_dirs: list[Path],
) -> Path | None:
    candidates: list[Path] = []
    if explicit_binary:
        candidates.append(Path(explicit_binary).expanduser())

    seen_summary_dirs: set[Path] = set()
    for export_dir in export_dirs:
        if export_dir in seen_summary_dirs:
            continue
        seen_summary_dirs.add(export_dir)
        summary = _read_json(export_dir / "program_summary.json")
        for key in ("executable_path", "binary_path", "binary"):
            value = summary.get(key)
            if isinstance(value, str) and value:
                candidates.append(Path(value).expanduser())
                if dyld_source and value.startswith("/"):
                    candidates.append(Path(dyld_source).expanduser() / value.lstrip("/"))

    if dyld_source:
        root = Path(dyld_source).expanduser()
        for rel in (
            f"System/Library/PrivateFrameworks/{program}.framework/Versions/A/{program}",
            f"System/Library/Frameworks/{program}.framework/Versions/A/{program}",
            f"usr/lib/{program}",
            f"usr/lib/{program}.dylib",
        ):
            candidates.append(root / rel)

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _collect_imports(binary: Path, *, timeout: float) -> dict[str, str]:
    result = _run_tool(["dyld_info", "-no_validate", "-imports", str(binary)], timeout=timeout)
    imports: dict[str, str] = {}
    if result.returncode != 0:
        return imports
    for line in result.stdout.splitlines():
        match = _IMPORT_LINE_RE.match(line)
        if not match:
            continue
        raw = match.group("symbol")
        library = match.group("library")
        imports[raw] = library
        imports[_clean_symbol_name(raw)] = library
    return imports


def _collect_indirect_authstubs(binary: Path, imports: dict[str, str], *, timeout: float) -> dict[str, dict[str, Any]]:
    result = _run_tool(["otool", "-Iv", str(binary)], timeout=timeout)
    if result.returncode != 0:
        return {}
    active_section = ""
    stubs: dict[str, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        header = _INDIRECT_HEADER_RE.search(line)
        if header:
            active_section = header.group("section")
            continue
        if active_section != "__auth_stubs":
            continue
        match = _INDIRECT_LINE_RE.match(line)
        if not match:
            continue
        addr = _normalize_addr(match.group("address"))
        raw_name = (match.group("name") or "").strip()
        index_text = match.group("index")
        name = _clean_symbol_name(raw_name) if raw_name else ""
        stubs[addr] = {
            "address": addr,
            "name": name,
            "raw_symbol": raw_name,
            "indirect_index": int(index_text) if index_text is not None else None,
            "source": "otool-indirect-auth-stubs" if name else "otool-indirect-local-absolute",
            "dyld_library": imports.get(raw_name) or imports.get(name) or "",
        }
    return stubs


def _collect_report_authstubs(report_path: Path) -> dict[str, dict[str, str]]:
    payload = _read_json(report_path)
    stubs: dict[str, dict[str, str]] = {}
    renames = payload.get("renames", [])
    if not isinstance(renames, list):
        return stubs
    for rec in renames:
        if not isinstance(rec, dict):
            continue
        category = str(rec.get("category") or "")
        new_name = str(rec.get("new_name") or "")
        if "authstub" not in category and "authstub" not in new_name:
            continue
        entry = _normalize_addr(str(rec.get("entry") or ""))
        if not entry:
            continue
        slot = _extract_slot(new_name)
        name = _extract_authstub_name(new_name)
        if _is_placeholder_authstub_name(name):
            name = ""
        stubs[entry] = {
            "slot": slot,
            "name": name,
            "raw_symbol": name,
            "old_name": str(rec.get("old_name") or ""),
            "new_name": new_name,
        }
    return stubs


def _run_ghidra_probe(project: str, program: str, output_path: Path) -> dict[str, Any]:
    from cerberus_re_skill.modules.importer import run_script

    try:
        return run_script(
            "BuildAuthStubMap.java",
            project,
            program,
            script_args=[f"output={output_path}"],
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc), "script_name": "BuildAuthStubMap.java"}


def _collect_ghidra_probe_stubs(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_stubs = payload.get("stubs")
    if not isinstance(raw_stubs, dict):
        return {}
    stubs: dict[str, dict[str, Any]] = {}
    for addr, entry in raw_stubs.items():
        if not isinstance(entry, dict):
            continue
        stub_addr = _normalize_addr(addr)
        if not stub_addr:
            continue
        stub = dict(entry)
        stub["address"] = stub_addr
        if stub.get("slot"):
            stub["slot"] = _normalize_addr(str(stub["slot"]))
        if stub.get("name"):
            stub["name"] = _clean_symbol_name(str(stub["name"]))
        stubs[stub_addr] = stub
    return stubs


def _merge_stub(stub: dict[str, Any], update: dict[str, Any]) -> None:
    for key, value in update.items():
        if value in (None, ""):
            continue
        if key == "source" and stub.get("source") and stub.get("name"):
            continue
        if key in {"name", "raw_symbol", "dyld_library", "slot", "target_address", "raw_pointer"}:
            if stub.get(key):
                continue
        stub[key] = value


def _extract_slot(value: str) -> str:
    match = _SLOT_RE.search(value)
    if not match:
        return ""
    return f"0x{match.group(1).lower()}"


def _extract_authstub_name(value: str) -> str:
    match = _AUTHSTUB_NAME_RE.search(value)
    if not match:
        return ""
    return _clean_symbol_name(match.group("name"))


def _is_placeholder_authstub_name(value: str) -> bool:
    text = value.strip().lower()
    if not text:
        return True
    if text.startswith("slot_"):
        return True
    return bool(re.fullmatch(r"[0-9a-f]+", text))


def _clean_symbol_name(value: str) -> str:
    text = value.strip()
    if not text or text == "LOCAL ABSOLUTE":
        return ""
    while text.startswith("_"):
        text = text[1:]
    return text


def _normalize_addr(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        return f"0x{int(text, 16):x}"
    except ValueError:
        return ""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _run_tool(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(argv[0]) or argv[0]
    return subprocess.run(
        [executable, *argv[1:]],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _artifact_status(path: Path) -> dict[str, int | bool | str]:
    exists = path.exists()
    return {
        "path": str(path),
        "exists": exists,
        "byte_size": path.stat().st_size if exists else 0,
    }
