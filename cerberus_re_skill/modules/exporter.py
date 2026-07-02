"""Export Apple binary analysis artifacts via Ghidra scripts.

Functions exported here correspond to 'ghidra-re export <subcommand>' CLI
commands. Each function:
  1. Resolves the output path (auto-derived under exports/<project>/<program>/
     if not explicitly specified).
  2. Delegates to run_script() from the importer, which invokes the matching
     Ghidra Java script via analyzeHeadless -readOnly.
  3. Returns a dict with 'ok', 'output', and script log paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cerberus_re_skill.core.config import cfg


def export_macho_structure(
    project: str,
    program: str | None = None,
    output: str | None = None,
) -> dict[str, Any]:
    """Run ExportMachOStructure.java and return the path to macho_structure.json.

    Parameters
    ----------
    project:
        Ghidra project name (must already exist under the workspace).
    program:
        Program name within the project.  Required when *output* is omitted,
        so that the auto-derived output path can be constructed as:
        ``exports/<project>/<program>/macho_structure.json``.
    output:
        Explicit destination file path.  If given, *program* is used only for
        the Ghidra ``-process`` selector (optional but improves targeting when
        multiple programs share a project).
    """
    from cerberus_re_skill.modules.importer import run_script

    # Determine output path
    if output:
        out_path = Path(output)
    elif program:
        out_path = cfg.export_dir(project, program) / "macho_structure.json"
    else:
        raise RuntimeError(
            "Either --output or program name must be provided to derive "
            "the export destination path."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    result = run_script(
        script_name="ExportMachOStructure.java",
        project_name=project,
        program_name=program,
        script_args=[f"output={out_path}"],
    )
    result["output"] = str(out_path)
    return result


def export_objc_layout(
    project: str,
    program: str | None = None,
    output: str | None = None,
) -> dict[str, Any]:
    """Run ExportObjCTypeLayout.java and return the path to objc_layout.json.

    Parameters
    ----------
    project:
        Ghidra project name (must already exist under the workspace).
    program:
        Program name within the project.  Required when *output* is omitted.
    output:
        Explicit destination file path.  Auto-derived under
        ``exports/<project>/<program>/objc_layout.json`` when omitted.
    """
    from cerberus_re_skill.modules.importer import run_script

    if output:
        out_path = Path(output)
    elif program:
        out_path = cfg.export_dir(project, program) / "objc_layout.json"
    else:
        raise RuntimeError(
            "Either --output or program name must be provided to derive "
            "the export destination path."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    result = run_script(
        script_name="ExportObjCTypeLayout.java",
        project_name=project,
        program_name=program,
        script_args=[f"output={out_path}"],
    )
    result["output"] = str(out_path)
    return result


def export_swift_layout(
    project: str,
    program: str | None = None,
    output: str | None = None,
) -> dict[str, Any]:
    """Run ExportSwiftTypeLayout.java and return the path to swift_layout.json.

    Parameters
    ----------
    project:
        Ghidra project name (must already exist under the workspace).
    program:
        Program name within the project.  Required when *output* is omitted.
    output:
        Explicit destination file path.  Auto-derived under
        ``exports/<project>/<program>/swift_layout.json`` when omitted.
    """
    from cerberus_re_skill.modules.importer import run_script

    if output:
        out_path = Path(output)
    elif program:
        out_path = cfg.export_dir(project, program) / "swift_layout.json"
    else:
        raise RuntimeError(
            "Either --output or program name must be provided to derive "
            "the export destination path."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    result = run_script(
        script_name="ExportSwiftTypeLayout.java",
        project_name=project,
        program_name=program,
        script_args=[f"output={out_path}"],
    )
    result["output"] = str(out_path)
    return result
