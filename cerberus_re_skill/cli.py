"""Main CLI registration shim for Cerberus RE."""

from __future__ import annotations

from cerberus_re_skill.cli_runtime import app

# Import modules for their Typer decorators. Keep this file intentionally thin;
# command implementations live under cerberus_re_skill.commands.
from cerberus_re_skill.commands import bridge_validate_frida as _bridge_validate_frida
from cerberus_re_skill.commands import core as _core
from cerberus_re_skill.commands import export_runtime as _export_runtime
from cerberus_re_skill.commands import export_static as _export_static
from cerberus_re_skill.commands import export_workflow as _export_workflow
from cerberus_re_skill.commands import export_xpc as _export_xpc
from cerberus_re_skill.commands import import_commands as _import_commands
from cerberus_re_skill.commands import install_publish_plugins as _install_publish_plugins
from cerberus_re_skill.commands import sources_mission_notes as _sources_mission_notes

__all__ = ["app"]
