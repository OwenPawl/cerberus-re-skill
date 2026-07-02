"""Bridge implementation shard."""

from __future__ import annotations

from cerberus_re_skill.modules.bridge_sessions import *  # noqa: F403
from cerberus_re_skill.modules.bridge_runtime import *  # noqa: F403
from cerberus_re_skill.modules.bridge_install import *  # noqa: F403


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def health_check(
    requested_session: str = "",
    requested_project: str = "",
    requested_program: str = "",
) -> dict:
    try:
        sf = resolve_session_file(requested_session, requested_project, requested_program)
    except RuntimeError as e:
        return {"ok": False, "healthy": False, "error": str(e)}
    healthy = session_healthy(sf)
    return {
        "ok": healthy,
        "healthy": healthy,
        "session_file": str(sf),
        "bridge_url": _read_session_value(sf, "bridge_url"),
    }

__all__ = [name for name in globals() if not name.startswith('__')]
