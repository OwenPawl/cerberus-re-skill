"""Generic XPC service candidate selection helpers."""

from __future__ import annotations

import re
from typing import Any


_GENERIC_TERMS = {
    "apple",
    "client",
    "com",
    "daemon",
    "framework",
    "helper",
    "interface",
    "manager",
    "protocol",
    "service",
    "xpc",
}


def best_xpc_service(interface: str, services: Any) -> str:
    """Choose the most plausible concrete service without target-specific names."""
    candidates = [str(item) for item in services if isinstance(item, str) and item]
    concrete = [item for item in candidates if item.startswith("com.apple.")]
    if concrete:
        interface_terms = _identifier_terms(interface)
        scored = [(_service_score(interface_terms, service), index, service) for index, service in enumerate(concrete)]
        score, _, service = max(scored, key=lambda item: (item[0], -item[1]))
        if score > 0:
            return service
        return concrete[0]
    return next((item for item in candidates if not item.startswith("_")), "")


def _identifier_terms(value: str) -> set[str]:
    terms: set[str] = set()
    for chunk in re.split(r"[^A-Za-z0-9]+", str(value)):
        for part in re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+", chunk):
            lowered = part.lower()
            if len(lowered) < 3 or lowered in _GENERIC_TERMS:
                continue
            terms.add(lowered)
            if lowered.endswith("s") and len(lowered) > 4:
                terms.add(lowered[:-1])
    return terms


def _service_score(interface_terms: set[str], service: str) -> int:
    service_terms = _identifier_terms(service)
    service_lower = service.lower()
    score = 0
    for term in interface_terms:
        if term in service_terms:
            score += 3
        elif term in service_lower:
            score += 2
    return score
