#!/usr/bin/env python3

import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Set

OBJC_METHOD_RE = re.compile(r"^([+-])\[(.+?) ([^\]]+)\]$")
OBJC_METHOD_BODY_RE = re.compile(r"^([+-])\[(.+)\]$")
CANONICAL_SWIFT_TYPE_RE = re.compile(
    r"(?:__C\.)?[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)+"
)
PROPERTY_DESCRIPTOR_RE = re.compile(
    r"property_descriptor_for_(?:\(extension_in_[^)]+\):)?"
    r"(?P<type>(?:__C\.)?[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)+)"
    r"\.(?P<property>[a-zA-Z_][A-Za-z0-9_]*)_"
)
CAMEL_CASE_TOKEN_RE = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+"
)
GENERIC_SWIFT_TYPE_TOKENS = {
    "action",
    "cell",
    "configuration",
    "context",
    "controller",
    "coordinator",
    "delegate",
    "helper",
    "item",
    "manager",
    "model",
    "presenter",
    "provider",
    "service",
    "state",
    "style",
    "type",
    "view",
    "viewmodel",
}
PATH_LIKE_NAMESPACE_SEGMENTS = {
    "applications",
    "coreservices",
    "desktop",
    "library",
    "mobile",
    "privateframeworks",
    "system",
    "tmp",
    "users",
    "var",
}


def load_json(path: str) -> Dict[str, Any]:
    file_path = pathlib.Path(path)
    if not file_path.is_file():
        return {}
    return json.loads(file_path.read_text(encoding="utf-8"))


def short_type_name(type_name: str) -> str:
    if not type_name:
        return ""
    return type_name.split(".")[-1]


def normalize(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def camel_case_tokens(value: str) -> List[str]:
    if not value:
        return []
    return [token.lower() for token in CAMEL_CASE_TOKEN_RE.findall(value) if token]


def empty_surface(type_name: str) -> Dict[str, Any]:
    return {
        "type_name": type_name,
        "short_name": short_type_name(type_name),
        "methods": [],
        "properties": [],
        "async_methods": [],
        "dispatch_thunks": [],
        "metadata_accessors": [],
        "metadata_methods": [],
        "protocol_witnesses": [],
        "protocol_requirements": [],
        "associated_types": [],
        "associated_conformances": [],
        "code_candidates": [],
        "async_helpers": [],
        "init_methods": [],
        "deinit_methods": [],
        "start_methods": [],
        "raw_symbols": [],
        "protocol_conformances": [],
        "objc_bridge_methods": [],
        "objc_runtime_artifacts": [],
        "property_hints": [],
        "objc_bridge_names": [],
    }


def unique_by_key(items: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = (
            item.get(key)
            or item.get("canonical_address")
            or item.get("candidate_address")
            or item.get("address")
            or item.get("associated_type")
            or item.get("conforming_type")
            or json.dumps(item, sort_keys=True)
        )
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def valid_surface_type_name(type_name: str) -> bool:
    if not type_name:
        return False
    if any(token in type_name for token in ("-[", "+[", "block_invoke", "___", "swift_async_")):
        return False
    if any(ch in type_name for ch in (" ", "(", ")")):
        return False
    if type_name.startswith("_") and not type_name.startswith("__C."):
        return False
    if ".." in type_name:
        return False
    return True


def type_name_noise_penalty(type_name: str) -> int:
    penalty = 0
    segments = [segment for segment in type_name.split(".") if segment]
    if not segments:
        return 100
    short_segments = 0
    for segment in segments:
        if segment.startswith("_") and segment != "__C":
            penalty += 35
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", segment):
            penalty += 30
        if len(segment) <= 2:
            short_segments += 1
        if re.search(r"[0-9]_[0-9]|_[0-9]|[0-9]$", segment):
            penalty += 12
        if segment.lower() in PATH_LIKE_NAMESPACE_SEGMENTS:
            penalty += 25
    if short_segments >= 2:
        penalty += 20
    if len(type_name) < 3:
        penalty += 25
    if len(segments) >= 3 and sum(1 for segment in segments[:-1] if segment.lower() in PATH_LIKE_NAMESPACE_SEGMENTS) >= 1:
        penalty += 35
    return penalty


def parse_length_encoded_path(value: str, start: int = 0) -> str:
    parts: List[str] = []
    index = start
    while index < len(value) and value[index].isdigit():
        end = index
        while end < len(value) and value[end].isdigit():
            end += 1
        try:
            declared_length = int(value[index:end])
        except ValueError:
            break
        if declared_length <= 0 or end + declared_length > len(value):
            break
        part = value[end:end + declared_length]
        if not part or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", part):
            break
        parts.append(part)
        index = end + declared_length
    if len(parts) >= 2:
        return ".".join(parts)
    return ""


def extract_type_candidates_from_text(text: str) -> List[str]:
    if not text:
        return []
    candidates = set()
    text = text.strip()
    for match in CANONICAL_SWIFT_TYPE_RE.finditer(text.replace("/", ".")):
        value = match.group(0).strip(".")
        if valid_surface_type_name(value):
            candidates.add(value)
    normalized = text.replace("_symbolic_", " ").replace("_symbolic ", " ").replace("/", ".")
    for index, ch in enumerate(normalized):
        if not ch.isdigit():
            continue
        value = parse_length_encoded_path(normalized, index)
        if valid_surface_type_name(value):
            candidates.add(value)
    return sorted(candidates, key=str.lower)


def parse_objc_method_name(name: str, known_classes=None) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    match = OBJC_METHOD_RE.match(name)
    if not match:
        body_match = OBJC_METHOD_BODY_RE.match(name)
        if not body_match:
            return None
        kind, body = body_match.groups()
        class_name = ""
        selector = ""
        for candidate in sorted(known_classes or [], key=len, reverse=True):
            for separator in (" ", "_"):
                prefix = candidate + separator
                if body.startswith(prefix):
                    class_name = candidate
                    selector = body[len(prefix):]
                    break
            if class_name:
                break
        if not class_name and "_" in body:
            class_name, selector = body.split("_", 1)
        if not class_name or not selector:
            return None
    else:
        kind, class_name, selector = match.groups()
    return {
        "kind": kind,
        "class_name": class_name,
        "selector": selector,
    }


def recovered_type_candidates(*values: str) -> List[str]:
    candidates: List[str] = []
    seen: Set[str] = set()
    for value in values:
        for candidate in extract_type_candidates_from_text(value):
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def recovered_type_score(type_name: str) -> int:
    score = len(type_name)
    segments = [segment for segment in type_name.split(".") if segment]
    score += len(segments) * 10
    if type_name.startswith("__C."):
        score += 15
    score -= type_name_noise_penalty(type_name)
    return score


def recover_surface_type_name(entry: Dict[str, Any], fallback_type_name: str = "") -> str:
    existing = (entry.get("type_name", "") or fallback_type_name or "").strip()
    candidates = recovered_type_candidates(
        existing,
        entry.get("stable_alias", ""),
        entry.get("member_name", ""),
        entry.get("display_name", ""),
        entry.get("demangled", ""),
        entry.get("name", ""),
    )
    if existing and candidates:
        if not valid_surface_type_name(existing) or type_name_noise_penalty(existing) >= 35:
            return max(candidates, key=recovered_type_score)
        for candidate in candidates:
            if candidate == existing:
                return existing
            if candidate.endswith("." + existing) or candidate.endswith(".__C." + existing):
                return candidate
            if candidate.startswith(existing + ".") or candidate.startswith("__C." + existing + "."):
                return candidate
    if valid_surface_type_name(existing):
        return existing
    if candidates:
        return max(candidates, key=recovered_type_score)
    return existing


def significant_type_tokens(type_name: str) -> List[str]:
    tokens: List[str] = []
    segments = [segment for segment in type_name.replace("__C.", "").split(".") if segment]
    if len(segments) >= 2:
        segments = segments[1:]
    for segment in segments:
        for token in camel_case_tokens(segment):
            if len(token) < 3:
                continue
            if token in GENERIC_SWIFT_TYPE_TOKENS:
                continue
            tokens.append(token)
    return list(dict.fromkeys(tokens))


def correlate_objc_classes(type_name: str, objc: Dict[str, Any]) -> List[str]:
    short_name = short_type_name(type_name)
    candidates = []
    significant_tokens = significant_type_tokens(type_name)
    significant_signature = "".join(significant_tokens)
    short_name_generic = normalize(short_name) in GENERIC_SWIFT_TYPE_TOKENS
    for value in objc.get("classes", []):
        lowered = value.lower()
        normalized_value = normalize(value)
        normalized_short = normalize(short_name)
        normalized_type = normalize(type_name)
        if value == type_name or value == short_name or value == f"Swift{short_name}":
            candidates.append(value)
            continue
        if (
            significant_signature
            and len(significant_signature) >= 8
            and significant_signature in normalized_value
        ):
            candidates.append(value)
            continue
        if (
            significant_tokens
            and sum(1 for token in significant_tokens if token in normalized_value) >= min(2, len(significant_tokens))
        ):
            candidates.append(value)
            continue
        if (
            normalized_short
            and not short_name_generic
            and len(normalized_short) >= 6
            and normalized_short in normalized_value
        ):
            candidates.append(value)
            continue
        if normalized_type and normalized_type in normalized_value:
            candidates.append(value)
    return sorted(dict.fromkeys(candidates), key=str.lower)


def bridge_name_matches_surface(type_name: str, bridge_name: str) -> bool:
    if not bridge_name:
        return False
    short_name = short_type_name(type_name)
    normalized_bridge = normalize(bridge_name.replace("_OBJC_CLASS_$", "").replace("_OBJC_METACLASS_$", ""))
    normalized_type = normalize(type_name)
    normalized_short = normalize(short_name)
    significant_tokens = significant_type_tokens(type_name)
    significant_signature = "".join(significant_tokens)
    short_name_generic = normalized_short in GENERIC_SWIFT_TYPE_TOKENS
    if normalized_type and normalized_type in normalized_bridge:
        return True
    if (
        normalized_short
        and not short_name_generic
        and len(normalized_short) >= 6
        and normalized_short in normalized_bridge
    ):
        return True
    if (
        significant_signature
        and len(significant_signature) >= 8
        and significant_signature in normalized_bridge
    ):
        return True
    if significant_tokens and sum(1 for token in significant_tokens if token in normalized_bridge) >= min(2, len(significant_tokens)):
        return True
    return False


def associated_conformance_label(entry: Dict[str, Any]) -> str:
    leading = entry.get("conforming_type", "") or entry.get("type_name", "")
    middle = entry.get("associated_type", "") or entry.get("protocol_name", "")
    trailing = entry.get("concrete_type", "")
    if middle and normalize(middle) == normalize(leading):
        middle = ""
    if trailing and normalize(trailing) == normalize(middle or leading):
        trailing = ""
    parts = [part for part in [leading, middle, trailing] if part]
    return " -> ".join(parts)


def related_strings(type_name: str, strings_doc: Dict[str, Any], extra_terms=None,
                    limit: int = 20) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    query_terms = [term for term in [type_name, short_name] + list(extra_terms or []) if term]
    matches: List[Dict[str, Any]] = []
    for item in strings_doc.get("strings", []):
        value = item.get("value", "")
        if any(term.lower() in value.lower() for term in query_terms):
            matches.append(
                {
                    "address": item.get("address", ""),
                    "value": value,
                    "artifact_type": item.get("artifact_type", ""),
                    "metadata_group": item.get("metadata_group", ""),
                    "xref_count": item.get("xref_count", 0),
                }
            )
        if len(matches) >= limit:
            break
    return matches


def related_symbols(type_name: str, symbols_doc: Dict[str, Any], extra_terms=None,
                    limit: int = 20,
                    symbol_indexes: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None
                    ) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    query_terms = [term for term in [type_name, short_name] + list(extra_terms or []) if term]
    matches: List[Dict[str, Any]] = []
    if symbol_indexes:
        items = []
        seen_items = set()
        for term in query_terms:
            for item in symbol_indexes.get("symbols_by_candidate", {}).get(term, []):
                marker = item.get("name", "") + "|" + item.get("address", "")
                if marker in seen_items:
                    continue
                seen_items.add(marker)
                items.append(item)
    else:
        items = symbols_doc.get("symbols", [])
    for item in items:
        name = item.get("name", "")
        demangled = item.get("demangled", "")
        if any(term.lower() in name.lower() or term.lower() in demangled.lower() for term in query_terms):
            matches.append(
                {
                    "name": name,
                    "demangled": demangled,
                    "address": item.get("address", ""),
                    "artifact_type": item.get("artifact_type", ""),
                    "xref_count": item.get("xref_count", 0),
                }
            )
        if len(matches) >= limit:
            break
    return matches


def build_symbol_indexes(objc: Dict[str, Any],
                         symbols_doc: Dict[str, Any]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    known_classes = set(objc.get("interface_classes", []) or [])
    known_classes.update(objc.get("classes", []))
    known_classes.update(objc.get("metaclasses", []))
    objc_methods_by_class: Dict[str, List[Dict[str, Any]]] = {}
    symbols_by_candidate: Dict[str, List[Dict[str, Any]]] = {}
    for item in symbols_doc.get("objc_related", []) + symbols_doc.get("symbols", []):
        text = " ".join(str(item.get(key, "")) for key in ["name", "demangled", "display_name"])
        for candidate in extract_type_candidates_from_text(text):
            symbols_by_candidate.setdefault(candidate, []).append(item)
            symbols_by_candidate.setdefault(short_type_name(candidate), []).append(item)
        parsed = parse_objc_method_name(item.get("name", ""), known_classes)
        if parsed:
            objc_methods_by_class.setdefault(parsed["class_name"], []).append(item)
    return {
        "objc_methods_by_class": objc_methods_by_class,
        "symbols_by_candidate": symbols_by_candidate,
    }


def inferred_surface_types(swift: Dict[str, Any], symbols_doc: Dict[str, Any],
                           strings_doc: Dict[str, Any]) -> List[str]:
    candidates = set()
    for type_name in swift.get("types", []):
        if valid_surface_type_name(type_name):
            candidates.add(type_name)
    for entry in swift.get("protocol_requirements", []):
        for value in [entry.get("type_name", ""), entry.get("protocol_name", "")]:
            if valid_surface_type_name(value):
                candidates.add(value)
    for entry in swift.get("associated_conformances", []):
        for value in [
            entry.get("type_name", ""),
            entry.get("protocol_name", ""),
            entry.get("conforming_type", ""),
            entry.get("concrete_type", ""),
        ]:
            if valid_surface_type_name(value):
                candidates.add(value)
    for entry in swift.get("symbols", []):
        for value in [entry.get("type_name", ""), entry.get("display_name", ""), entry.get("name", "")]:
            for candidate in extract_type_candidates_from_text(value):
                candidates.add(candidate)
    for collection in [symbols_doc.get("symbols", []), symbols_doc.get("objc_related", [])]:
        for entry in collection:
            for value in [entry.get("name", ""), entry.get("demangled", ""), entry.get("display_name", "")]:
                for candidate in extract_type_candidates_from_text(value):
                    candidates.add(candidate)
    for entry in strings_doc.get("strings", []):
        value = entry.get("value", "") or entry.get("string_value", "")
        for candidate in extract_type_candidates_from_text(value):
            candidates.add(candidate)
    for meta in swift.get("metadata_sections", {}).values():
        for key in ["demangled_strings", "strings"]:
            for value in meta.get(key, []):
                for candidate in extract_type_candidates_from_text(value):
                    candidates.add(candidate)
    return sorted(candidates, key=str.lower)


def objc_runtime_artifacts_for_type(type_name: str, objc: Dict[str, Any],
                                    symbols_doc: Dict[str, Any],
                                    bridge_names: List[str],
                                    symbol_indexes: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None
                                    ) -> List[Dict[str, Any]]:
    short_name = short_type_name(type_name)
    matches = []
    candidates = [type_name, short_name] + list(bridge_names)
    seen_names = set()
    indexed_items: List[Dict[str, Any]] = []
    if symbol_indexes:
        for candidate in candidates:
            if not candidate:
                continue
            for item in symbol_indexes.get("symbols_by_candidate", {}).get(candidate, []):
                marker = item.get("name", "") + "|" + item.get("address", "")
                if marker in seen_names:
                    continue
                seen_names.add(marker)
                indexed_items.append(item)
    else:
        indexed_items = symbols_doc.get("objc_related", []) + symbols_doc.get("symbols", [])
    for item in indexed_items:
        name = item.get("name", "")
        matches.append(
            {
                "name": name,
                "demangled": item.get("demangled", ""),
                "address": item.get("address", ""),
                "artifact_type": item.get("artifact_type", ""),
                "xref_count": item.get("xref_count", 0),
            }
        )
    return unique_by_key(matches, "name")


def bridge_names_for_surface(type_name: str, objc: Dict[str, Any],
                             surface: Dict[str, Any]) -> List[str]:
    candidates: Set[str] = set(correlate_objc_classes(type_name, objc))
    for bucket_name in ["raw_symbols", "properties", "objc_runtime_artifacts", "metadata_methods"]:
        for entry in surface.get(bucket_name, []):
            bridge_name = entry.get("objc_bridge_name", "")
            if bridge_name and bridge_name_matches_surface(type_name, bridge_name):
                candidates.add(bridge_name)
    for artifact in surface.get("objc_runtime_artifacts", []):
        name = artifact.get("name", "")
        if name.startswith("_OBJC_CLASS_$__Tt") or name.startswith("_OBJC_METACLASS_$__Tt"):
            candidate = name.split("$", 1)[-1]
            if bridge_name_matches_surface(type_name, candidate):
                candidates.add(candidate)
    return sorted(candidates, key=str.lower)


def preferred_namespaces(program_name: str) -> List[str]:
    if not program_name:
        return []
    candidates = [program_name]
    if program_name.endswith("Core") and len(program_name) > 4:
        candidates.append(program_name[:-4])
    if program_name.endswith("UI") and len(program_name) > 2:
        candidates.append(program_name[:-2])
    return [value for value in dict.fromkeys(candidates) if value]


def candidate_type_priority(type_name: str, program_name: str) -> int:
    short_name = short_type_name(type_name)
    score = 0
    namespaces = preferred_namespaces(program_name)
    if "." in type_name:
        namespace = type_name.split(".", 1)[0]
        if namespace in namespaces:
            score += 120
        elif namespace in {"SwiftUI", "Foundation", "Combine", "AppKit", "CoreGraphics"}:
            score -= 25
    else:
        if short_name.startswith(("WF", "AK", "CK", "TK", "IN")):
            score += 40
        elif len(short_name) <= 2:
            score -= 25
    if short_name.startswith(program_name):
        score += 35
    if any(token in type_name for token in ("Controller", "Manager", "Client", "Service")):
        score += 12
    score -= type_name_noise_penalty(type_name)
    return score


def select_candidate_types(type_names: List[str], program_name: str,
                           focus_query: str) -> List[str]:
    if focus_query:
        return type_names
    ranked = sorted(
        type_names,
        key=lambda value: (-candidate_type_priority(value, program_name), value.lower()),
    )
    return ranked[:40]


def score_surface(surface: Dict[str, Any], program_name: str) -> int:
    type_name = surface["type_name"]
    short_name = surface["short_name"]
    summary = surface.get("summary", {})
    score = 0
    if "." in type_name:
        namespace = type_name.split(".", 1)[0]
        if namespace in preferred_namespaces(program_name):
            score += 120
        elif namespace in {"SwiftUI", "Foundation", "Combine", "AppKit"}:
            score -= 20
    elif short_name.startswith(("WF", "CK", "AK", "TK", "IN")):
        score += 35
    if any(name.startswith("_Tt") or name.startswith("__Tt") for name in surface.get("objc_bridge_names", [])):
        score += 40
    if any(name.startswith("WF") for name in surface.get("objc_bridge_names", [])):
        score += 25
    score += summary.get("method_count", 0) * 4
    score += summary.get("property_count", 0) * 3
    score += summary.get("async_method_count", 0) * 5
    score += summary.get("metadata_method_count", 0) * 4
    score += summary.get("objc_runtime_artifact_count", 0) * 2
    score += summary.get("objc_bridge_method_count", 0) * 4
    score += summary.get("associated_conformance_count", 0) * 2
    score += min(20, len(surface.get("related_strings", [])))
    score -= type_name_noise_penalty(type_name)
    return score


def rank_surfaces(surfaces: List[Dict[str, Any]], program_name: str) -> List[Dict[str, Any]]:
    for surface in surfaces:
        surface["surface_score"] = score_surface(surface, program_name)
    return sorted(
        surfaces,
        key=lambda item: (
            -item.get("surface_score", 0),
            -item.get("summary", {}).get("method_count", 0),
            -item.get("summary", {}).get("objc_runtime_artifact_count", 0),
            item["type_name"].lower(),
        ),
    )


def surface_identity_key(surface: Dict[str, Any]) -> str:
    for bucket_name in ["objc_bridge_methods", "methods", "objc_runtime_artifacts", "metadata_methods"]:
        for entry in surface.get(bucket_name, []):
            address = (
                entry.get("canonical_address")
                or entry.get("candidate_address")
                or entry.get("address", "")
            )
            if address:
                return "addr:" + address
    bridge_names = sorted(surface.get("objc_bridge_names", []))
    if bridge_names:
        return "bridge:" + "|".join(bridge_names)
    return "type:" + surface.get("type_name", "")


def dedupe_ranked_surfaces(surfaces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    result: List[Dict[str, Any]] = []
    for surface in surfaces:
        marker = surface_identity_key(surface)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(surface)
    return result


def property_hints_from_strings(type_name: str, strings_doc: Dict[str, Any],
                                extra_terms=None) -> List[Dict[str, Any]]:
    hints = []
    for entry in related_strings(type_name, strings_doc, extra_terms=extra_terms, limit=200):
        value = entry.get("value", "")
        candidates = []
        if re.match(r"^[a-z][A-Za-z0-9_]{2,}$", value):
            candidates.append(value)
        for match in re.finditer(r"V_([A-Za-z_][A-Za-z0-9_]*)", value):
            candidates.append(match.group(1))
        if re.match(r"^_[a-z][A-Za-z0-9_]*$", value):
            candidates.append(value[1:])
        for candidate in candidates:
            if candidate.lower() == short_type_name(type_name).lower():
                continue
            hints.append(
                {
                    "name": candidate,
                    "address": entry.get("address", ""),
                    "artifact_type": entry.get("artifact_type", ""),
                    "xref_count": entry.get("xref_count", 0),
                }
            )
    return unique_by_key(hints, "name")


def properties_from_runtime_artifacts(type_name: str,
                                      runtime_artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    properties: List[Dict[str, Any]] = []
    for artifact in runtime_artifacts:
        labels = [
            artifact.get("stable_alias", ""),
            artifact.get("demangled", ""),
            artifact.get("name", ""),
        ]
        for label in labels:
            match = PROPERTY_DESCRIPTOR_RE.search(label)
            if not match:
                continue
            descriptor_type = match.group("type")
            descriptor_property = match.group("property")
            if not descriptor_property:
                continue
            if descriptor_type != type_name and short_type_name(descriptor_type) != short_type_name(type_name):
                continue
            properties.append(
                {
                    "name": artifact.get("name", ""),
                    "display_name": artifact.get("demangled", "") or artifact.get("name", ""),
                    "demangled": artifact.get("demangled", "") or artifact.get("name", ""),
                    "address": artifact.get("address", ""),
                    "canonical_address": artifact.get("canonical_address", artifact.get("address", "")),
                    "source": "runtime_property_descriptor",
                    "stable_alias": f"{type_name}.{descriptor_property}",
                    "member_name": descriptor_property,
                    "symbol_kind": "runtime_property_descriptor",
                    "objc_bridge_name": artifact.get("objc_bridge_name", ""),
                    "xref_count": artifact.get("xref_count", 0),
                }
            )
            break
    return unique_by_key(properties, "stable_alias")


def objc_bridge_methods_for_type(type_name: str, objc: Dict[str, Any],
                                 symbols_doc: Dict[str, Any],
                                 bridge_names: List[str],
                                 symbol_indexes: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None
                                 ) -> List[Dict[str, Any]]:
    known_classes = set(objc.get("interface_classes", []) or [])
    known_classes.update(objc.get("classes", []))
    known_classes.update(objc.get("metaclasses", []))
    allowed = set(bridge_names)
    methods = []
    if symbol_indexes:
        method_items = []
        seen_items = set()
        for class_name in allowed:
            for item in symbol_indexes.get("objc_methods_by_class", {}).get(class_name, []):
                marker = item.get("name", "") + "|" + item.get("address", "")
                if marker in seen_items:
                    continue
                seen_items.add(marker)
                method_items.append(item)
    else:
        method_items = symbols_doc.get("objc_related", [])
    for item in method_items:
        parsed = parse_objc_method_name(item.get("name", ""), known_classes)
        if not parsed:
            continue
        if parsed["class_name"] not in allowed:
            continue
        selector = parsed["selector"]
        record = {
            "name": item.get("name", ""),
            "display_name": item.get("name", ""),
            "demangled": item.get("name", ""),
            "address": item.get("address", ""),
            "canonical_address": item.get("address", ""),
            "source": "objc_bridge",
            "stable_alias": f"{type_name}.{selector}",
            "member_name": selector,
            "symbol_kind": "objc_bridge_method",
            "objc_class_name": parsed["class_name"],
            "xref_count": item.get("xref_count", 0),
        }
        methods.append(record)
    return unique_by_key(methods, "stable_alias")
