"""Swift surface construction and search helpers."""

from python_lib.ghidra_swift_surface_core import *  # noqa: F403

def build_surface_types(swift: Dict[str, Any], objc: Dict[str, Any], symbols_doc: Dict[str, Any],
                        strings_doc: Dict[str, Any], focus_query: str = "") -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    symbol_indexes = build_symbol_indexes(objc, symbols_doc)
    inferred_types = inferred_surface_types(swift, symbols_doc, strings_doc)
    if focus_query:
        lowered = focus_query.lower()
        focused = [
            type_name
            for type_name in inferred_types
            if lowered == type_name.lower()
            or lowered == short_type_name(type_name).lower()
            or lowered in type_name.lower()
            or lowered in short_type_name(type_name).lower()
        ]
        for candidate in extract_type_candidates_from_text(focus_query):
            if candidate not in focused:
                focused.append(candidate)
        if valid_surface_type_name(focus_query) and focus_query not in focused:
            focused.append(focus_query)
        inferred_types = focused
    inferred_types = select_candidate_types(
        inferred_types, swift.get("program_name", ""), focus_query
    )
    allowed_type_names = set(inferred_types)
    for type_name in inferred_types:
        if not valid_surface_type_name(type_name):
            continue
        grouped.setdefault(type_name, empty_surface(type_name))
    for symbol in swift.get("symbols", []):
        type_name = recover_surface_type_name(symbol)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        entry = {
            "name": symbol.get("name", ""),
            "demangled": symbol.get("demangled", ""),
            "display_name": symbol.get("display_name", ""),
            "address": symbol.get("address", ""),
            "canonical_address": symbol.get("canonical_address", symbol.get("thunk_target_address", symbol.get("address", ""))),
            "source": symbol.get("source", ""),
            "stable_alias": symbol.get("stable_alias", ""),
            "member_name": symbol.get("member_name", ""),
            "symbol_kind": symbol.get("symbol_kind", ""),
            "thunk": bool(symbol.get("thunk", False)),
            "thunk_target_name": symbol.get("thunk_target_name", ""),
            "thunk_target_address": symbol.get("thunk_target_address", ""),
        }
        surface["raw_symbols"].append(entry)
        kind = entry["symbol_kind"]
        member_name = entry["member_name"]
        if kind == "property_accessor":
            surface["properties"].append(entry)
        elif kind == "metadata_accessor":
            surface["metadata_accessors"].append(entry)
        elif kind == "protocol_witness":
            surface["protocol_witnesses"].append(entry)
        elif kind == "dispatch_thunk":
            surface["dispatch_thunks"].append(entry)
            surface["methods"].append(entry)
        else:
            surface["methods"].append(entry)
        if symbol.get("async_like"):
            surface["async_methods"].append(entry)
        if member_name.startswith("init(") or member_name.startswith("__allocating_init("):
            surface["init_methods"].append(entry)
        if member_name.startswith("deinit"):
            surface["deinit_methods"].append(entry)
        if member_name.startswith("start(") or member_name.startswith("start()"):
            surface["start_methods"].append(entry)

    for entry in swift.get("metadata_methods", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        record = {
            "name": entry.get("name", ""),
            "demangled": entry.get("demangled", ""),
            "display_name": entry.get("display_name", ""),
            "address": entry.get("address", ""),
            "canonical_address": entry.get("canonical_address", entry.get("address", "")),
            "source": entry.get("source", ""),
            "stable_alias": entry.get("stable_alias", ""),
            "member_name": entry.get("member_name", ""),
            "symbol_kind": entry.get("symbol_kind", ""),
            "artifact_role": entry.get("artifact_role", "metadata_method"),
            "implementation_chain": entry.get("implementation_chain", []),
        }
        surface["metadata_methods"].append(record)
        surface["methods"].append(record)
        member_name = record["member_name"]
        if member_name.startswith("init(") or member_name.startswith("__allocating_init("):
            surface["init_methods"].append(record)
        if member_name.startswith("deinit"):
            surface["deinit_methods"].append(record)
        if member_name.startswith("start(") or member_name.startswith("start()"):
            surface["start_methods"].append(record)

    for entry in swift.get("property_records", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        record = {
            "name": entry.get("name", ""),
            "demangled": entry.get("demangled", ""),
            "display_name": entry.get("display_name", ""),
            "address": entry.get("address", ""),
            "canonical_address": entry.get("canonical_address", entry.get("address", "")),
            "source": entry.get("source", ""),
            "stable_alias": entry.get("stable_alias", ""),
            "member_name": entry.get("member_name", ""),
            "symbol_kind": entry.get("symbol_kind", "property_record"),
            "objc_bridge_name": entry.get("objc_bridge_name", ""),
            "readonly": bool(entry.get("readonly", False)),
        }
        surface["properties"].append(record)

    for entry in swift.get("protocol_requirements", []):
        type_name = recover_surface_type_name(
            entry, entry.get("type_name") or entry.get("protocol_name") or ""
        )
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["protocol_requirements"].append(entry)
        if entry.get("kind") == "associated_type":
            surface["associated_types"].append(entry)

    for entry in swift.get("associated_conformances", []):
        type_name = recover_surface_type_name(
            entry, entry.get("type_name") or entry.get("protocol_name") or ""
        )
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        record = dict(entry)
        if not record.get("stable_alias"):
            record["stable_alias"] = associated_conformance_label(record)
        surface["associated_conformances"].append(record)

    for entry in swift.get("code_candidates", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["code_candidates"].append(entry)
        for candidate in surface["code_candidates"]:
            if candidate.get("candidate_address") and not candidate.get("canonical_address"):
                candidate["canonical_address"] = candidate.get("candidate_address", "")
            if candidate.get("candidate_address") and not candidate.get("address"):
                candidate["address"] = candidate.get("candidate_address", "")

    for entry in swift.get("runtime_artifacts", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["objc_runtime_artifacts"].append(
            {
                "name": entry.get("name", ""),
                "demangled": entry.get("demangled", ""),
                "address": entry.get("address", ""),
                "artifact_type": entry.get("symbol_kind", ""),
                "xref_count": entry.get("xref_count", 0),
                "objc_bridge_name": entry.get("objc_bridge_name", ""),
                "stable_alias": entry.get("stable_alias", ""),
            }
        )

    for entry in swift.get("async_relationships", []):
        type_name = recover_surface_type_name(entry)
        if not valid_surface_type_name(type_name):
            continue
        if allowed_type_names is not None and type_name not in allowed_type_names:
            continue
        surface = grouped.setdefault(type_name, empty_surface(type_name))
        surface["async_helpers"].append(entry)

    conformance_hits = swift.get("protocol_conformances", [])
    for surface in grouped.values():
        type_name = surface["type_name"]
        surface["protocol_conformances"] = list(dict.fromkeys([
            value for value in conformance_hits if type_name in value or short_type_name(type_name) in value
        ]))
        surface["objc_bridge_names"] = bridge_names_for_surface(type_name, objc, surface)
        bridge_names = surface["objc_bridge_names"]
        surface["related_strings"] = related_strings(type_name, strings_doc, extra_terms=bridge_names)
        surface["related_symbols"] = related_symbols(
            type_name, symbols_doc, extra_terms=bridge_names, symbol_indexes=symbol_indexes
        )
        surface["objc_runtime_artifacts"].extend(
            objc_runtime_artifacts_for_type(
                type_name, objc, symbols_doc, bridge_names, symbol_indexes=symbol_indexes
            )
        )
        surface["properties"].extend(
            properties_from_runtime_artifacts(type_name, surface["objc_runtime_artifacts"])
        )
        surface["property_hints"] = property_hints_from_strings(
            type_name, strings_doc, extra_terms=bridge_names
        )
        surface["objc_bridge_methods"] = objc_bridge_methods_for_type(
            type_name, objc, symbols_doc, bridge_names, symbol_indexes=symbol_indexes
        )
        surface["methods"].extend(surface["objc_bridge_methods"])
        for key in [
            "methods",
            "properties",
            "async_methods",
            "dispatch_thunks",
            "metadata_accessors",
            "metadata_methods",
            "protocol_witnesses",
            "protocol_requirements",
            "associated_types",
            "associated_conformances",
            "code_candidates",
            "async_helpers",
            "init_methods",
            "deinit_methods",
            "start_methods",
            "raw_symbols",
            "objc_bridge_methods",
            "objc_runtime_artifacts",
            "property_hints",
        ]:
            surface[key] = unique_by_key(surface[key], "stable_alias")
        surface["summary"] = {
            "method_count": len(surface["methods"]),
            "property_count": len(surface["properties"]),
            "async_method_count": len(surface["async_methods"]),
            "dispatch_thunk_count": len(surface["dispatch_thunks"]),
            "metadata_method_count": len(surface["metadata_methods"]),
            "protocol_witness_count": len(surface["protocol_witnesses"]),
            "protocol_requirement_count": len(surface["protocol_requirements"]),
            "associated_type_count": len(surface["associated_types"]),
            "associated_conformance_count": len(surface["associated_conformances"]),
            "code_candidate_count": len(surface["code_candidates"]),
            "objc_bridge_count": len(surface["objc_bridge_names"]),
            "objc_bridge_method_count": len(surface["objc_bridge_methods"]),
            "objc_runtime_artifact_count": len(surface["objc_runtime_artifacts"]),
            "property_hint_count": len(surface["property_hints"]),
        }

    return sorted(grouped.values(), key=lambda item: item["type_name"].lower())


def find_surface(surfaces: List[Dict[str, Any]], query: str) -> Optional[Dict[str, Any]]:
    if not query:
        return None
    lowered = query.lower()
    exact = [surface for surface in surfaces if surface["type_name"].lower() == lowered or surface["short_name"].lower() == lowered]
    if exact:
        return exact[0]
    contains = [
        surface
        for surface in surfaces
        if lowered in surface["type_name"].lower()
        or lowered in surface["short_name"].lower()
        or any(lowered in candidate.lower() for candidate in surface.get("objc_bridge_names", []))
    ]
    return contains[0] if contains else None


def search_swift_surface(surfaces: List[Dict[str, Any]], query: str) -> Dict[str, Any]:
    lowered = query.lower()
    candidates: List[Dict[str, Any]] = []
    for surface in surfaces:
        type_name = surface["type_name"]
        short_name = surface["short_name"]
        type_score = 0
        if lowered == type_name.lower() or lowered == short_name.lower():
            type_score = 260
        elif lowered in type_name.lower() or lowered in short_name.lower():
            type_score = 180

        if type_score:
            candidates.append(
                {
                    "score": type_score,
                    "kind": "type",
                    "type_name": type_name,
                    "label": type_name,
                    "address": "",
                    "canonical_address": "",
                    "symbol": None,
                }
            )

        for bucket_name in [
            "methods",
            "properties",
            "async_methods",
            "dispatch_thunks",
            "metadata_accessors",
            "metadata_methods",
            "protocol_witnesses",
            "protocol_requirements",
            "associated_conformances",
            "code_candidates",
            "objc_bridge_methods",
            "objc_runtime_artifacts",
            "property_hints",
            "init_methods",
            "deinit_methods",
            "start_methods",
        ]:
            for entry in surface.get(bucket_name, []):
                labels = [
                    entry.get("stable_alias", ""),
                    entry.get("display_name", ""),
                    entry.get("demangled", ""),
                    entry.get("name", ""),
                    entry.get("associated_type", ""),
                    entry.get("conforming_type", ""),
                    entry.get("concrete_type", ""),
                    f"{type_name}.{entry.get('member_name', '')}",
                    f"{short_name}.{entry.get('member_name', '')}",
                ]
                labels = [label for label in labels if label]
                score = 0
                for label in labels:
                    label_lower = label.lower()
                    if lowered == label_lower:
                        score = max(score, 200)
                    elif label_lower.endswith("." + lowered):
                        score = max(score, 180)
                    elif lowered in label_lower:
                        score = max(score, 120)
                if score == 0:
                    continue
                if bucket_name in {"methods", "metadata_methods", "objc_bridge_methods"}:
                    score += 40
                elif bucket_name == "objc_runtime_artifacts":
                    score += 15
                elif bucket_name in {"associated_conformances", "property_hints"}:
                    score -= 60
                elif bucket_name in {"protocol_requirements", "protocol_witnesses"}:
                    score -= 15
                if bucket_name == "dispatch_thunks" and entry.get("thunk_target_address"):
                    score += 10
                if bucket_name == "start_methods":
                    score += 15
                if bucket_name == "async_methods":
                    score += 8
                candidates.append(
                    {
                        "score": score,
                        "kind": bucket_name,
                        "type_name": type_name,
                        "label": entry.get("stable_alias") or entry.get("display_name") or entry.get("name") or entry.get("associated_type") or entry.get("conforming_type"),
                        "address": entry.get("address", entry.get("candidate_address", "")),
                        "canonical_address": entry.get("canonical_address", entry.get("candidate_address", entry.get("address", ""))),
                        "symbol": entry,
                    }
                )

    candidates.sort(
        key=lambda item: (
            -item["score"],
            item["type_name"].lower(),
            item["label"].lower(),
            item["canonical_address"],
        )
    )
    return {"query": query, "match_count": len(candidates), "matches": candidates[:50]}


def choose_live_entry(surface: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for bucket in [
        "start_methods",
        "async_methods",
        "init_methods",
        "methods",
        "metadata_methods",
        "metadata_accessors",
        "dispatch_thunks",
        "code_candidates",
        "objc_bridge_methods",
        "objc_runtime_artifacts",
        "property_hints",
        "protocol_requirements",
        "associated_conformances",
        "associated_types",
        "related_symbols",
    ]:
        entries = surface.get(bucket, [])
        if entries:
            if bucket == "code_candidates":
                entries = sorted(
                    entries,
                    key=lambda entry: (
                        0 if entry.get("function_address") or entry.get("instruction_address") or entry.get("candidate_executable") else 1,
                        0 if entry.get("canonical_address") else 1,
                        entry.get("canonical_address", entry.get("candidate_address", entry.get("address", ""))),
                    ),
                )
            if bucket == "objc_runtime_artifacts":
                entries = sorted(
                    entries,
                    key=lambda entry: (
                        0 if "__INSTANCE_METHODS_" in entry.get("name", "") else
                        1 if "__PROPERTIES_" in entry.get("name", "") else
                        2 if "__IVARS_" in entry.get("name", "") else
                        3 if "_OBJC_CLASS_" in entry.get("name", "") else
                        4,
                        entry.get("name", ""),
                    ),
                )
            return entries[0]
    return None
