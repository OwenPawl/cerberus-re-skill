"""CLI rendering for the Swift surface backend compatibility script."""

import json
import sys

from python_lib.ghidra_swift_surface_build import *  # noqa: F403
from python_lib.ghidra_swift_surface_core import *  # noqa: F403

def render_markdown(payload: Dict[str, Any]) -> str:
    lines = []
    query = payload.get("query", "")
    if query:
        lines.append(f"# Swift Surface Report: {query}")
    else:
        lines.append("# Swift Surface Report")
        candidate_count = payload.get("candidate_type_count", 0)
        returned_count = payload.get("returned_type_count", len(payload.get("types", [])))
        if candidate_count:
            lines.append(
                f"Showing top {returned_count} of {candidate_count} inferred surfaces"
            )
        namespaces = payload.get("preferred_namespaces", [])
        if namespaces:
            lines.append("Preferred namespaces: " + ", ".join(namespaces))
    for surface in payload.get("types", []):
        lines.append("")
        lines.append(f"## {surface['type_name']}")
        summary = surface.get("summary", {})
        lines.append(
            f"- methods: {summary.get('method_count', 0)}"
            f", properties: {summary.get('property_count', 0)}"
            f", async: {summary.get('async_method_count', 0)}"
            f", thunks: {summary.get('dispatch_thunk_count', 0)}"
            f", requirements: {summary.get('protocol_requirement_count', 0)}"
        )
        if "surface_score" in surface:
            lines.append(f"- score: {surface['surface_score']}")
        if surface.get("objc_bridge_names"):
            lines.append("- objc bridges: " + ", ".join(surface["objc_bridge_names"]))
        if surface.get("property_hints"):
            lines.append("- property hints: " + ", ".join(
                entry.get("name", "") for entry in surface["property_hints"][:10] if entry.get("name")
            ))
        if surface.get("protocol_conformances"):
            lines.append("- conformances: " + ", ".join(surface["protocol_conformances"][:10]))
        if surface.get("associated_types"):
            lines.append("- associated types: " + ", ".join(
                entry.get("associated_type", "") for entry in surface["associated_types"][:10]
                if entry.get("associated_type", "")
            ))
        if surface.get("associated_conformances"):
            labels = []
            for entry in surface["associated_conformances"][:8]:
                label = associated_conformance_label(entry)
                if label:
                    labels.append(label)
            if labels:
                lines.append("- associated conformances: " + ", ".join(dict.fromkeys(labels)))
        for bucket_name, title in [
            ("start_methods", "start"),
            ("async_methods", "async"),
            ("methods", "methods"),
            ("metadata_methods", "metadata methods"),
            ("properties", "properties"),
            ("dispatch_thunks", "dispatch thunks"),
            ("protocol_witnesses", "protocol witnesses"),
            ("protocol_requirements", "protocol requirements"),
            ("code_candidates", "code candidates"),
            ("objc_bridge_methods", "objc bridge methods"),
            ("objc_runtime_artifacts", "objc runtime artifacts"),
            ("property_hints", "property hints"),
        ]:
            entries = surface.get(bucket_name, [])
            if not entries:
                continue
            lines.append(f"- {title}:")
            for entry in entries[:8]:
                label = (
                    entry.get("stable_alias")
                    or entry.get("display_name")
                    or entry.get("name")
                    or entry.get("associated_type")
                    or entry.get("conforming_type")
                )
                address = (
                    entry.get("canonical_address")
                    or entry.get("candidate_address")
                    or entry.get("address", "")
                )
                lines.append(f"  - {label} @ {address}")
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    if len(sys.argv) < 7:
        print(
            "Usage: ghidra_swift_surface_backend.py <mode> <swift_json> <objc_json> <symbols_json> <strings_json> <query> [format]",
            file=sys.stderr,
        )
        return 1

    mode = sys.argv[1]
    swift = load_json(sys.argv[2])
    objc = load_json(sys.argv[3])
    symbols_doc = load_json(sys.argv[4])
    strings_doc = load_json(sys.argv[5])
    query = sys.argv[6]
    output_format = sys.argv[7] if len(sys.argv) > 7 else "json"

    focus_query = query if mode in {"type", "search"} or (mode == "report" and query) else ""
    surfaces = build_surface_types(swift, objc, symbols_doc, strings_doc, focus_query=focus_query)

    if mode == "report":
        if query:
            types = [
            surface for surface in surfaces
            if query.lower() in surface["type_name"].lower()
            or query.lower() in surface["short_name"].lower()
            or any(query.lower() in value.lower() for value in surface.get("objc_bridge_names", []))
            ]
            types = rank_surfaces(types, swift.get("program_name", ""))
            types = dedupe_ranked_surfaces(types)
            if types:
                min_score = max(120, types[0].get("surface_score", 0) - 100)
                types = [surface for surface in types if surface.get("surface_score", 0) >= min_score]
            types = types[:10]
        else:
            ranked = rank_surfaces(surfaces, swift.get("program_name", ""))
            types = ranked[:25]
        payload = {
            "query": query,
            "type_count": len(types),
            "candidate_type_count": len(surfaces),
            "returned_type_count": len(types),
            "preferred_namespaces": preferred_namespaces(swift.get("program_name", "")),
            "types": types,
            "alias_map": swift.get("alias_map", {}),
            "metadata_sections": swift.get("metadata_sections", {}),
        }
        if output_format == "markdown":
            print(render_markdown(payload))
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if mode == "type":
        surface = find_surface(surfaces, query)
        payload = {
            "query": query,
            "type": surface,
            "selected_entry": choose_live_entry(surface) if surface else None,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if mode == "search":
        payload = search_swift_surface(surfaces, query)
        print(json.dumps(payload, indent=2))
        return 0

    print(f"unsupported mode: {mode}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
