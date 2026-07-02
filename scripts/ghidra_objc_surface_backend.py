#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
from collections import Counter, defaultdict


OBJC_METHOD_RE = re.compile(r"^([+-])\[(.+?) ([^\]]+)\]$")
OBJC_METHOD_BODY_RE = re.compile(r"^([+-])\[(.+)\]$")
PROTOCOL_WRAPPER_PATTERNS = [
    "_OBJC_PROTOCOL_$_",
    "__OBJC_PROTOCOL_$_",
    "__OBJC_LABEL_PROTOCOL_$_",
    "__OBJC_PROTOCOL_REFERENCE_$_",
    "__OBJC_$_PROTOCOL_INSTANCE_METHODS_",
    "__OBJC_$_PROTOCOL_CLASS_METHODS_",
    "__OBJC_$_PROTOCOL_REFS_",
    "__OBJC_$_PROTOCOL_METHOD_TYPES_",
    "$$protocol_requirements_base_descriptor_for_",
    "protocol_requirements_base_descriptor_for_",
]


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def unique_records(records, key_fn):
    seen = set()
    output = []
    for record in records:
        key = key_fn(record)
        if key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output


def short_swift_name(value):
    if not value:
        return ""
    if "::" in value:
        value = value.split("::")[-1]
    if "." in value:
        value = value.split(".")[-1]
    return value


def normalize_protocol_name(value):
    value = (value or "").strip()
    if not value:
        return ""
    for prefix in PROTOCOL_WRAPPER_PATTERNS:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value.startswith("_objc_msgSend$") or value.startswith("_objc_msgLookup$"):
        return ""
    if value.startswith("associated type descriptor for "):
        value = value[len("associated type descriptor for "):]
    if value.startswith("protocol descriptor for "):
        value = value[len("protocol descriptor for "):]
    if value.startswith("$$method_descriptor_for_"):
        return ""
    if value.startswith("method_descriptor_for_"):
        return ""
    return short_swift_name(value)


def protocol_name_matches(candidate, query):
    normalized_candidate = normalize_protocol_name(candidate)
    normalized_query = normalize_protocol_name(query) or short_swift_name(query)
    if not normalized_candidate or not normalized_query:
        return False
    if normalized_candidate == normalized_query:
        return True
    return normalized_query in normalized_candidate or normalized_candidate in normalized_query


def parse_objc_method_name(name, address="", source="symbol", known_classes=None):
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
        "name": name,
        "kind": kind,
        "class_name": class_name,
        "selector": selector,
        "address": address,
        "source": source,
    }


def merged_methods(objc, symbols):
    methods = []
    known_classes = set(objc.get("interface_classes", []) or [])
    known_classes.update(objc.get("classes", []))
    known_classes.update(objc.get("metaclasses", []))
    for method in objc.get("methods", []):
        parsed = dict(method)
        parsed.setdefault("name", f"{parsed.get('kind', '-')}" +
                          f"[{parsed.get('class_name', '')} {parsed.get('selector', '')}]")
        parsed.setdefault("source", "objc_metadata")
        methods.append(parsed)
    for symbol in symbols.get("objc_related", []):
        parsed = parse_objc_method_name(
            symbol.get("name", ""),
            symbol.get("address", ""),
            symbol.get("source", "symbols"),
            known_classes,
        )
        if parsed:
            parsed["artifact_type"] = symbol.get("artifact_type", "")
            parsed["xref_count"] = symbol.get("xref_count", 0)
            parsed["sample_xrefs"] = symbol.get("sample_xrefs", [])
            methods.append(parsed)
    return unique_records(
        methods,
        lambda item: (
            item.get("address", ""),
            item.get("name", ""),
            item.get("class_name", ""),
            item.get("selector", ""),
        ),
    )


def symbol_hits_for_name(symbols, query):
    return [
        symbol for symbol in (symbols.get("objc_related", []) + symbols.get("symbols", []))
        if query in symbol.get("name", "") or protocol_name_matches(symbol.get("name", ""), query)
    ]


def recovered_protocol_hits(objc, protocol_name):
    return [
        record for record in objc.get("recovered_protocols", [])
        if protocol_name_matches(record.get("name", ""), protocol_name)
        or protocol_name_matches(record.get("raw_name", ""), protocol_name)
    ]


def methods_for_class(methods, class_name):
    return [method for method in methods if method.get("class_name") == class_name]


def methods_for_selector(methods, selector):
    return [method for method in methods if method.get("selector") == selector]


def categories_for_class(objc, class_name):
    hits = []
    for category in objc.get("categories", []):
        if category == class_name or category.startswith(class_name + "("):
            hits.append(category)
    return hits


def class_ref_hits(objc, class_name):
    hits = []
    for entry in objc.get("class_refs", []):
        name = entry.get("name", "")
        if class_name in name or name.endswith(class_name):
            hits.append(entry)
    return hits


def protocol_ref_hits(objc, protocol_name):
    hits = []
    for entry in objc.get("protocol_refs", []):
        name = entry.get("name", "")
        if protocol_name_matches(name, protocol_name):
            hits.append(entry)
    return hits


def selector_ref_hits(objc, selector):
    hits = []
    for entry in objc.get("selector_refs", []):
        name = entry.get("name", "")
        if name == selector or name.endswith(selector):
            hits.append(entry)
    return hits


def selector_string_hits(objc, strings, selector):
    hits = [
        entry for entry in objc.get("selector_strings", [])
        if entry.get("value") == selector
    ]
    hits.extend(
        entry for entry in strings.get("strings", [])
        if entry.get("value") == selector or entry.get("string_value") == selector
    )
    return unique_records(hits, lambda item: (item.get("address", ""), item.get("value", ""), item.get("string_value", "")))


def swift_protocol_hits(swift, protocol_name):
    conformances = []
    for record in swift.get("associated_conformances", []):
        if protocol_name_matches(record.get("protocol_name", ""), protocol_name) or \
           protocol_name_matches(record.get("type_name", ""), protocol_name):
            conformances.append(record)
    for record in swift.get("protocol_requirements", []):
        if protocol_name_matches(record.get("protocol_name", ""), protocol_name) or \
           protocol_name_matches(record.get("type_name", ""), protocol_name):
            conformances.append(record)
    for record in swift.get("protocol_conformances", []):
        if protocol_name_matches(str(record), protocol_name):
            conformances.append({"kind": "protocol_conformance", "value": record})
    return conformances


def class_payload(objc, symbols, strings, swift, class_name):
    methods = merged_methods(objc, symbols)
    class_methods = methods_for_class(methods, class_name)
    symbol_hits = symbol_hits_for_name(symbols, class_name)
    swift_bridge_types = set()
    swift_bridge_protocols = set()
    alias_map = swift.get("alias_map", {})
    if isinstance(alias_map, dict):
        for alias, canonical in alias_map.items():
            if class_name in alias or class_name in str(canonical):
                swift_bridge_types.add(alias)
                swift_bridge_types.add(str(canonical))
    aliases = swift.get("aliases", {})
    if isinstance(aliases, dict):
        for alias, canonical in aliases.items():
            if class_name in alias or class_name in str(canonical):
                swift_bridge_types.add(alias)
                swift_bridge_types.add(str(canonical))
    elif isinstance(aliases, list):
        for alias in aliases:
            if class_name in str(alias):
                swift_bridge_types.add(str(alias))
    for record in swift.get("protocol_conformances", []):
        record_text = str(record)
        if class_name in record_text or f"__C.{class_name}" in record_text:
            normalized = normalize_protocol_name(record_text)
            if normalized:
                swift_bridge_protocols.add(normalized)
    return {
        "class_name": class_name,
        "declared": class_name in (objc.get("interface_classes", []) or []) or class_name in objc.get("classes", []),
        "interface_declared": class_name in (objc.get("interface_classes", []) or []),
        "runtime_bucket_declared": class_name in objc.get("classes", []),
        "metaclass_declared": class_name in objc.get("metaclasses", []),
        "class_name_entries": [entry for entry in objc.get("class_names", []) if entry.get("value") == class_name],
        "categories": categories_for_class(objc, class_name),
        "class_ref_hits": class_ref_hits(objc, class_name),
        "method_count": len(class_methods),
        "methods": class_methods,
        "selectors": sorted({method.get("selector", "") for method in class_methods if method.get("selector")}),
        "symbol_hits": symbol_hits,
        "protocol_hits": [
            hit for hit in swift.get("protocol_conformances", [])
            if class_name in hit
        ],
        "swift_bridge_types": sorted(swift_bridge_types)[:20],
        "swift_bridge_protocols": sorted(swift_bridge_protocols)[:20],
    }


def selector_payload(objc, symbols, strings, selector, live_trace=None):
    methods = merged_methods(objc, symbols)
    method_matches = methods_for_selector(methods, selector)
    live_result = {}
    if isinstance(live_trace, dict) and live_trace.get("ok"):
        live_result = live_trace.get("result", {})
    return {
        "selector": selector,
        "implementation_count": len(method_matches),
        "candidate_classes": sorted({method.get("class_name", "") for method in method_matches if method.get("class_name")}),
        "implementations": method_matches,
        "selector_ref_hits": selector_ref_hits(objc, selector),
        "string_hits": selector_string_hits(objc, strings, selector),
        "live_trace": live_result,
    }


def protocol_payload(objc, symbols, swift, protocol_name):
    normalized_name = normalize_protocol_name(protocol_name) or protocol_name
    explicit = any(protocol_name_matches(name, normalized_name) for name in objc.get("protocols", []))
    recovered = recovered_protocol_hits(objc, protocol_name)
    symbol_hits = symbol_hits_for_name(symbols, protocol_name)
    swift_hits = swift_protocol_hits(swift, protocol_name)
    protocol_refs = protocol_ref_hits(objc, protocol_name)
    method_descriptor_hits = [
        hit for hit in protocol_refs
        if "INSTANCE_METHODS" in hit.get("name", "") or "CLASS_METHODS" in hit.get("name", "")
    ]
    swift_conforming_types = sorted({
        short_swift_name(hit.get("conforming_type", ""))
        for hit in swift_hits
        if isinstance(hit, dict) and hit.get("conforming_type")
    })
    swift_related_types = sorted({
        short_swift_name(hit.get("type_name", ""))
        for hit in swift_hits
        if isinstance(hit, dict) and hit.get("type_name")
    })
    return {
        "protocol_name": normalized_name,
        "explicit_declared": explicit,
        "recovered_declared": bool(recovered),
        "recovered_hits": recovered,
        "protocol_ref_hits": protocol_refs,
        "symbol_hits": symbol_hits,
        "swift_hits": swift_hits,
        "method_descriptor_hits": method_descriptor_hits,
        "swift_conforming_types": swift_conforming_types,
        "swift_related_types": swift_related_types,
    }


def classref_payload(objc, symbols, class_name, live_trace=None):
    live_result = {}
    if isinstance(live_trace, dict) and live_trace.get("ok"):
        live_result = live_trace.get("result", {})
    return {
        "class_name": class_name,
        "class_ref_hits": class_ref_hits(objc, class_name),
        "symbol_hits": symbol_hits_for_name(symbols, class_name),
        "live_xrefs": live_result,
    }


def class_selector_summary(methods, class_name, limit=12):
    class_methods = methods_for_class(methods, class_name)
    selector_counter = Counter()
    for method in class_methods:
        selector = method.get("selector") or ""
        if selector:
            selector_counter[selector] += 1
    sample_methods = sorted(
        class_methods,
        key=lambda item: (item.get("selector", ""), item.get("address", "")),
    )[:limit]
    return {
        "class_name": class_name,
        "method_count": len(class_methods),
        "top_selectors": [
            {"selector": selector, "count": count}
            for selector, count in selector_counter.most_common(limit)
        ],
        "sample_methods": sample_methods,
    }


def message_flow_payload(objc, symbols, strings, selector, live_trace=None, class_name=""):
    methods = merged_methods(objc, symbols)
    implementations = methods_for_selector(methods, selector)
    if class_name:
        implementations = [
            method for method in implementations
            if method.get("class_name") == class_name
        ]
    receiver_classes = sorted({
        method.get("class_name", "")
        for method in implementations
        if method.get("class_name")
    })
    live_result = {}
    if isinstance(live_trace, dict) and live_trace.get("ok"):
        live_result = live_trace.get("result", {})
    sender_functions = live_result.get("sender_functions", []) if isinstance(live_result, dict) else []
    sender_callsites = live_result.get("sender_callsites", []) if isinstance(live_result, dict) else []
    selector_strings = live_result.get("selector_string_matches", []) if isinstance(live_result, dict) else []
    if not selector_strings:
        selector_strings = selector_string_hits(objc, strings, selector)
    return {
        "selector": selector,
        "class_filter": class_name,
        "implementation_count": len(implementations),
        "receiver_classes": receiver_classes,
        "implementations": implementations,
        "receiver_class_summaries": [
            class_selector_summary(methods, receiver, 10)
            for receiver in receiver_classes[:12]
        ],
        "selector_ref_hits": selector_ref_hits(objc, selector),
        "selector_string_hits": selector_strings,
        "sender_function_count": len(sender_functions),
        "sender_functions": sender_functions,
        "sender_callsites": sender_callsites,
    }


def split_objc_words(class_name):
    prefix_match = re.match(r"^([A-Z]{2,4})(.*)$", class_name)
    if prefix_match:
        prefix, remainder = prefix_match.groups()
    else:
        prefix, remainder = "", class_name
    words = re.findall(r"[A-Z][a-z0-9]*|[A-Z]+(?![a-z])", remainder)
    if prefix:
        return [prefix] + words
    return words


def subsystem_key_for_class(class_name):
    words = split_objc_words(class_name)
    if len(words) >= 3:
        return "".join(words[:3])
    if len(words) >= 2:
        return "".join(words[:2])
    return class_name


def surface_payload(objc, symbols, strings):
    methods = merged_methods(objc, symbols)
    class_counter = Counter()
    selector_counter = Counter()
    subsystem_counter = Counter()
    for method in methods:
        class_name = method.get("class_name") or ""
        selector = method.get("selector") or ""
        if class_name:
            class_counter[class_name] += 1
            subsystem_counter[subsystem_key_for_class(class_name)] += 1
        if selector:
            selector_counter[selector] += 1
    def keep_protocol(name):
        normalized = normalize_protocol_name(name)
        if not normalized:
            return False
        if normalized.startswith("$$") or normalized.startswith("_OBJC_") or normalized.startswith("__OBJC_"):
            return False
        if "::" in normalized or "PROTOCOL_" in normalized:
            return False
        return True

    protocol_names = set(
        normalize_protocol_name(name) for name in objc.get("protocols", [])
        if keep_protocol(name)
    )
    protocol_names.update(
        normalize_protocol_name(record.get("name", "")) for record in objc.get("recovered_protocols", [])
        if keep_protocol(record.get("name", ""))
    )
    protocol_names.discard("")
    return {
        "program_name": objc.get("program_name"),
        "class_count": len(objc.get("interface_classes", []) or objc.get("classes", [])),
        "protocol_count": len(protocol_names),
        "category_count": len(objc.get("categories", [])),
        "selector_count": len(objc.get("selectors", [])),
        "class_ref_count": len(objc.get("class_refs", [])),
        "selector_ref_count": len(objc.get("selector_refs", [])),
        "protocol_ref_count": len(objc.get("protocol_refs", [])),
        "top_classes": [
            {"class_name": name, "method_count": count}
            for name, count in class_counter.most_common(20)
        ],
        "top_protocols": sorted(protocol_names)[:50],
        "top_selectors": [
            {"selector": name, "implementation_count": count}
            for name, count in selector_counter.most_common(30)
        ],
        "top_subsystems": [
            {"subsystem": name, "method_count": count}
            for name, count in subsystem_counter.most_common(20)
        ],
        "sample_class_refs": objc.get("class_refs", [])[:20],
        "sample_selector_strings": objc.get("selector_strings", [])[:20],
        "sample_class_names": objc.get("class_names", [])[:20],
    }


def render_surface_markdown(payload):
    lines = []
    lines.append(f"# Objective-C Surface Report: {payload.get('program_name', 'unknown')}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Classes: {payload.get('class_count', 0)}")
    lines.append(f"- Protocols: {payload.get('protocol_count', 0)}")
    lines.append(f"- Categories: {payload.get('category_count', 0)}")
    lines.append(f"- Selectors: {payload.get('selector_count', 0)}")
    lines.append(f"- Class refs: {payload.get('class_ref_count', 0)}")
    lines.append(f"- Selector refs: {payload.get('selector_ref_count', 0)}")
    lines.append(f"- Protocol refs: {payload.get('protocol_ref_count', 0)}")
    lines.append("")
    lines.append("## Top Subsystems")
    for item in payload.get("top_subsystems", [])[:12]:
        lines.append(f"- {item['subsystem']}: {item['method_count']} methods")
    lines.append("")
    lines.append("## Top Classes")
    for item in payload.get("top_classes", [])[:12]:
        lines.append(f"- {item['class_name']}: {item['method_count']} methods")
    lines.append("")
    lines.append("## Top Selectors")
    for item in payload.get("top_selectors", [])[:15]:
        lines.append(f"- {item['selector']}: {item['implementation_count']} implementations")
    lines.append("")
    lines.append("## Top Protocols")
    for name in payload.get("top_protocols", [])[:20]:
        lines.append(f"- {name}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["surface", "class", "selector", "protocol", "classref", "message_flow"])
    parser.add_argument("--export-dir", required=True)
    parser.add_argument("--query", default="")
    parser.add_argument("--class-name", default="")
    parser.add_argument("--format", default="json", choices=["json", "markdown"])
    parser.add_argument("--trace-file", default="")
    parser.add_argument("--trace-json", default="")
    args = parser.parse_args()

    export_dir = pathlib.Path(args.export_dir)
    objc = load_json(export_dir / "objc_metadata.json")
    symbols = load_json(export_dir / "symbols.json")
    strings = load_json(export_dir / "strings.json")
    swift_path = export_dir / "swift_metadata.json"
    swift = load_json(swift_path) if swift_path.exists() else {}
    live_trace = {}
    if args.trace_file:
        trace_path = pathlib.Path(args.trace_file)
        if trace_path.is_file():
            live_trace = load_json(trace_path)
    elif args.trace_json:
        try:
            live_trace = json.loads(args.trace_json)
        except Exception:
            live_trace = {}

    if args.mode == "surface":
        payload = surface_payload(objc, symbols, strings)
    elif args.mode == "class":
        payload = class_payload(objc, symbols, strings, swift, args.query)
    elif args.mode == "selector":
        payload = selector_payload(objc, symbols, strings, args.query, live_trace)
    elif args.mode == "classref":
        payload = classref_payload(objc, symbols, args.query, live_trace)
    elif args.mode == "message_flow":
        payload = message_flow_payload(objc, symbols, strings, args.query, live_trace, args.class_name)
    else:
        payload = protocol_payload(objc, symbols, swift, args.query)

    if args.format == "markdown" and args.mode == "surface":
        print(render_surface_markdown(payload))
    else:
        print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
