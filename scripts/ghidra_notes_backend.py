#!/usr/bin/env python3

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


STATE_BEGIN = "<!-- ghidra-re:shared-notes-state-begin -->"
STATE_END = "<!-- ghidra-re:shared-notes-state-end -->"
MAX_RECENT = 25


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path, default=None):
    if not path.exists():
        return {} if default is None else default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def fingerprint_for(title: str, body: str, category: str, target: str) -> str:
    normalized = "\n".join(
        [
            normalize_text(title),
            normalize_text(body),
            normalize_text(category),
            normalize_text(target),
        ]
    )
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]


def default_remote_state(config):
    return {
        "version": 1,
        "repo": config.get("repo", ""),
        "issue_number": str(config.get("issue_number", "") or ""),
        "issue_url": config.get("issue_url", ""),
        "notes": [],
        "recently_seen": [],
        "updated_at": "",
    }


def sort_notes(notes):
    def key(note):
        status_rank = {"open": 0, "remediated": 1, "superseded": 2}.get(note.get("status", "open"), 9)
        return (
            status_rank,
            note.get("category", ""),
            note.get("title", "").lower(),
            note.get("fingerprint", ""),
        )

    return sorted(notes, key=key)


def render_note_lines(note):
    lines = []
    header = f"- **{note.get('title', 'Untitled note')}**"
    category = note.get("category", "")
    if category:
        header += f" [`{category}`]"
    target = note.get("target", "")
    if target:
        header += f" on `{target}`"
    lines.append(header)
    body = note.get("body", "").strip()
    if body:
        lines.append(f"  - {body}")
    lines.append(f"  - fingerprint: `{note.get('fingerprint', '')}`")
    lines.append(
        f"  - first seen: {note.get('first_seen_at', '')} | last seen: {note.get('last_seen_at', '')} | occurrences: {note.get('occurrence_count', 1)}"
    )
    platform = note.get("platform", "")
    skill_version = note.get("skill_version", "")
    if platform or skill_version:
        lines.append(f"  - platform: `{platform or 'unknown'}` | skill: `{skill_version or 'unknown'}`")
    metadata = note.get("session_metadata", {}) or {}
    context_bits = []
    for key in ("mission_name", "project_name", "program_name", "context_mode"):
        value = metadata.get(key, "")
        if value:
            label = key.replace("_", " ")
            context_bits.append(f"{label}: `{value}`")
    if context_bits:
        lines.append(f"  - {' | '.join(context_bits)}")
    if note.get("status") == "remediated" and note.get("remediation_summary"):
        lines.append(f"  - remediation: {note.get('remediation_summary')}")
    if note.get("status") == "superseded" and note.get("superseded_by"):
        lines.append(f"  - superseded by: `{note.get('superseded_by')}`")
    return lines


def render_issue_body(remote_state):
    notes = sort_notes(remote_state.get("notes", []))
    grouped = {"open": {}, "remediated": {}, "superseded": {}}
    for note in notes:
        status = note.get("status", "open")
        grouped.setdefault(status, {})
        grouped[status].setdefault(note.get("category", "general"), []).append(note)

    lines = [
        "# Global Use-Case Driven Notes",
        "",
        "Machine-managed shared backlog for `ghidra-re` workflow friction, missing features, and discovered quality-of-life improvements.",
        "",
        "Updates come from skill users automatically. Comments are the raw append log; the sections below are the curated state.",
        "",
        "## Open",
    ]
    if grouped["open"]:
        for category in sorted(grouped["open"]):
            lines.append(f"### {category}")
            for note in grouped["open"][category]:
                lines.extend(render_note_lines(note))
    else:
        lines.append("- No open notes.")

    lines.extend(["", "## Remediated"])
    if grouped["remediated"]:
        for category in sorted(grouped["remediated"]):
            lines.append(f"### {category}")
            for note in grouped["remediated"][category]:
                lines.extend(render_note_lines(note))
    else:
        lines.append("- No remediated notes.")

    lines.extend(["", "## Superseded"])
    if grouped["superseded"]:
        for category in sorted(grouped["superseded"]):
            lines.append(f"### {category}")
            for note in grouped["superseded"][category]:
                lines.extend(render_note_lines(note))
    else:
        lines.append("- No superseded notes.")

    lines.extend(["", "## Recently Seen"])
    recent = remote_state.get("recently_seen", [])[-MAX_RECENT:]
    if recent:
        for item in reversed(recent):
            title = item.get("title", "Untitled note")
            event = item.get("event_kind", "observe")
            fp = item.get("fingerprint", "")
            target = item.get("target", "")
            when = item.get("observed_at", "")
            pieces = [f"`{event}`", title]
            if target:
                pieces.append(f"on `{target}`")
            if fp:
                pieces.append(f"`{fp}`")
            if when:
                pieces.append(when)
            lines.append(f"- {' | '.join(pieces)}")
    else:
        lines.append("- No recent observations.")

    state_json = json.dumps(remote_state, indent=2, sort_keys=False)
    lines.extend(
        [
            "",
            STATE_BEGIN,
            "```json",
            state_json,
            "```",
            STATE_END,
            "",
        ]
    )
    return "\n".join(lines)


def extract_remote_state(body: str, config):
    if not body:
        return default_remote_state(config)
    match = re.search(
        re.escape(STATE_BEGIN) + r"\s*```json\s*(.*?)\s*```\s*" + re.escape(STATE_END),
        body,
        re.DOTALL,
    )
    if not match:
        return default_remote_state(config)
    try:
        state = json.loads(match.group(1))
    except json.JSONDecodeError:
        return default_remote_state(config)
    for key, value in default_remote_state(config).items():
        state.setdefault(key, value)
    state["notes"] = sort_notes(state.get("notes", []))
    return state


def run_gh(args, *, input_text=None):
    if shutil.which("gh") is None:
        raise RuntimeError("GitHub CLI is not installed")
    command = ["gh"] + list(args)
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "gh command failed")
    return result.stdout


def gh_authenticated():
    if shutil.which("gh") is None:
        return False
    result = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    return result.returncode == 0


def issue_url(repo: str, issue_number: str) -> str:
    if repo and issue_number:
        return f"https://github.com/{repo}/issues/{issue_number}"
    return ""


def save_config(path: Path, config):
    write_json(path, config)


def save_state(path: Path, state):
    write_json(path, state)


def load_config(path: Path):
    payload = load_json(path, {})
    payload.setdefault("version", 1)
    payload.setdefault("repo", "")
    payload.setdefault("issue_title", "Global Use-Case Driven Notes")
    payload.setdefault("issue_number", "")
    payload.setdefault("issue_url", issue_url(payload.get("repo", ""), str(payload.get("issue_number", "") or "")))
    payload.setdefault("enabled", True)
    payload.setdefault("auto_sync", True)
    return payload


def load_state(path: Path):
    payload = load_json(path, {})
    payload.setdefault("version", 1)
    payload.setdefault("last_sync_at", "")
    payload.setdefault("last_pull_at", "")
    payload.setdefault("last_error", "")
    payload.setdefault("pending_queue_count", 0)
    payload.setdefault("issue_url", "")
    payload.setdefault("issue_number", "")
    return payload


def queue_payload_path(queue_dir: Path, fingerprint: str, event_kind: str):
    return queue_dir / f"{utc_now().replace(':', '').replace('-', '')}-{event_kind}-{fingerprint}.json"


def upsert_note(existing, note):
    for key in ("title", "body", "category", "target", "platform", "skill_version"):
        if note.get(key):
            existing[key] = note[key]
    if note.get("session_metadata"):
        existing["session_metadata"] = note["session_metadata"]
    return existing


def render_comment(event_kind: str, note: dict) -> str:
    headline = {
        "observe": "Observed note",
        "seen-again": "Seen again",
        "reopened": "Reopened note",
        "remediate": "Remediated note",
        "supersede": "Superseded note",
    }.get(event_kind, "Shared note update")
    lines = [
        f"### {headline}",
        "",
        f"- fingerprint: `{note.get('fingerprint', '')}`",
        f"- title: {note.get('title', 'Untitled note')}",
        f"- category: `{note.get('category', 'general')}`",
        f"- target: `{note.get('target', '') or 'unknown'}`",
        f"- platform: `{note.get('platform', '') or 'unknown'}`",
        f"- skill version: `{note.get('skill_version', '') or 'unknown'}`",
        f"- observed at: `{note.get('observed_at', '')}`",
    ]
    metadata = note.get("session_metadata", {}) or {}
    for key in ("mission_name", "project_name", "program_name", "context_mode"):
        value = metadata.get(key, "")
        if value:
            lines.append(f"- {key.replace('_', ' ')}: `{value}`")
    lines.extend(["", note.get("body", "").strip() or "_No body provided._"])
    return "\n".join(lines).strip() + "\n"


def merge_event(remote_state, event):
    note = dict(event.get("note", {}))
    event_kind = event.get("event_kind", "observe")
    observed_at = note.get("observed_at", "") or utc_now()
    note["observed_at"] = observed_at
    note.setdefault("status", "open")
    note.setdefault("session_metadata", {})
    notes = remote_state.setdefault("notes", [])
    existing = next((item for item in notes if item.get("fingerprint") == note.get("fingerprint")), None)
    comment_kind = event_kind

    if event_kind == "observe":
        if existing is None:
            existing = dict(note)
            existing["first_seen_at"] = observed_at
            existing["last_seen_at"] = observed_at
            existing["occurrence_count"] = 1
            existing["status"] = "open"
            notes.append(existing)
        else:
            previous_status = existing.get("status", "open")
            existing = upsert_note(existing, note)
            existing["last_seen_at"] = observed_at
            existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1
            if previous_status != "open":
                existing["status"] = "open"
                existing["reopened_at"] = observed_at
                comment_kind = "reopened"
            else:
                comment_kind = "seen-again"
    elif event_kind == "remediate":
        if existing is None:
            existing = dict(note)
            existing["first_seen_at"] = observed_at
            existing["occurrence_count"] = 1
            notes.append(existing)
        else:
            existing = upsert_note(existing, note)
        existing["status"] = "remediated"
        existing["remediated_at"] = observed_at
        existing["last_seen_at"] = observed_at
        if note.get("remediation_summary"):
            existing["remediation_summary"] = note["remediation_summary"]
    elif event_kind == "supersede":
        if existing is None:
            existing = dict(note)
            existing["first_seen_at"] = observed_at
            existing["occurrence_count"] = 1
            notes.append(existing)
        else:
            existing = upsert_note(existing, note)
        existing["status"] = "superseded"
        existing["superseded_at"] = observed_at
        existing["last_seen_at"] = observed_at
        if note.get("superseded_by"):
            existing["superseded_by"] = note["superseded_by"]
    else:
        raise RuntimeError(f"unsupported event kind: {event_kind}")

    remote_state["notes"] = sort_notes(notes)
    remote_state.setdefault("recently_seen", []).append(
        {
            "fingerprint": note.get("fingerprint", ""),
            "title": note.get("title", ""),
            "category": note.get("category", ""),
            "target": note.get("target", ""),
            "status": existing.get("status", note.get("status", "open")),
            "event_kind": comment_kind,
            "observed_at": observed_at,
        }
    )
    remote_state["recently_seen"] = remote_state["recently_seen"][-MAX_RECENT:]
    remote_state["updated_at"] = utc_now()
    return remote_state, render_comment(comment_kind, existing)


def write_cache(cache_json: Path, cache_md: Path, remote_state, body_text: str):
    write_json(cache_json, remote_state)
    cache_md.parent.mkdir(parents=True, exist_ok=True)
    cache_md.write_text(body_text, encoding="utf-8")


def ensure_issue(config, config_path: Path, create=False):
    if not gh_authenticated():
        raise RuntimeError("GitHub CLI is not authenticated")

    repo = config.get("repo", "")
    issue_number = str(config.get("issue_number", "") or "")
    if issue_number:
        payload = json.loads(
            run_gh(
                [
                    "issue",
                    "view",
                    issue_number,
                    "--repo",
                    repo,
                    "--json",
                    "number,url,title,body",
                ]
            )
        )
        config["issue_url"] = payload.get("url", "")
        save_config(config_path, config)
        return payload

    search_payload = json.loads(
        run_gh(
            [
                "issue",
                "list",
                "--repo",
                repo,
                "--state",
                "all",
                "--search",
                f'{config.get("issue_title", "")} in:title',
                "--json",
                "number,title,url,body",
                "--limit",
                "50",
            ]
        )
    )
    exact = next((item for item in search_payload if item.get("title") == config.get("issue_title")), None)
    if exact is None and create:
        initial_state = default_remote_state(config)
        initial_body = render_issue_body(initial_state)
        url = run_gh(
            [
                "issue",
                "create",
                "--repo",
                repo,
                "--title",
                config.get("issue_title", "Global Use-Case Driven Notes"),
                "--body-file",
                "-",
            ],
            input_text=initial_body,
        ).strip()
        exact = json.loads(
            run_gh(
                [
                    "issue",
                    "view",
                    url,
                    "--repo",
                    repo,
                    "--json",
                    "number,title,url,body",
                ]
            )
        )
    if exact is None:
        raise RuntimeError("shared notes issue is not configured and could not be discovered")

    config["issue_number"] = str(exact.get("number", ""))
    config["issue_url"] = exact.get("url", "")
    save_config(config_path, config)
    return exact


def cmd_add(args):
    config = load_config(Path(args.config_file))
    state = load_state(Path(args.state_file))
    queue_dir = Path(args.queue_dir)
    queue_dir.mkdir(parents=True, exist_ok=True)

    note = {
        "title": args.title,
        "body": args.body,
        "category": args.category,
        "target": args.target,
        "platform": args.platform or "unknown",
        "skill_version": args.skill_version or "unknown",
        "observed_at": args.observed_at or utc_now(),
        "status": args.status,
        "fingerprint": args.fingerprint or fingerprint_for(args.title, args.body, args.category, args.target),
        "session_metadata": json.loads(args.session_metadata_json) if args.session_metadata_json else {},
    }
    if args.remediation_summary:
        note["remediation_summary"] = args.remediation_summary
    if args.superseded_by:
        note["superseded_by"] = args.superseded_by

    payload = {
        "version": 1,
        "event_kind": args.event_kind,
        "queued_at": utc_now(),
        "note": note,
    }
    path = queue_payload_path(queue_dir, note["fingerprint"], args.event_kind)
    write_json(path, payload)

    state["pending_queue_count"] = len(list(queue_dir.glob("*.json")))
    save_state(Path(args.state_file), state)
    print(json.dumps({"ok": True, "queued": True, "event_kind": args.event_kind, "queue_file": str(path), "note": note}, indent=2))


def cmd_status(args):
    config = load_config(Path(args.config_file))
    state = load_state(Path(args.state_file))
    cache = load_json(Path(args.cache_json), {"notes": [], "recently_seen": []})
    queue_dir = Path(args.queue_dir)
    queue_count = len(list(queue_dir.glob("*.json"))) if queue_dir.exists() else 0
    resolved_issue_number = str(config.get("issue_number", "") or state.get("issue_number", ""))
    resolved_issue_url = config.get("issue_url", "") or state.get("issue_url", "") or issue_url(config.get("repo", ""), resolved_issue_number)
    payload = {
        "ok": True,
        "enabled": bool(config.get("enabled", True)),
        "auto_sync": bool(config.get("auto_sync", True)),
        "repo": config.get("repo", ""),
        "issue_number": resolved_issue_number,
        "issue_url": resolved_issue_url,
        "gh_available": shutil.which("gh") is not None,
        "gh_authenticated": gh_authenticated(),
        "queue_count": queue_count,
        "last_sync_at": state.get("last_sync_at", ""),
        "last_pull_at": state.get("last_pull_at", ""),
        "last_error": state.get("last_error", ""),
        "cached_note_count": len(cache.get("notes", [])),
        "cache_json": args.cache_json,
        "cache_markdown": args.cache_md,
    }
    print(json.dumps(payload, indent=2))

def pull_or_sync(args, *, sync_mode: bool):
    config_path = Path(args.config_file)
    state_path = Path(args.state_file)
    cache_json = Path(args.cache_json)
    cache_md = Path(args.cache_md)
    queue_dir = Path(args.queue_dir)
    queue_dir.mkdir(parents=True, exist_ok=True)

    config = load_config(config_path)
    state = load_state(state_path)

    issue = ensure_issue(config, config_path, create=sync_mode)
    remote_state = extract_remote_state(issue.get("body", ""), config)
    remote_state["repo"] = config.get("repo", "")
    remote_state["issue_number"] = str(config.get("issue_number", ""))
    remote_state["issue_url"] = config.get("issue_url", "")

    comments_to_post = []
    processed_files = []
    if sync_mode:
        for queue_file in sorted(queue_dir.glob("*.json")):
            event = load_json(queue_file, {})
            remote_state, comment = merge_event(remote_state, event)
            comments_to_post.append(comment)
            processed_files.append(queue_file)
        body_text = render_issue_body(remote_state)
        if body_text.strip() != issue.get("body", "").strip():
            run_gh(
                [
                    "issue",
                    "edit",
                    str(config.get("issue_number", "")),
                    "--repo",
                    config.get("repo", ""),
                    "--body-file",
                    "-",
                ],
                input_text=body_text,
            )
        for comment in comments_to_post:
            run_gh(
                [
                    "issue",
                    "comment",
                    str(config.get("issue_number", "")),
                    "--repo",
                    config.get("repo", ""),
                    "--body-file",
                    "-",
                ],
                input_text=comment,
            )
        for path in processed_files:
            path.unlink(missing_ok=True)
        state["last_sync_at"] = utc_now()
        state["last_error"] = ""
    else:
        body_text = render_issue_body(remote_state)
        state["last_pull_at"] = utc_now()
        state["last_error"] = ""

    state["issue_number"] = str(config.get("issue_number", ""))
    state["issue_url"] = config.get("issue_url", "")
    state["pending_queue_count"] = len(list(queue_dir.glob("*.json")))
    save_state(state_path, state)
    write_cache(cache_json, cache_md, remote_state, body_text)

    print(
        json.dumps(
            {
                "ok": True,
                "mode": "sync" if sync_mode else "pull",
                "repo": config.get("repo", ""),
                "issue_number": str(config.get("issue_number", "")),
                "issue_url": config.get("issue_url", ""),
                "processed_queue_items": len(processed_files),
                "notes_count": len(remote_state.get("notes", [])),
                "recently_seen_count": len(remote_state.get("recently_seen", [])),
                "cache_json": str(cache_json),
                "cache_markdown": str(cache_md),
            },
            indent=2,
        )
    )


def cmd_sync(args):
    pull_or_sync(args, sync_mode=True)


def cmd_pull(args):
    pull_or_sync(args, sync_mode=False)


def build_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("--config-file", required=True)
    add_parser.add_argument("--state-file", required=True)
    add_parser.add_argument("--queue-dir", required=True)
    add_parser.add_argument("--event-kind", default="observe", choices=["observe", "remediate", "supersede"])
    add_parser.add_argument("--title", required=True)
    add_parser.add_argument("--body", required=True)
    add_parser.add_argument("--category", required=True)
    add_parser.add_argument("--target", default="")
    add_parser.add_argument("--platform", default="unknown")
    add_parser.add_argument("--skill-version", default="unknown")
    add_parser.add_argument("--observed-at", default="")
    add_parser.add_argument("--status", default="open")
    add_parser.add_argument("--fingerprint", default="")
    add_parser.add_argument("--session-metadata-json", default="{}")
    add_parser.add_argument("--remediation-summary", default="")
    add_parser.add_argument("--superseded-by", default="")
    add_parser.set_defaults(func=cmd_add)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--config-file", required=True)
    status_parser.add_argument("--state-file", required=True)
    status_parser.add_argument("--queue-dir", required=True)
    status_parser.add_argument("--cache-json", required=True)
    status_parser.add_argument("--cache-md", required=True)
    status_parser.set_defaults(func=cmd_status)

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--config-file", required=True)
    sync_parser.add_argument("--state-file", required=True)
    sync_parser.add_argument("--queue-dir", required=True)
    sync_parser.add_argument("--cache-json", required=True)
    sync_parser.add_argument("--cache-md", required=True)
    sync_parser.set_defaults(func=cmd_sync)

    pull_parser = subparsers.add_parser("pull")
    pull_parser.add_argument("--config-file", required=True)
    pull_parser.add_argument("--state-file", required=True)
    pull_parser.add_argument("--queue-dir", required=True)
    pull_parser.add_argument("--cache-json", required=True)
    pull_parser.add_argument("--cache-md", required=True)
    pull_parser.set_defaults(func=cmd_pull)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
