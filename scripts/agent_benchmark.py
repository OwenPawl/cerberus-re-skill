#!/usr/bin/env python3
"""Create and validate public agent benchmark result bundles.

This script prepares reproducible result directories. It does not run agents,
score them, or claim benchmark outcomes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import platform
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFINITION_PATH = ROOT / "benchmarks" / "agent_benchmark.v1.json"


class BenchmarkError(RuntimeError):
    """Raised for user-facing benchmark scaffold errors."""


def utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_definition() -> dict[str, Any]:
    try:
        payload = json.loads(DEFINITION_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BenchmarkError(f"missing benchmark definition: {DEFINITION_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"invalid benchmark definition JSON: {exc}") from exc
    if payload.get("schema_version") != "agent_benchmark.v1":
        raise BenchmarkError("benchmark definition schema_version must be agent_benchmark.v1")
    for task in payload.get("tasks", []):
        prompt_path = task.get("prompt_path")
        if not prompt_path:
            raise BenchmarkError(f"task {task.get('id', '<missing>')!r} is missing prompt_path")
        if not (ROOT / str(prompt_path)).is_file():
            raise BenchmarkError(f"task {task.get('id', '<missing>')!r} prompt_path does not exist: {prompt_path}")
    return payload


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def index_by_id(items: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = str(item.get("id", ""))
        if not item_id:
            raise BenchmarkError(f"{label} entry is missing id")
        if item_id in indexed:
            raise BenchmarkError(f"duplicate {label} id: {item_id}")
        indexed[item_id] = item
    return indexed


def empty_metrics(definition: dict[str, Any], runner: str, configuration: str) -> dict[str, Any]:
    tasks = [
        {
            "id": task["id"],
            "label": task["label"],
            "status": "not_run",
            "evidence": [],
            "verification": [],
            "notes": "",
        }
        for task in definition["tasks"]
    ]
    return {
        "schema_version": "agent_benchmark_result.v1",
        "generated_at": utc_now(),
        "runner": runner,
        "configuration": configuration,
        "repo_commit": git_commit(),
        "host_platform": platform.platform(),
        "elapsed_seconds": None,
        "task_statuses": tasks,
        "verification_count": 0,
        "claim_count": 0,
        "artifact_count": 0,
        "failure_count": 0,
        "assessment": "not_run",
    }


def bundle_readme(definition: dict[str, Any], runner: str, configuration: str) -> str:
    runners = index_by_id(definition["runners"], "runner")
    configs = index_by_id(definition["configurations"], "configuration")
    runner_label = runners[runner]["label"]
    config = configs[configuration]
    lines = [
        "# Agent Benchmark Result Bundle",
        "",
        f"- Runner: {runner_label} (`{runner}`)",
        f"- Configuration: {config['label']} (`{configuration}`)",
        f"- Created: {utc_now()}",
        "- Status: scaffolded, no benchmark results recorded yet.",
        "",
        "## Required Files",
    ]
    lines.extend(f"- `{name}`" for name in definition["required_bundle_files"])
    lines.extend(
        [
            "",
            "## Recording Rules",
            "- Do not claim a task passed unless `metrics.json` links durable evidence and verification commands.",
            "- Use `blocked` when a prerequisite is unavailable and record the retry condition in `failures.md`.",
            "- Keep generated artifacts in this bundle or reference stable absolute paths.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_prompt(definition: dict[str, Any], runner: str, configuration: str, bundle: str) -> str:
    runners = index_by_id(definition["runners"], "runner")
    configs = index_by_id(definition["configurations"], "configuration")
    if runner not in runners:
        raise BenchmarkError(f"unknown runner {runner!r}")
    if configuration not in configs:
        raise BenchmarkError(f"unknown configuration {configuration!r}")

    config = configs[configuration]
    enabled = config.get("enabled_skills", [])
    enabled_text = ", ".join(enabled) if enabled else "none"
    lines = [
        "# Agent Benchmark Prompt",
        "",
        f"Runner: {runners[runner]['label']} (`{runner}`)",
        f"Configuration: {config['label']} (`{configuration}`)",
        f"Enabled skills: {enabled_text}",
        f"Result bundle: `{bundle}`",
        "",
        "## Operating Rules",
        "",
        "- Start from a fresh checkout of this repository.",
        "- Use only the skills listed for this configuration.",
        "- Do not claim benchmark results until the result bundle contains durable evidence.",
        "- Record commands in `commands.jsonl` as JSONL objects with command, cwd, exit status, and notes.",
        "- Record claims in `claims.json`, artifacts in `artifacts.json`, failures in `failures.md`, and task status in `metrics.json`.",
        "- Mark a task `blocked` when prerequisites are unavailable and include a concrete retry condition.",
        "- Do not use private targets, personal state, or manual GUI interaction.",
        "",
        "## Result Bundle Setup",
        "",
        "Before starting, create the result bundle scaffold:",
        "",
        "```bash",
        f"python3 scripts/agent_benchmark.py scaffold --runner {runner} --configuration {configuration} --output {bundle}",
        "```",
        "",
        "After the run, validate it:",
        "",
        "```bash",
        f"python3 scripts/agent_benchmark.py validate --bundle {bundle}",
        "```",
    ]
    for task in definition["tasks"]:
        prompt_path = ROOT / str(task["prompt_path"])
        lines.extend(["", "---", "", prompt_path.read_text(encoding="utf-8").strip(), ""])
    return "\n".join(lines).rstrip() + "\n"


def write_json(path: pathlib.Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_list(args: argparse.Namespace) -> int:
    definition = load_definition()
    if args.json:
        print(json.dumps(definition, indent=2, sort_keys=True))
        return 0
    print("Runners:")
    for runner in definition["runners"]:
        print(f"- {runner['id']}: {runner['label']}")
    print("Configurations:")
    for config in definition["configurations"]:
        print(f"- {config['id']}: {config['label']}")
    print("Tasks:")
    for task in definition["tasks"]:
        print(f"- {task['id']}: {task['label']}")
    return 0


def cmd_scaffold(args: argparse.Namespace) -> int:
    definition = load_definition()
    runners = index_by_id(definition["runners"], "runner")
    configs = index_by_id(definition["configurations"], "configuration")
    if args.runner not in runners:
        raise BenchmarkError(f"unknown runner {args.runner!r}")
    if args.configuration not in configs:
        raise BenchmarkError(f"unknown configuration {args.configuration!r}")

    output = pathlib.Path(args.output).expanduser()
    output.mkdir(parents=True, exist_ok=True)
    required = [output / name for name in definition["required_bundle_files"]]
    existing = [path for path in required if path.exists()]
    if existing and not args.force:
        raise BenchmarkError("bundle files already exist; pass --force to overwrite scaffold files")

    (output / "README.md").write_text(bundle_readme(definition, args.runner, args.configuration), encoding="utf-8")
    (output / "commands.jsonl").write_text("", encoding="utf-8")
    write_json(output / "claims.json", {"schema_version": "agent_benchmark_claims.v1", "claims": []})
    write_json(output / "artifacts.json", {"schema_version": "agent_benchmark_artifacts.v1", "artifacts": []})
    (output / "failures.md").write_text("# Failures\n\nNo failures recorded yet.\n", encoding="utf-8")
    write_json(output / "metrics.json", empty_metrics(definition, args.runner, args.configuration))
    print(json.dumps({"ok": True, "bundle": str(output)}, sort_keys=True))
    return 0


def cmd_prompt(args: argparse.Namespace) -> int:
    definition = load_definition()
    text = render_prompt(definition, args.runner, args.configuration, args.bundle)
    if args.output:
        output = pathlib.Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(json.dumps({"ok": True, "prompt": str(output)}, sort_keys=True))
        return 0
    print(text, end="")
    return 0


def read_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BenchmarkError(f"missing {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"invalid {label} JSON: {exc}") from exc


def validate_jsonl(path: pathlib.Path) -> int:
    if not path.exists():
        raise BenchmarkError(f"missing commands.jsonl: {path}")
    count = 0
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BenchmarkError(f"invalid commands.jsonl:{lineno}: {exc}") from exc
        if not isinstance(value, dict):
            raise BenchmarkError(f"invalid commands.jsonl:{lineno}: record must be an object")
        count += 1
    return count


def cmd_validate(args: argparse.Namespace) -> int:
    definition = load_definition()
    runners = index_by_id(definition["runners"], "runner")
    configs = index_by_id(definition["configurations"], "configuration")
    allowed_statuses = set(definition["allowed_task_statuses"])
    bundle = pathlib.Path(args.bundle).expanduser()
    missing = [name for name in definition["required_bundle_files"] if not (bundle / name).exists()]
    if missing:
        raise BenchmarkError("missing bundle files: " + ", ".join(missing))

    command_count = validate_jsonl(bundle / "commands.jsonl")
    claims = read_json(bundle / "claims.json", "claims")
    artifacts = read_json(bundle / "artifacts.json", "artifacts")
    metrics = read_json(bundle / "metrics.json", "metrics")
    if claims.get("schema_version") != "agent_benchmark_claims.v1" or not isinstance(claims.get("claims"), list):
        raise BenchmarkError("claims.json must contain schema_version agent_benchmark_claims.v1 and a claims list")
    if artifacts.get("schema_version") != "agent_benchmark_artifacts.v1" or not isinstance(artifacts.get("artifacts"), list):
        raise BenchmarkError("artifacts.json must contain schema_version agent_benchmark_artifacts.v1 and an artifacts list")
    if metrics.get("schema_version") != "agent_benchmark_result.v1":
        raise BenchmarkError("metrics.json schema_version must be agent_benchmark_result.v1")
    if metrics.get("runner") not in runners:
        raise BenchmarkError(f"metrics.json runner is not in benchmark definition: {metrics.get('runner')!r}")
    if metrics.get("configuration") not in configs:
        raise BenchmarkError(f"metrics.json configuration is not in benchmark definition: {metrics.get('configuration')!r}")
    observed_tasks = {str(item.get("id", "")): item for item in metrics.get("task_statuses", []) if isinstance(item, dict)}
    expected_tasks = {task["id"] for task in definition["tasks"]}
    if set(observed_tasks) != expected_tasks:
        raise BenchmarkError("metrics.json task ids must match benchmark definition")
    bad_statuses = sorted(
        str(item.get("status", ""))
        for item in observed_tasks.values()
        if str(item.get("status", "")) not in allowed_statuses
    )
    if bad_statuses:
        raise BenchmarkError("metrics.json has unsupported task status: " + ", ".join(bad_statuses))
    payload = {
        "ok": True,
        "bundle": str(bundle),
        "runner": metrics.get("runner"),
        "configuration": metrics.get("configuration"),
        "command_count": command_count,
        "claim_count": len(claims.get("claims", [])),
        "artifact_count": len(artifacts.get("artifacts", [])),
        "task_count": len(observed_tasks),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    list_parser = subcommands.add_parser("list", help="show benchmark runners, configurations, and tasks")
    list_parser.add_argument("--json", action="store_true", help="emit the benchmark definition JSON")
    list_parser.set_defaults(func=cmd_list)

    scaffold = subcommands.add_parser("scaffold", help="create an empty result bundle")
    scaffold.add_argument("--output", required=True, help="destination result bundle directory")
    scaffold.add_argument("--runner", required=True, help="runner id from the benchmark definition")
    scaffold.add_argument("--configuration", required=True, help="configuration id from the benchmark definition")
    scaffold.add_argument("--force", action="store_true", help="overwrite existing scaffold files")
    scaffold.set_defaults(func=cmd_scaffold)

    prompt = subcommands.add_parser("prompt", help="render a fresh-agent benchmark prompt")
    prompt.add_argument("--runner", required=True, help="runner id from the benchmark definition")
    prompt.add_argument("--configuration", required=True, help="configuration id from the benchmark definition")
    prompt.add_argument(
        "--bundle",
        required=True,
        help="result bundle path the fresh agent should write",
    )
    prompt.add_argument("--output", help="write prompt to this file instead of stdout")
    prompt.set_defaults(func=cmd_prompt)

    validate = subcommands.add_parser("validate", help="validate a result bundle")
    validate.add_argument("--bundle", required=True, help="result bundle directory")
    validate.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BenchmarkError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
