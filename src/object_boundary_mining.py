# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


DEFAULT_BASE_DIR = r"D:\browser\Innovation\sequence\log_process"

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
STEP_RE = re.compile(r"^Step\s+\d+:\s+(?P<body>.+)$")
SESSION_HEADER_RE = re.compile(r"^===\s+(?P<header>.*?)\s*===")
STATUS_SUFFIX_RE = re.compile(r"\s+\[(?P<status>\d+)\](?:\s+.*)?$")
BODY_SPLIT_RE = re.compile(r"\s+BODY\s+", re.I)

OBJECT_FIELD_RE = re.compile(
    r"(issue|project|space|content|page|comment|worklog|attachment|board|sprint|filter|dashboard|avatar|user|group|role|permission|account|tenant).*(id|key|name)?$|^(id|key)$",
    re.I,
)
NON_OBJECT_FIELD_RE = re.compile(
    r"(pageSize|pageNum|pageNumber|startAt|maxResults|limit|offset|size|sort|order|expand|fields|userScope|scope|filterType|jql|cql|query|search|issueNavId)$",
    re.I,
)
NON_OBJECT_VALUE_RE = re.compile(r"^(all|none|null|true|false|undefined|sidebar|search|default|primary|latest)$", re.I)
OBJECT_SEGMENT_TYPES = {
    "issue": "issue",
    "issues": "issue",
    "project": "project",
    "projects": "project",
    "space": "space",
    "spaces": "space",
    "content": "content",
    "page": "page",
    "pages": "page",
    "comment": "comment",
    "comments": "comment",
    "worklog": "worklog",
    "worklogs": "worklog",
    "attachment": "attachment",
    "attachments": "attachment",
    "board": "board",
    "boards": "board",
    "sprint": "sprint",
    "sprints": "sprint",
    "filter": "filter",
    "filters": "filter",
    "dashboard": "dashboard",
    "dashboards": "dashboard",
    "avatar": "avatar",
    "avatars": "avatar",
    "user": "user",
    "users": "user",
    "group": "group",
    "groups": "group",
    "role": "role",
    "roles": "role",
    "permission": "permission",
    "permissions": "permission",
}
ACTOR_FIELD_RE = re.compile(r"(user|username|account|owner|author|reporter|creator|assignee|session|token|cookie)", re.I)
STATIC_RE = re.compile(
    r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)(?:$|\?)|/s/|/download/resources/|/images/|/static/",
    re.I,
)
ID_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mine which object identifiers are usually bound to which actors, sessions, and upstream contexts.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--input-dir", default="", help="Default: <base-dir>/log_sequence")
    parser.add_argument("--openapi-file", default="", help="Optional: <base-dir>/API document/site_<site_id>_openapi.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/object_boundary_mining")
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--bucket", default="all", choices=["short_1_2", "main_3_50", "long_51_plus", "all"])
    parser.add_argument("--max-sessions", type=int, default=0, help="0 means no limit.")
    parser.add_argument("--window-size", type=int, default=6, help="Previous event window used as upstream context.")
    parser.add_argument("--min-support", type=int, default=3, help="Minimum events required for a boundary candidate.")
    parser.add_argument("--top-items", type=int, default=0, help="0 means output all rows/items.")
    parser.add_argument("--include-static", action="store_true")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def clean_token(token: str) -> str:
    token = str(token or "").strip()
    token = STATUS_SUFFIX_RE.sub("", token).strip()
    if " action=" in token:
        token = token.split(" action=", 1)[0].strip()
    if " label=" in token:
        token = token.split(" label=", 1)[0].strip()
    return token


def split_request(token: str) -> tuple[str, str, str]:
    text = clean_token(token)
    body = ""
    body_match = BODY_SPLIT_RE.split(text, maxsplit=1)
    if len(body_match) == 2:
        text, body = body_match[0].strip(), body_match[1].strip()
    if " " not in text:
        return "", text, body
    method, target = text.split(" ", 1)
    method = method.upper().strip()
    return (method if method in HTTP_METHODS else "", target.strip(), body)


def request_api(token: str) -> str:
    method, target, _ = split_request(token)
    if not method:
        return clean_token(token).split("?", 1)[0]
    parsed = urlparse("http://local" + target if target.startswith("/") else target)
    return f"{method} {unquote(parsed.path or target)}"


def infer_site_id_from_name(path: Path) -> str:
    stem = path.stem
    if "site_" in stem:
        return stem.rsplit("site_", 1)[-1].split("_", 1)[0]
    return "unknown_site"


def file_matches_site(path: Path, site_id: str) -> bool:
    return not site_id or infer_site_id_from_name(path) == site_id


def iter_json_blocks(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = [block.strip() for block in text.split("\n\n") if block.strip()]
    if len(blocks) > 1:
        for block in blocks:
            try:
                payload = json.loads(block)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                yield payload
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


def session_from_json(session_obj: dict[str, Any]) -> dict[str, Any]:
    raw_sequence = session_obj.get("full_api_sequence", [])
    if not isinstance(raw_sequence, list) or not raw_sequence:
        raw_sequence = session_obj.get("api_sequence", [])
    if not isinstance(raw_sequence, list) or not raw_sequence:
        sequence_obj = session_obj.get("sequence", {})
        raw_sequence = []
        if isinstance(sequence_obj, dict):
            for _, event in sorted(sequence_obj.items(), key=lambda item: int(item[0])):
                if isinstance(event, dict):
                    raw_sequence.append(event.get("full_api_request") or event.get("token") or event.get("api_request_pattern") or "")
    raw = [str(item).strip() for item in raw_sequence if str(item).strip()]
    return {
        "site_id": str(session_obj.get("site_id") or "unknown_site"),
        "session_id": str(session_obj.get("session_id") or ""),
        "source_ip": str(session_obj.get("source_ip") or session_obj.get("client_key") or ""),
        "user_hint": str(session_obj.get("user") or session_obj.get("username") or session_obj.get("account_id") or ""),
        "raw_sequence": raw,
    }


def iter_compressed_txt(path: Path):
    site_id = infer_site_id_from_name(path)
    current: list[str] = []
    current_session_id = ""
    session_index = 0

    def emit():
        nonlocal current, current_session_id
        if not current:
            return None
        payload = {
            "site_id": site_id,
            "session_id": current_session_id or f"{site_id}_txt_{session_index}",
            "source_ip": "",
            "user_hint": "",
            "raw_sequence": current,
        }
        current = []
        current_session_id = ""
        return payload

    with path.open("r", encoding="utf-8", errors="replace") as fin:
        for raw_line in fin:
            line = raw_line.strip()
            if not line:
                continue
            header = SESSION_HEADER_RE.match(line)
            if header:
                previous = emit()
                if previous:
                    yield previous
                session_index += 1
                current_session_id = header.group("header").strip().replace(" ", "_")
                continue
            step = STEP_RE.match(line)
            if step:
                token = clean_token(step.group("body"))
                if token:
                    current.append(token)
    previous = emit()
    if previous:
        yield previous


def discover_input_files(input_dir: Path, bucket: str, site_id: str) -> list[Path]:
    if not input_dir.exists():
        raise FileNotFoundError(f"input dir not found: {input_dir}")
    site_part = site_id if site_id else "*"
    patterns = [f"session_site_{site_part}.jsonl", f"*site_{site_part}.txt"]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(sorted(input_dir.glob(pattern)))
    if not files and bucket != "all" and (input_dir / bucket).exists():
        for pattern in patterns:
            files.extend(sorted((input_dir / bucket).glob(pattern)))
    if not files:
        for pattern in patterns:
            files.extend(sorted(input_dir.glob(f"**/{pattern}")))
    return [path for path in files if file_matches_site(path, site_id)]


def iter_sessions(files: list[Path]):
    for path in files:
        if path.suffix.lower() == ".jsonl":
            for payload in iter_json_blocks(path):
                session = session_from_json(payload)
                if session["raw_sequence"]:
                    yield session
        elif path.suffix.lower() == ".txt":
            for session in iter_compressed_txt(path):
                if session["raw_sequence"]:
                    yield session


def flatten_json_values(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            output.extend(flatten_json_values(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value[:20]):
            child_prefix = f"{prefix}[{index}]"
            output.extend(flatten_json_values(child, child_prefix))
    elif value is not None:
        output.append((prefix, str(value)))
    return output


def parse_body_params(body: str) -> list[tuple[str, str]]:
    text = str(body or "").strip()
    if not text:
        return []
    if text.startswith("{") or text.startswith("["):
        try:
            return flatten_json_values(json.loads(text))
        except json.JSONDecodeError:
            return []
    output = []
    for key, values in parse_qs(text, keep_blank_values=True).items():
        for value in values:
            output.append((key, value))
    return output


def value_is_object_like(value: str) -> bool:
    value = str(value or "").strip()
    if not value or len(value) > 100:
        return False
    if NON_OBJECT_VALUE_RE.fullmatch(value):
        return False
    return bool(ID_VALUE_RE.match(value))


def param_is_object_identifier(field: str, value: str) -> bool:
    if NON_OBJECT_FIELD_RE.search(str(field or "")):
        return False
    if str(field or "").lower() == "id" and re.search(r"[:/]", str(value or "")):
        return False
    return bool(OBJECT_FIELD_RE.search(str(field or "")) and value_is_object_like(value))


def path_value_is_identifier(value: str) -> bool:
    text = str(value or "").strip()
    if not value_is_object_like(text):
        return False
    if re.fullmatch(r"\d+(?:\.\d+)+", text):
        return False
    if re.search(r"\d", text):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]{1,15}", text):
        return True
    if re.fullmatch(r"[A-Fa-f0-9]{16,}|[A-Fa-f0-9-]{24,}", text):
        return True
    return False


def normalize_object_type(name: str) -> str:
    lower = str(name or "").lower()
    for token in (
        "issue",
        "project",
        "space",
        "content",
        "page",
        "comment",
        "worklog",
        "attachment",
        "board",
        "sprint",
        "filter",
        "dashboard",
        "avatar",
        "user",
        "group",
        "role",
        "permission",
        "account",
        "tenant",
    ):
        if token in lower:
            return token
    return "object"


def path_segment_object_type(segment: str) -> str:
    return OBJECT_SEGMENT_TYPES.get(str(segment or "").lower(), "")


def path_object_candidates(path: str) -> list[tuple[str, str, str]]:
    parts = [part for part in unquote(path).split("/") if part]
    output = []
    for index, part in enumerate(parts):
        if not path_value_is_identifier(part):
            continue
        previous = parts[index - 1] if index > 0 else "path"
        previous_type = path_segment_object_type(previous)
        if previous_type:
            output.append((previous_type, f"{previous_type}Id", part))
            continue
        previous2 = parts[index - 2] if index > 1 else ""
        previous2_type = path_segment_object_type(previous2)
        if previous2_type:
            output.append((previous2_type, f"{previous2_type}Id", part))
    return output


def extract_event_objects(token: str) -> tuple[str, list[dict[str, str]], dict[str, str]]:
    method, target, body = split_request(token)
    parsed = urlparse("http://local" + target if target.startswith("/") else target)
    api = f"{method} {unquote(parsed.path or target)}" if method else request_api(token)
    objects = []
    actor_hints = {}

    for object_type, field, value in path_object_candidates(parsed.path or ""):
        objects.append({"part": "path", "object_type": object_type, "field": field, "value": value})

    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        for value in values:
            if not value_is_object_like(value):
                continue
            if ACTOR_FIELD_RE.search(key):
                actor_hints[key] = value
            if param_is_object_identifier(key, value):
                objects.append({"part": "query", "object_type": normalize_object_type(key), "field": key, "value": value})

    for key, value in parse_body_params(body):
        if not value_is_object_like(value):
            continue
        if ACTOR_FIELD_RE.search(key):
            actor_hints[key] = value
        if param_is_object_identifier(key, value):
            objects.append({"part": "body", "object_type": normalize_object_type(key), "field": key, "value": value})

    unique = {}
    for item in objects:
        unique[(item["part"], item["object_type"], item["field"], item["value"])] = item
    return api, list(unique.values()), actor_hints


def actor_key(session: dict[str, Any], session_actor_hints: Counter[str]) -> str:
    if session.get("user_hint"):
        return f"user:{session['user_hint']}"
    if session.get("source_ip"):
        return f"client:{session['source_ip']}"
    if session_actor_hints:
        value, count = session_actor_hints.most_common(1)[0]
        if count >= 2:
            return f"hint:{value}"
    return f"session:{session.get('session_id') or 'unknown'}"


def confidence_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def load_openapi_param_index(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    doc = read_json(path)
    output: dict[str, list[str]] = {}
    paths = doc.get("paths", {}) if isinstance(doc, dict) else {}
    if not isinstance(paths, dict):
        return output
    for api_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.upper() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            names = []
            for param in operation.get("parameters", []) or []:
                if isinstance(param, dict) and param.get("name"):
                    names.append(str(param["name"]))
            output[f"{method.upper()} {api_path}"] = names
    return output


def api_matches_observed(template_api: str, observed_api: str) -> bool:
    if template_api == observed_api:
        return True
    t_method, _, t_path = template_api.partition(" ")
    o_method, _, o_path = observed_api.partition(" ")
    if t_method != o_method:
        return False
    generalized = re.sub(r"\{[^/]+\}", "{}", t_path.rstrip("/"))
    observed = re.sub(r"/[A-Za-z0-9_.:-]+", lambda m: "/{}" if re.search(r"\d|[A-Fa-f0-9-]{8,}", m.group(0)) else m.group(0), o_path.rstrip("/"))
    return generalized == observed or t_path.rstrip("/").endswith(o_path.rstrip("/")) or o_path.rstrip("/").endswith(t_path.rstrip("/"))


def project_key_from_issue_value(value: str) -> str:
    match = re.match(r"^([A-Z][A-Z0-9_]+)-\d+$", str(value or "").strip())
    return match.group(1) if match else ""


def project_ref(object_type: str, field: str, value: str) -> str:
    if object_type != "project":
        return ""
    field_lower = field.lower()
    if "key" in field_lower or re.fullmatch(r"[A-Z][A-Z0-9_]{1,15}", str(value or "")):
        return f"projectKey:{value}"
    return f"projectId:{value}"


def issue_ref(field: str, value: str) -> str:
    field_lower = field.lower()
    if "key" in field_lower or project_key_from_issue_value(value):
        return f"issueKey:{value}"
    return f"issueId:{value}"


def compact_counter(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    items = counter.most_common(limit if limit > 0 else None)
    return [{"value": value, "count": count} for value, count in items]


def limit_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return rows[:limit] if limit > 0 else rows


def mine_project_issue_access(sessions: list[dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    project_issue_stats: dict[str, dict[str, Any]] = {}
    actor_project_stats: dict[str, dict[str, Any]] = {}
    issue_to_projects: dict[str, Counter[str]] = defaultdict(Counter)
    parsed_object_event_count = 0

    def ensure_project(project: str) -> dict[str, Any]:
        if project not in project_issue_stats:
            project_issue_stats[project] = {
                "issues": Counter(),
            }
        return project_issue_stats[project]

    def ensure_actor(actor: str) -> dict[str, Any]:
        if actor not in actor_project_stats:
            actor_project_stats[actor] = {
                "projects": Counter(),
            }
        return actor_project_stats[actor]

    def add_project_issue(project: str, issue: str, actor: str, session_id: str, evidence_type: str, example: dict[str, Any]) -> None:
        if not project or not issue:
            return
        stats = ensure_project(project)
        stats["issues"][issue] += 1
        issue_to_projects[issue][project] += 1

    def add_actor_project(actor: str, project: str, session_id: str, source: str, example: dict[str, Any]) -> None:
        if not project:
            return
        stats = ensure_actor(actor)
        stats["projects"][project] += 1

    for session in sessions:
        session_actor_hints: Counter[str] = Counter()
        parsed_events = []
        for step, token in enumerate(session["raw_sequence"], start=1):
            api, objects, hints = extract_event_objects(token)
            if not args.include_static and STATIC_RE.search(api):
                continue
            for value in hints.values():
                session_actor_hints[value] += 1
            parsed_events.append({"step": step, "api": api, "objects": objects, "request": clean_token(token)})

        actor = actor_key(session, session_actor_hints)
        session_id = session.get("session_id", "")
        for event_index, event in enumerate(parsed_events):
            upstream_events = parsed_events[max(0, event_index - args.window_size) : event_index]
            event_projects = [project_ref(obj["object_type"], obj["field"], obj["value"]) for obj in event["objects"]]
            event_projects = [item for item in event_projects if item]
            event_issues = [issue_ref(obj["field"], obj["value"]) for obj in event["objects"] if obj["object_type"] == "issue"]
            upstream_projects = []
            upstream_issues = []
            for upstream in upstream_events:
                for obj in upstream["objects"]:
                    project = project_ref(obj["object_type"], obj["field"], obj["value"])
                    if project:
                        upstream_projects.append(project)
                    if obj["object_type"] == "issue":
                        upstream_issues.append(issue_ref(obj["field"], obj["value"]))

            parsed_object_event_count += len(event["objects"])

            for project in event_projects:
                add_actor_project(
                    actor,
                    project,
                    session_id,
                    "direct_project_access",
                    {"step": event["step"], "api": event["api"], "request": event["request"]},
                )
            for project in event_projects:
                for issue in event_issues:
                    add_project_issue(
                        project,
                        issue,
                        actor,
                        session_id,
                        "same_request",
                        {"step": event["step"], "api": event["api"], "request": event["request"]},
                    )
            for project in event_projects:
                for issue in upstream_issues[-args.window_size :]:
                    add_project_issue(
                        project,
                        issue,
                        actor,
                        session_id,
                        "upstream_issue_context",
                        {"step": event["step"], "api": event["api"], "request": event["request"], "upstream_issue": issue},
                    )
            for issue in event_issues:
                for project in upstream_projects[-args.window_size :]:
                    add_project_issue(
                        project,
                        issue,
                        actor,
                        session_id,
                        "upstream_project_context",
                        {"step": event["step"], "api": event["api"], "request": event["request"], "upstream_project": project},
                    )
                issue_value = issue.split(":", 1)[-1]
                issue_project_key = project_key_from_issue_value(issue_value)
                if issue_project_key:
                    project = f"projectKey:{issue_project_key}"
                    add_project_issue(
                        project,
                        issue,
                        actor,
                        session_id,
                        "issue_key_prefix",
                        {"step": event["step"], "api": event["api"], "request": event["request"]},
                    )

    for session in sessions:
        session_actor_hints = Counter()
        session_events = []
        for step, token in enumerate(session["raw_sequence"], start=1):
            api, objects, hints = extract_event_objects(token)
            if not args.include_static and STATIC_RE.search(api):
                continue
            for value in hints.values():
                session_actor_hints[value] += 1
            session_events.append({"step": step, "api": api, "objects": objects, "request": clean_token(token)})
        actor = actor_key(session, session_actor_hints)
        session_id = session.get("session_id", "")
        for event in session_events:
            for obj in event["objects"]:
                if obj["object_type"] != "issue":
                    continue
                issue = issue_ref(obj["field"], obj["value"])
                for project, _ in issue_to_projects.get(issue, Counter()).most_common(3):
                    add_actor_project(
                        actor,
                        project,
                        session_id,
                        "inferred_from_accessed_issue",
                        {"step": event["step"], "api": event["api"], "request": event["request"], "issue": issue},
                    )

    project_contains_issues = []
    for project, stats in project_issue_stats.items():
        support = sum(stats["issues"].values())
        if support < args.min_support:
            continue
        project_contains_issues.append(
            {
                "project": project,
                "support": support,
                "issue_count": len(stats["issues"]),
                "issues": compact_counter(stats["issues"], args.top_items),
            }
        )

    actor_accessible_projects = []
    for actor, stats in actor_project_stats.items():
        support = sum(stats["projects"].values())
        if support < args.min_support:
            continue
        actor_accessible_projects.append(
            {
                "actor": actor,
                "support": support,
                "project_count": len(stats["projects"]),
                "projects": compact_counter(stats["projects"], args.top_items),
            }
        )

    project_contains_issues.sort(key=lambda item: (item["issue_count"], item["support"]), reverse=True)
    actor_accessible_projects.sort(key=lambda item: (item["project_count"], item["support"]), reverse=True)

    return {
        "project_contains_issues": limit_rows(project_contains_issues, args.top_items),
        "actor_accessible_projects": limit_rows(actor_accessible_projects, args.top_items),
    }


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    input_dir = Path(args.input_dir) if args.input_dir else base_dir / "log_sequence"
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "object_boundary_mining"
    openapi_file = Path(args.openapi_file) if args.openapi_file else base_dir / "API document" / f"site_{args.site_id}_openapi.json"

    files = discover_input_files(input_dir, args.bucket, args.site_id)
    if not files:
        raise FileNotFoundError(f"no input sequence files found in {input_dir}")

    sessions = []
    for session in iter_sessions(files):
        if args.site_id and session["site_id"] != args.site_id:
            continue
        sessions.append(session)
        if args.max_sessions > 0 and len(sessions) >= args.max_sessions:
            break
    if not sessions:
        raise RuntimeError("no sessions loaded")

    mined = mine_project_issue_access(sessions, args)
    payload = {
        "project_contains_issues": mined["project_contains_issues"],
        "actor_accessible_projects": mined["actor_accessible_projects"],
    }
    output_path = output_dir / f"site_{args.site_id}_project_issue_access.json"
    write_json(output_path, payload)
    print(
        f"site={args.site_id} sessions={len(sessions)} "
        f"project_issue_relations={len(mined['project_contains_issues'])} "
        f"actor_project_relations={len(mined['actor_accessible_projects'])} "
        f"output={output_path}"
    )


if __name__ == "__main__":
    main()
