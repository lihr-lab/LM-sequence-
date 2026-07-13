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
STATUS_SUFFIX_RE = re.compile(r"\s+\[(?P<status>\d+)(?:\s+.*)?\]?$")
BODY_SPLIT_RE = re.compile(r"\s+BODY\s+", re.I)
FRONTEND_NOISE_RE = re.compile(
    r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)(?:$|\?)"
    r"|/s/|/download/resources/|/download/batch/|/images/|/static/|/assets/"
    r"|/rest/wrm/|/webResources/|/useravatar|/avatar|/favicon",
    re.I,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply generated FOL-style sequence rules to original sessions.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--input-dir", default="", help="Default: <base-dir>/log_sequence")
    parser.add_argument("--fol-file", default="", help="Default: <base-dir>/fol_expressions/site_<site_id>_fol_expressions.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/fol_rule_violations")
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--bucket", default="all", choices=["short_1_2", "main_3_50", "long_51_plus", "all"])
    parser.add_argument("--max-sessions", type=int, default=0, help="0 means no limit.")
    parser.add_argument("--max-evidence-per-rule", type=int, default=0, help="0 means no per-rule evidence limit.")
    parser.add_argument("--include-frontend-noise", action="store_true", help="Do not filter static/frontend resource requests.")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def clean_token(token: str) -> str:
    text = str(token or "").strip()
    text = STATUS_SUFFIX_RE.sub("", text).strip()
    if " action=" in text:
        text = text.split(" action=", 1)[0].strip()
    if " label=" in text:
        text = text.split(" label=", 1)[0].strip()
    return text


def split_request(token: str) -> tuple[str, str, str]:
    text = clean_token(token)
    body = ""
    parts = BODY_SPLIT_RE.split(text, maxsplit=1)
    if len(parts) == 2:
        text, body = parts[0].strip(), parts[1].strip()
    if " " not in text:
        return "", text, body
    method, target = text.split(" ", 1)
    method = method.upper().strip()
    return (method if method in HTTP_METHODS else "", target.strip(), body)


def request_api(token: str) -> str:
    method, target, _ = split_request(token)
    if not method:
        return clean_token(token).split("?", 1)[0].strip()
    parsed = urlparse("http://local" + target if target.startswith("/") else target)
    return f"{method} {unquote(parsed.path or target)}"


def is_frontend_noise_api(api: str) -> bool:
    return bool(FRONTEND_NOISE_RE.search(str(api or "")))


def request_params(token: str) -> dict[str, list[str]]:
    method, target, body = split_request(token)
    params: dict[str, list[str]] = defaultdict(list)
    parsed = urlparse("http://local" + target if target.startswith("/") else target)
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        params[key].extend(str(value) for value in values)
    if body:
        parse_body_params(body, params)
    return dict(params)


def parse_body_params(body: str, params: dict[str, list[str]]) -> None:
    body = body.strip()
    if not body:
        return
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        flatten_json_params(payload, "", params)
        return
    for key, values in parse_qs(body, keep_blank_values=True).items():
        params[key].extend(str(value) for value in values)


def flatten_json_params(value: Any, prefix: str, params: dict[str, list[str]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            flatten_json_params(child, name, params)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            flatten_json_params(child, name, params)
    elif prefix:
        params[prefix].append(str(value))


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
        "raw_sequence": raw,
        "api_sequence": [request_api(item) for item in raw if request_api(item)],
    }


def apply_business_focus_filter(session: dict[str, Any], include_frontend_noise: bool) -> dict[str, Any]:
    if include_frontend_noise:
        return session
    raw_sequence = []
    api_sequence = []
    for raw, api in zip(session.get("raw_sequence", []), session.get("api_sequence", [])):
        if is_frontend_noise_api(api):
            continue
        raw_sequence.append(raw)
        api_sequence.append(api)
    filtered = dict(session)
    filtered["raw_sequence"] = raw_sequence
    filtered["api_sequence"] = api_sequence
    filtered["filtered_frontend_noise_count"] = len(session.get("api_sequence", [])) - len(api_sequence)
    return filtered


def iter_compressed_txt(path: Path):
    site_id = infer_site_id_from_name(path)
    current: list[str] = []
    current_session_id = ""
    session_index = 0

    def emit():
        nonlocal current, current_session_id
        if not current:
            return None
        raw = current
        payload = {
            "site_id": site_id,
            "session_id": current_session_id or f"{site_id}_txt_{session_index}",
            "source_ip": "",
            "raw_sequence": raw,
            "api_sequence": [request_api(item) for item in raw if request_api(item)],
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
                if session["api_sequence"]:
                    yield session
        elif path.suffix.lower() == ".txt":
            for session in iter_compressed_txt(path):
                if session["api_sequence"]:
                    yield session


def activity_map(rule: dict[str, Any]) -> dict[str, str]:
    result = {}
    activity = rule.get("activity_abstraction", {})
    for item in activity.get("activities", []) if isinstance(activity, dict) else []:
        if isinstance(item, dict) and item.get("symbol") and item.get("label"):
            result[str(item["symbol"])] = str(item["label"])
    return result


def rule_related_apis(rule: dict[str, Any]) -> set[str]:
    apis = set()
    for api in activity_map(rule).values():
        if api:
            apis.add(api)
    for item in rule.get("openapi_summary", []) or []:
        if isinstance(item, dict) and item.get("api"):
            apis.add(str(item["api"]))
    summary = rule.get("scenario_summary", {})
    for key in ("normal_sequence", "possible_violation_sequence"):
        values = summary.get(key, [])
        if isinstance(values, list):
            for value in values:
                api = request_api(str(value))
                if api:
                    apis.add(api)
    return {api for api in apis if api}


def api_positions(session: dict[str, Any], api: str) -> list[int]:
    if not api:
        return []
    sequence = session.get("api_sequence", [])
    return [index for index, item in enumerate(sequence) if item == api]


def first_before(left_positions: list[int], right_index: int) -> int | None:
    candidates = [index for index in left_positions if index < right_index]
    return max(candidates) if candidates else None


def detect_sequence_order(rule: dict[str, Any], expr: dict[str, Any], session: dict[str, Any]) -> list[dict[str, Any]]:
    amap = activity_map(rule)
    scope = expr.get("scope", {}) if isinstance(expr.get("scope"), dict) else {}
    mode = str(scope.get("mode", ""))
    hits = []
    if mode == "repeated_call":
        symbol = str(scope.get("activity", ""))
        api = amap.get(symbol, "")
        threshold = int(str(scope.get("threshold") or "2"))
        positions = api_positions(session, api)
        if len(positions) >= threshold:
            hits.append(
                {
                    "reason": "repeated_call",
                    "api": api,
                    "threshold": threshold,
                    "count": len(positions),
                    "steps": [index + 1 for index in positions],
                    "requests": [session["raw_sequence"][index] for index in positions[:10]],
                }
            )
        return hits

    if mode == "missing_or_reordered_step":
        required_symbol = str(scope.get("required_activity", ""))
        target_symbol = str(scope.get("target_activity", ""))
        required_api = amap.get(required_symbol, "")
        target_api = amap.get(target_symbol, "")
        required_positions = api_positions(session, required_api)
        target_positions = api_positions(session, target_api)
        for target_index in target_positions:
            before_index = first_before(required_positions, target_index)
            if before_index is None:
                hits.append(
                    {
                        "reason": "required_before_missing",
                        "required_api": required_api,
                        "target_api": target_api,
                        "target_step": target_index + 1,
                        "target_request": session["raw_sequence"][target_index],
                    }
                )
        return hits

    target_symbol = str(scope.get("target_activity", ""))
    target_api = amap.get(target_symbol, "")
    for index in api_positions(session, target_api):
        hits.append(
            {
                "reason": "sequence_order_uncertain",
                "target_api": target_api,
                "target_step": index + 1,
                "target_request": session["raw_sequence"][index],
            }
        )
    return hits


def parameter_name_matches(observed: str, wanted: str) -> bool:
    observed_l = observed.lower()
    wanted_l = wanted.lower()
    return observed_l == wanted_l or observed_l.endswith("." + wanted_l) or observed_l.endswith("]" + wanted_l)


def collect_param_values(
    session: dict[str, Any],
    wanted_params: list[str],
    allowed_apis: set[str],
) -> dict[str, list[dict[str, Any]]]:
    collected: dict[str, list[dict[str, Any]]] = {name: [] for name in wanted_params}
    for index, token in enumerate(session.get("raw_sequence", [])):
        api = request_api(token)
        if allowed_apis and api not in allowed_apis:
            continue
        params = request_params(token)
        for observed_name, values in params.items():
            for wanted in wanted_params:
                if parameter_name_matches(observed_name, wanted):
                    for value in values:
                        collected[wanted].append(
                            {
                                "step": index + 1,
                                "api": api,
                                "request": token,
                                "value": value,
                            }
                        )
    return collected


def normalize_scope_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value:
        return [str(value).strip()]
    return []


def non_empty_values(items: list[dict[str, Any]]) -> list[str]:
    return sorted({str(item.get("value", "")) for item in items if str(item.get("value", "")) not in {"", "null", "undefined"}})


def evidence_steps(items: list[dict[str, Any]]) -> list[int]:
    return [int(item["step"]) for item in items if "step" in item]


def detect_parameter_consistency(rule: dict[str, Any], expr: dict[str, Any], session: dict[str, Any]) -> list[dict[str, Any]]:
    scope = expr.get("scope", {}) if isinstance(expr.get("scope"), dict) else {}
    if "parameter" in scope and isinstance(scope.get("parameter"), dict):
        scope = scope["parameter"]
    params = normalize_scope_list(scope.get("parameters") or rule.get("scenario_summary", {}).get("parameter_objects", []))
    wanted_params = [item for item in params if item]
    if not wanted_params:
        return []

    target_apis = normalize_scope_list(scope.get("target_api_scope", scope.get("api_scope", [])))
    context_apis = normalize_scope_list(scope.get("context_api_scope", []))
    target_api_set = set(target_apis)
    context_api_set = set(context_apis)
    if not target_api_set:
        return []

    target_values = collect_param_values(session, wanted_params, target_api_set)
    context_values = collect_param_values(session, wanted_params, context_api_set) if context_api_set else {name: [] for name in wanted_params}
    dependency = str(scope.get("dependency_relation", "") or "").strip().lower()
    expected_source = str(scope.get("expected_source", "") or "").strip().lower()
    requires_context = bool(context_api_set) and (
        dependency in {"derived_from_context_api", "bound_to_upstream_context"}
        or expected_source in {"upstream_context_api", "normal_sequence_context", "upstream_context"}
    )
    hits = []
    for name in wanted_params:
        target_items = target_values.get(name, [])
        context_items = context_values.get(name, [])
        target_distinct = non_empty_values(target_items)
        context_distinct = non_empty_values(context_items)

        if len(target_distinct) >= 2:
            hits.append(
                {
                    "reason": "parameter_value_switch",
                    "parameter": name,
                    "distinct_value_count": len(target_distinct),
                    "values": target_distinct[:20],
                    "steps": evidence_steps(target_items),
                    "examples": target_items[:10],
                }
            )
        if requires_context and target_distinct and not context_distinct:
            hits.append(
                {
                    "reason": "parameter_context_missing",
                    "parameter": name,
                    "target_apis": target_apis,
                    "context_apis": context_apis,
                    "target_values": target_distinct[:20],
                    "target_steps": evidence_steps(target_items),
                    "examples": target_items[:10],
                }
            )
            continue
        if requires_context and target_distinct and context_distinct:
            unexpected_values = [value for value in target_distinct if value not in set(context_distinct)]
            if unexpected_values:
                hits.append(
                    {
                        "reason": "parameter_not_from_context",
                        "parameter": name,
                        "unexpected_target_values": unexpected_values[:20],
                        "context_values": context_distinct[:20],
                        "target_apis": target_apis,
                        "context_apis": context_apis,
                        "target_steps": evidence_steps(target_items),
                        "context_steps": evidence_steps(context_items),
                        "target_examples": target_items[:10],
                        "context_examples": context_items[:10],
                    }
                )
    return hits


def detect_rule_on_session(rule: dict[str, Any], session: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for index, expr in enumerate(rule.get("logic_expressions", []) or [], start=1):
        if not isinstance(expr, dict):
            continue
        dimension = str(expr.get("dimension", ""))
        hits: list[dict[str, Any]] = []
        if dimension == "sequence_order":
            hits = detect_sequence_order(rule, expr, session)
        elif dimension == "parameter_consistency":
            hits = detect_parameter_consistency(rule, expr, session)
        elif dimension == "sequence_order_and_parameter_consistency":
            seq_hits = detect_sequence_order(rule, {"scope": expr.get("scope", {}).get("sequence", {}), "dimension": "sequence_order"}, session)
            param_scope = expr.get("scope", {}).get("parameter", expr.get("scope", {}))
            param_hits = detect_parameter_consistency(rule, {"scope": param_scope}, session)
            if seq_hits and param_hits:
                hits = [{"reason": "combined_sequence_parameter_risk", "sequence_hits": seq_hits, "parameter_hits": param_hits}]
        for hit in hits:
            output.append(
                {
                    "expression_index": index,
                    "dimension": dimension,
                    "formula": expr.get("formula", ""),
                    "meaning": expr.get("meaning", ""),
                    "hit": hit,
                }
            )
    return output


def summarize_hit(rule: dict[str, Any], session: dict[str, Any], expr_hits: list[dict[str, Any]]) -> dict[str, Any]:
    source = rule.get("source", {})
    summary = rule.get("scenario_summary", {})
    return {
        "fol_id": rule.get("fol_id", ""),
        "scenario_id": source.get("scenario_id", ""),
        "scenario_title": source.get("scenario_title", ""),
        "security_type": summary.get("security_type", source.get("security_type", "")),
        "risk_level": summary.get("risk_level", ""),
        "session_id": session.get("session_id", ""),
        "source_ip": session.get("source_ip", ""),
        "business_pattern_name": source.get("business_pattern_name", ""),
        "overall_reason": summary.get("overall_reason", ""),
        "expression_hits": expr_hits,
        "session_context": {
            "raw_sequence": session.get("raw_sequence", []),
            "api_sequence": session.get("api_sequence", []),
            "filtered_frontend_noise_count": session.get("filtered_frontend_noise_count", 0),
        },
    }


def group_findings_by_rule(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    hit_session_sets: dict[str, set[str]] = {}
    for finding in findings:
        fol_id = str(finding.get("fol_id", ""))
        if not fol_id:
            continue
        session_id = str(finding.get("session_id", ""))
        bucket = grouped.setdefault(
            fol_id,
            {
                "fol_id": fol_id,
                "scenario_id": finding.get("scenario_id", ""),
                "scenario_title": finding.get("scenario_title", ""),
                "security_type": finding.get("security_type", ""),
                "risk_level": finding.get("risk_level", ""),
                "hit_count": 0,
                "hit_session_count": 0,
                "hit_session_ids": [],
                "hit_sessions": [],
            },
        )
        hit_session_sets.setdefault(fol_id, set())
        if session_id:
            hit_session_sets[fol_id].add(session_id)
        bucket["hit_count"] += 1
        bucket["hit_sessions"].append(
            {
                "session_id": session_id,
                "source_ip": finding.get("source_ip", ""),
                "expression_hits": finding.get("expression_hits", []),
                "session_context": finding.get("session_context", {}),
            }
        )
    for fol_id, session_ids in hit_session_sets.items():
        grouped[fol_id]["hit_session_ids"] = sorted(session_ids)
        grouped[fol_id]["hit_session_count"] = len(session_ids)
    return grouped


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    input_dir = Path(args.input_dir) if args.input_dir else base_dir / "log_sequence"
    fol_file = Path(args.fol_file) if args.fol_file else base_dir / "fol_expressions" / f"site_{args.site_id}_fol_expressions.json"
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "fol_rule_violations"

    fol_payload = read_json(fol_file)
    rules = [
        item
        for item in fol_payload.get("expressions", [])
        if isinstance(item, dict)
        and item.get("status") == "generated"
        and not item.get("refinement", {}).get("disabled")
    ]
    files = discover_input_files(input_dir, args.bucket, args.site_id)
    if not files:
        raise FileNotFoundError(f"no input sequence files found in {input_dir}")

    sessions = []
    filtered_frontend_noise_count = 0
    for session in iter_sessions(files):
        if args.site_id and session.get("site_id") != args.site_id:
            continue
        session = apply_business_focus_filter(session, args.include_frontend_noise)
        filtered_frontend_noise_count += int(session.get("filtered_frontend_noise_count", 0) or 0)
        if not session.get("api_sequence"):
            continue
        sessions.append(session)
        if args.max_sessions > 0 and len(sessions) >= args.max_sessions:
            break

    findings = []
    rule_hit_counter: Counter[str] = Counter()
    emitted_rule_counter: Counter[str] = Counter()
    for session in sessions:
        for rule in rules:
            expr_hits = detect_rule_on_session(rule, session)
            if not expr_hits:
                continue
            rule_id = str(rule.get("fol_id", ""))
            rule_hit_counter[rule_id] += 1
            if args.max_evidence_per_rule > 0 and emitted_rule_counter[rule_id] >= args.max_evidence_per_rule:
                continue
            emitted_rule_counter[rule_id] += 1
            findings.append(summarize_hit(rule, session, expr_hits))

    rule_findings = group_findings_by_rule(findings)
    hit_session_ids = sorted({str(finding.get("session_id", "")) for finding in findings if str(finding.get("session_id", ""))})
    payload = {
        "site_id": args.site_id,
        "fol_file": str(fol_file),
        "input_dir": str(input_dir),
        "session_count": len(sessions),
        "frontend_noise_filter": {
            "enabled": not args.include_frontend_noise,
            "filtered_event_count": filtered_frontend_noise_count,
        },
        "rule_count": len(rules),
        "finding_count": len(findings),
        "hit_session_count": len(hit_session_ids),
        "hit_session_ids": hit_session_ids,
        "rule_hit_count": dict(rule_hit_counter),
        "emitted_rule_evidence_count": dict(emitted_rule_counter),
        "max_evidence_per_rule": args.max_evidence_per_rule,
        "rule_findings": rule_findings,
        "findings": findings,
    }
    output_path = output_dir / f"site_{args.site_id}_fol_rule_violations.json"
    write_json(output_path, payload)
    print(
        f"site={args.site_id} sessions={len(sessions)} rules={len(rules)} "
        f"findings={len(findings)} output={output_path}"
    )


if __name__ == "__main__":
    main()
