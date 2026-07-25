# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


DEFAULT_BASE_DIR = str(Path(__file__).resolve().parent / "artifacts" / "train")
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
AUTH_RESPONSE_KEYWORDS = ["token", "session", "permission", "permissions", "access", "allowed", "role", "roles"]
DEFAULT_REFRESH_KEYWORDS = ["/refresh", "/reload", "refresh=", "up_refresh", "quickreload"]


def user_type_is_normal(value: Any) -> bool:
    return str(value if value is not None else "").strip() in {"0", "0.0"}


def label_from_user_types(values: list[Any]) -> dict[str, Any]:
    user_types = [str(value if value is not None else "").strip() for value in values if str(value if value is not None else "").strip()]
    is_anomalous = any(not user_type_is_normal(value) for value in user_types)
    return {
        "user_types": sorted(set(user_types)),
        "label": "abnormal" if is_anomalous else "normal",
        "is_anomalous": is_anomalous,
        "label_source": "user_type_all_zero_normal_else_abnormal",
    }


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
    parser.add_argument("--filter-input-site", action="store_true", help="Only keep input sessions whose site_id equals --site-id. Disabled by default so generated rules can be applied to merged test sessions.")
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


def parse_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def status_from_token(token: str) -> int:
    match = STATUS_SUFFIX_RE.search(str(token or "").strip())
    return parse_int(match.group("status")) if match else 0


def parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def seconds_between(left: Any, right: Any) -> float | None:
    left_time = parse_time(left)
    right_time = parse_time(right)
    if not left_time or not right_time:
        return None
    return abs((right_time - left_time).total_seconds())


def event_headers(event: dict[str, Any]) -> dict[str, str]:
    for key in ("requestHeaders", "request_headers", "headers", "header", "requestHeader"):
        value = event.get(key)
        if isinstance(value, dict):
            return {str(k).lower(): str(v) for k, v in value.items()}
        if isinstance(value, str):
            return {"raw": value}
    return {}


def event_response_text(event: dict[str, Any]) -> str:
    for key in ("responseData", "responseBody", "response_body", "response", "body"):
        if event.get(key) is not None:
            return str(event.get(key))
    return ""


def event_status(event: dict[str, Any], raw: str) -> int:
    for key in ("status_code", "ser_status_code", "http.status_code", "statusCode", "responseStatus", "status"):
        status = parse_int(event.get(key))
        if status:
            return status
    return status_from_token(raw)


def event_raw_request(event: dict[str, Any]) -> str:
    for key in (
        "full_api_request",
        "token",
        "api_request_pattern",
        "raw_request",
        "request",
        "api",
        "api_pattern",
    ):
        value = event.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    method = str(event.get("method") or event.get("http_method") or "").upper().strip()
    path = str(event.get("path") or event.get("url") or event.get("uri") or "").strip()
    if method and path:
        return f"{method} {path}"
    return path


def event_detail_from_raw(raw: str) -> dict[str, Any]:
    return {
        "api": request_api(raw),
        "status": status_from_token(raw),
        "response_text": "",
        "request_time": "",
        "response_time": "",
        "headers": {},
        "raw": raw,
    }


def event_detail_from_event(event: dict[str, Any], raw: str) -> dict[str, Any]:
    return {
        "api": request_api(raw),
        "status": event_status(event, raw),
        "response_text": event_response_text(event),
        "request_time": str(event.get("requestTime") or event.get("request_time") or ""),
        "response_time": str(event.get("responseTime") or event.get("response_time") or ""),
        "headers": event_headers(event),
        "user_type": event.get("user_type"),
        "label": event.get("label"),
        "is_anomalous": event.get("is_anomalous"),
        "raw": raw,
    }


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
    event_details: list[dict[str, Any]] = []
    event_user_types: list[Any] = []
    status_sequence = session_obj.get("status_sequence", session_obj.get("status_code_sequence", []))
    if not isinstance(status_sequence, list):
        status_sequence = []
    sequence_obj = session_obj.get("sequence", {})
    if isinstance(sequence_obj, dict):
        sequence_events = []
        for _, event in sorted(sequence_obj.items(), key=lambda item: int(item[0])):
            if isinstance(event, dict):
                if event.get("user_type") is not None:
                    event_user_types.append(event.get("user_type"))
                raw = event_raw_request(event)
                if raw:
                    sequence_events.append(raw)
                    event_details.append(event_detail_from_event(event, raw))
        if sequence_events:
            raw_sequence = sequence_events
    if not isinstance(raw_sequence, list) or not raw_sequence:
        raw_sequence = session_obj.get("api_sequence", [])
    if isinstance(raw_sequence, list) and raw_sequence and all(isinstance(item, dict) for item in raw_sequence):
        raw_sequence_from_events = []
        for event in raw_sequence:
            if event.get("user_type") is not None:
                event_user_types.append(event.get("user_type"))
            raw = event_raw_request(event)
            if raw:
                raw_sequence_from_events.append(raw)
                event_details.append(event_detail_from_event(event, raw))
        raw_sequence = raw_sequence_from_events
    if not isinstance(raw_sequence, list) or not raw_sequence:
        raw_sequence = []
        if isinstance(sequence_obj, dict):
            for _, event in sorted(sequence_obj.items(), key=lambda item: int(item[0])):
                if isinstance(event, dict):
                    if event.get("user_type") is not None:
                        event_user_types.append(event.get("user_type"))
                    raw = event_raw_request(event)
                    if raw:
                        raw_sequence.append(raw)
                        event_details.append(event_detail_from_event(event, raw))
    raw = [str(item).strip() for item in raw_sequence if str(item).strip()]
    if not event_details:
        event_details = [event_detail_from_raw(item) for item in raw]
    for index, detail in enumerate(event_details):
        if parse_int(detail.get("status")):
            continue
        if index < len(status_sequence):
            detail["status"] = parse_int(status_sequence[index])
    if not status_sequence:
        status_sequence = [parse_int(detail.get("status")) for detail in event_details]
    if not event_user_types:
        event_user_types = [detail.get("user_type") for detail in event_details if detail.get("user_type") is not None]
    if session_obj.get("label") is not None or session_obj.get("is_anomalous") is not None:
        label_text = str(session_obj.get("label") or "").strip().lower()
        is_anomalous = bool(session_obj.get("is_anomalous")) or label_text in {
            "abnormal",
            "anomaly",
            "attack",
            "malicious",
            "true",
            "1",
        }
        label_info = {
            "user_types": session_obj.get("user_types", sorted(set(str(value).strip() for value in event_user_types if str(value).strip()))),
            "label": "abnormal" if is_anomalous else "normal",
            "is_anomalous": is_anomalous,
            "label_source": session_obj.get("label_source", "session_label"),
        }
    else:
        label_info = label_from_user_types(event_user_types)
    return {
        "site_id": str(session_obj.get("site_id") or "unknown_site"),
        "session_id": str(session_obj.get("session_id") or ""),
        "source_ip": str(session_obj.get("source_ip") or session_obj.get("client_key") or ""),
        "raw_sequence": raw,
        "api_sequence": [request_api(item) for item in raw if request_api(item)],
        "event_details": event_details,
        "status_sequence": status_sequence,
        **label_info,
    }


def apply_business_focus_filter(session: dict[str, Any], include_frontend_noise: bool) -> dict[str, Any]:
    if include_frontend_noise:
        return session
    raw_sequence = []
    api_sequence = []
    event_details = []
    status_sequence = []
    for index, (raw, api) in enumerate(zip(session.get("raw_sequence", []), session.get("api_sequence", []))):
        if is_frontend_noise_api(api):
            continue
        raw_sequence.append(raw)
        api_sequence.append(api)
        details = session.get("event_details", [])
        if index < len(details):
            event_details.append(details[index])
        statuses = session.get("status_sequence", [])
        if index < len(statuses):
            status_sequence.append(parse_int(statuses[index]))
    filtered = dict(session)
    filtered["raw_sequence"] = raw_sequence
    filtered["api_sequence"] = api_sequence
    filtered["event_details"] = event_details
    filtered["status_sequence"] = status_sequence
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
            "event_details": [event_detail_from_raw(item) for item in raw],
            "status_sequence": [status_from_token(item) for item in raw],
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


def discover_input_files(input_dir: Path, bucket: str, site_id: str, filter_site: bool = False) -> list[Path]:
    if not input_dir.exists():
        raise FileNotFoundError(f"input dir not found: {input_dir}")
    search_dirs = [input_dir]
    if (input_dir / "log_sequence").is_dir():
        search_dirs.insert(0, input_dir / "log_sequence")

    site_part = site_id if site_id and filter_site else "*"
    patterns = ["session_all.jsonl", f"session_site_{site_part}.jsonl", f"*site_{site_part}.txt"]
    files: list[Path] = []
    for root in search_dirs:
        for pattern in patterns:
            files.extend(sorted(root.glob(pattern)))
    if not files and bucket != "all":
        for root in search_dirs:
            if (root / bucket).exists():
                for pattern in patterns:
                    files.extend(sorted((root / bucket).glob(pattern)))
    if not files:
        for root in search_dirs:
            for pattern in patterns:
                files.extend(sorted(root.glob(f"**/{pattern}")))

    unique: list[Path] = []
    seen: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    if filter_site:
        return [path for path in unique if path.name == "session_all.jsonl" or file_matches_site(path, site_id)]
    return unique


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


def normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def scope_exclude_keywords(scope: dict[str, Any]) -> list[str]:
    keywords = normalize_string_list(scope.get("exclude_if_session_contains_api_keywords"))
    keywords.extend(normalize_string_list(scope.get("exclude_api_keywords")))
    context = scope.get("exclude_context")
    if isinstance(context, dict):
        keywords.extend(normalize_string_list(context.get("api_keywords")))
    refresh = scope.get("exclude_refresh_context", scope.get("refresh_exclusion", False))
    if refresh:
        keywords.extend(DEFAULT_REFRESH_KEYWORDS)
    return sorted({keyword.lower() for keyword in keywords if keyword})


def session_contains_keyword(session: dict[str, Any], keywords: list[str]) -> bool:
    if not keywords:
        return False
    haystack = "\n".join(
        str(item).lower()
        for item in list(session.get("api_sequence", [])) + list(session.get("raw_sequence", []))
    )
    return any(keyword in haystack for keyword in keywords)


def scope_counting_parameter(scope: dict[str, Any]) -> str:
    for key in (
        "count_within_same_parameter",
        "same_parameter",
        "same_parameter_name",
        "group_by_parameter",
        "consistent_parameter",
    ):
        value = str(scope.get(key, "") or "").strip()
        if value:
            return value
    context = scope.get("context_requirement")
    if isinstance(context, dict):
        for key in ("count_within_same_parameter", "same_parameter", "group_by_parameter"):
            value = str(context.get(key, "") or "").strip()
            if value:
                return value
    return ""


def param_values_at_step(session: dict[str, Any], step_index: int, parameter: str) -> list[str]:
    if not parameter:
        return []
    raw_sequence = session.get("raw_sequence", [])
    if step_index < 0 or step_index >= len(raw_sequence):
        return []
    values = []
    for observed_name, observed_values in request_params(raw_sequence[step_index]).items():
        if parameter_name_matches(observed_name, parameter):
            values.extend(str(value) for value in observed_values if str(value) not in {"", "null", "undefined"})
    return values


def status_class(status: int) -> str:
    return f"{int(status) // 100}xx" if status else ""


def event_status_at(session: dict[str, Any], step_index: int) -> int:
    details = session.get("event_details", [])
    if 0 <= step_index < len(details) and isinstance(details[step_index], dict):
        status = parse_int(details[step_index].get("status"))
        if status:
            return status
    status_sequence = session.get("status_sequence", [])
    if 0 <= step_index < len(status_sequence):
        status = parse_int(status_sequence[step_index])
        if status:
            return status
    raw_sequence = session.get("raw_sequence", [])
    if 0 <= step_index < len(raw_sequence):
        return status_from_token(str(raw_sequence[step_index]))
    return 0


def status_matches(status: int, codes: list[str], classes: list[str]) -> bool:
    if not status:
        return False
    status_text = str(status)
    class_text = status_class(status)
    return status_text in {str(item) for item in codes} or class_text in {str(item).lower() for item in classes}


def positions_status_evidence(
    session: dict[str, Any],
    positions: list[int],
    codes: list[str] | None = None,
    classes: list[str] | None = None,
) -> list[dict[str, Any]]:
    codes = [str(item) for item in (codes or []) if str(item)]
    classes = [str(item).lower() for item in (classes or []) if str(item)]
    evidence = []
    for index in positions:
        status = event_status_at(session, index)
        if status_matches(status, codes, classes):
            api = session.get("api_sequence", [""])[index] if index < len(session.get("api_sequence", [])) else ""
            evidence.append({"step": index + 1, "api": api, "status": status, "status_class": status_class(status)})
    return evidence


def status_constraints_evidence(
    rule: dict[str, Any],
    scope: dict[str, Any],
    session: dict[str, Any],
) -> dict[str, Any]:
    constraints = scope.get("status_code_constraints", {}) if isinstance(scope.get("status_code_constraints"), dict) else {}
    if not constraints:
        return {}
    amap = activity_map(rule)
    evidence: dict[str, Any] = {}

    target_symbol = str(constraints.get("target_activity") or scope.get("target_activity") or scope.get("activity") or "")
    target_api = amap.get(target_symbol, "")
    target_positions = api_positions(session, target_api) if target_api else []
    target_classes = normalize_scope_list(constraints.get("target_status_classes", []))
    target_codes = normalize_scope_list(constraints.get("target_status_codes", []))
    if target_positions and (target_classes or target_codes):
        matches = positions_status_evidence(session, target_positions, target_codes, target_classes)
        if matches:
            evidence["target_status"] = matches[:10]
        else:
            evidence["target_status_unmatched"] = {
                "api": target_api,
                "expected_codes": target_codes,
                "expected_classes": target_classes,
                "note": "状态码证据未匹配；响应码只作为证据层，不阻断规则命中。",
            }

    precheck_symbol = str(constraints.get("precheck_activity") or scope.get("required_activity") or "")
    precheck_api = amap.get(precheck_symbol, "")
    precheck_positions = api_positions(session, precheck_api) if precheck_api else []
    precheck_codes = normalize_scope_list(constraints.get("precheck_status_codes", []))
    precheck_classes = normalize_scope_list(constraints.get("precheck_status_classes", []))
    if precheck_positions and (precheck_codes or precheck_classes):
        matches = positions_status_evidence(session, precheck_positions, precheck_codes, precheck_classes)
        if matches:
            evidence["precheck_status"] = matches[:10]
        else:
            evidence["precheck_status_unmatched"] = {
                "api": precheck_api,
                "expected_codes": precheck_codes,
                "expected_classes": precheck_classes,
                "note": "前置 API 状态码证据未匹配；不阻断顺序规则命中。",
            }

    server_error_classes = normalize_scope_list(constraints.get("server_error_status_classes", []))
    if target_positions and server_error_classes:
        matches = positions_status_evidence(session, target_positions, [], server_error_classes)
        if matches:
            evidence["server_error_status"] = matches[:10]
        else:
            evidence["server_error_status_unmatched"] = {
                "api": target_api,
                "expected_classes": server_error_classes,
                "note": "5xx 证据未匹配；不阻断规则命中。",
            }

    target_api_scope = normalize_scope_list(constraints.get("target_api_scope", []))
    api_status_classes = normalize_scope_list(constraints.get("target_status_classes", []))
    if target_api_scope and api_status_classes:
        api_matches = []
        for api in target_api_scope:
            api_matches.extend(positions_status_evidence(session, api_positions(session, api), [], api_status_classes))
        if api_matches:
            evidence["target_api_scope_status"] = api_matches[:10]
        else:
            evidence["target_api_scope_status_unmatched"] = {
                "target_api_scope": target_api_scope[:20],
                "expected_classes": api_status_classes,
                "note": "参数相关 API 状态码证据未匹配；不阻断参数规则命中。",
            }

    if constraints.get("status_code_analysis"):
        evidence["status_code_analysis"] = str(constraints.get("status_code_analysis"))
    return evidence


def first_before(left_positions: list[int], right_index: int) -> int | None:
    candidates = [index for index in left_positions if index < right_index]
    return max(candidates) if candidates else None


def detect_sequence_order(rule: dict[str, Any], expr: dict[str, Any], session: dict[str, Any]) -> list[dict[str, Any]]:
    amap = activity_map(rule)
    scope = expr.get("scope", {}) if isinstance(expr.get("scope"), dict) else {}
    if session_contains_keyword(session, scope_exclude_keywords(scope)):
        return []
    status_evidence = status_constraints_evidence(rule, scope, session)
    mode = str(scope.get("mode", ""))
    hits = []
    if mode == "repeated_call":
        symbol = str(scope.get("activity", ""))
        api = amap.get(symbol, "")
        threshold = int(str(scope.get("threshold") or "2"))
        positions = api_positions(session, api)
        counting_parameter = scope_counting_parameter(scope)
        if counting_parameter:
            grouped_positions: dict[str, list[int]] = defaultdict(list)
            for position in positions:
                for value in param_values_at_step(session, position, counting_parameter):
                    grouped_positions[value].append(position)
            if not grouped_positions:
                return []
            value, positions = max(grouped_positions.items(), key=lambda item: len(item[1]))
        else:
            value = ""
        if len(positions) >= threshold:
            hits.append(
                {
                    "reason": "repeated_call",
                    "api": api,
                    "threshold": threshold,
                    "count": len(positions),
                    "steps": [index + 1 for index in positions],
                    "requests": [session["raw_sequence"][index] for index in positions[:10]],
                    "key_context_steps": compact_step_evidence(session, positions),
                    "key_target_steps": compact_step_evidence(session, positions),
                    "count_within_same_parameter": counting_parameter,
                    "counting_parameter_value": value,
                    "status_evidence": status_evidence,
                }
            )
        return hits

    if mode in {"missing_or_reordered_step", "missing_step"}:
        required_symbol = str(scope.get("required_activity", ""))
        target_symbol = str(scope.get("target_activity", ""))
        required_api = amap.get(required_symbol, "")
        target_api = amap.get(target_symbol, "")
        required_positions = api_positions(session, required_api)
        target_positions = api_positions(session, target_api)
        if mode == "missing_step" and required_positions:
            return []
        for target_index in target_positions:
            before_index = first_before(required_positions, target_index)
            if before_index is None:
                hits.append(
                    {
                        "reason": "required_step_missing" if mode == "missing_step" else "required_before_missing",
                        "required_api": required_api,
                        "target_api": target_api,
                        "target_step": target_index + 1,
                        "target_request": session["raw_sequence"][target_index],
                        "key_context_steps": compact_step_evidence(session, required_positions),
                        "key_target_steps": compact_step_evidence(session, [target_index]),
                        "missing_context": {
                            "required_api": required_api,
                            "expected_before_target_step": target_index + 1,
                            "observed_required_steps": [index + 1 for index in required_positions],
                        },
                        "status_evidence": status_evidence,
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
                "key_target_steps": compact_step_evidence(session, [index]),
                "status_evidence": status_evidence,
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
                                "status": event_status_at(session, index),
                                "observed_parameter": observed_name,
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


def compact_step_evidence(session: dict[str, Any], step_indexes: list[int], limit: int = 10) -> list[dict[str, Any]]:
    output = []
    raw_sequence = session.get("raw_sequence", [])
    api_sequence = session.get("api_sequence", [])
    for index in step_indexes[:limit]:
        if index < 0:
            continue
        output.append(
            {
                "step": index + 1,
                "api": api_sequence[index] if index < len(api_sequence) else "",
                "status": event_status_at(session, index),
                "request": raw_sequence[index] if index < len(raw_sequence) else "",
            }
        )
    return output


def compact_param_occurrences(items: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    output = []
    for item in items[:limit]:
        output.append(
            {
                "step": item.get("step"),
                "api": item.get("api", ""),
                "status": item.get("status", 0),
                "parameter": item.get("observed_parameter", ""),
                "value": item.get("value", ""),
                "request": item.get("request", ""),
            }
        )
    return output


def parameter_value_changes(parameter: str, items: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    ordered = sorted(
        [item for item in items if str(item.get("value", "")) not in {"", "null", "undefined"}],
        key=lambda item: int(item.get("step", 0) or 0),
    )
    changes = []
    previous: dict[str, Any] | None = None
    for item in ordered:
        if previous and str(previous.get("value")) != str(item.get("value")):
            changes.append(
                {
                    "parameter": parameter,
                    "from_value": previous.get("value", ""),
                    "to_value": item.get("value", ""),
                    "from_step": previous.get("step"),
                    "to_step": item.get("step"),
                    "from_api": previous.get("api", ""),
                    "to_api": item.get("api", ""),
                    "from_status": previous.get("status", 0),
                    "to_status": item.get("status", 0),
                }
            )
            if len(changes) >= limit:
                break
        previous = item
    return changes


def parameter_context_summary(
    parameter: str,
    target_items: list[dict[str, Any]],
    context_items: list[dict[str, Any]],
) -> dict[str, Any]:
    target_values = non_empty_values(target_items)
    context_values = non_empty_values(context_items)
    return {
        "parameter": parameter,
        "target_values": target_values[:20],
        "context_values": context_values[:20],
        "unexpected_target_values": [value for value in target_values if value not in set(context_values)][:20],
        "missing_from_context": bool(target_values and not context_values),
        "target_occurrences": compact_param_occurrences(target_items),
        "context_occurrences": compact_param_occurrences(context_items),
        "value_changes_in_target": parameter_value_changes(parameter, target_items),
    }


def target_parameter_pair_specs(scope: dict[str, Any], wanted_params: list[str]) -> list[dict[str, str]]:
    specs = []
    raw_specs = (
        scope.get("target_parameter_consistency_pairs")
        or scope.get("same_target_parameter_pairs")
        or scope.get("intra_target_parameter_relations")
        or scope.get("parameter_consistency_pairs")
        or []
    )
    if isinstance(raw_specs, dict):
        raw_specs = [raw_specs]
    if isinstance(raw_specs, list):
        for item in raw_specs:
            if not isinstance(item, dict):
                continue
            left = str(item.get("left") or item.get("source") or item.get("parameter") or item.get("parameter_a") or "").strip()
            right = str(item.get("right") or item.get("target") or item.get("derived_parameter") or item.get("parameter_b") or "").strip()
            if left and right:
                specs.append(
                    {
                        "left": left,
                        "right": right,
                        "relation": str(item.get("relation") or "same_value"),
                        "source": "scope",
                    }
                )
    wanted = {item.lower(): item for item in wanted_params}
    if "stepid" in wanted and "testrunstepid" in wanted:
        specs.append(
            {
                "left": wanted["stepid"],
                "right": wanted["testrunstepid"],
                "relation": "same_value",
                "source": "heuristic_stepId_testRunStepId",
            }
        )
    unique = []
    seen = set()
    for item in specs:
        marker = (item["left"].lower(), item["right"].lower(), item["relation"].lower())
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(item)
    return unique


def target_parameter_pair_mismatches(
    target_values: dict[str, list[dict[str, Any]]],
    pair_specs: list[dict[str, str]],
    status_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    hits = []
    for spec in pair_specs:
        left = spec["left"]
        right = spec["right"]
        left_by_step: dict[int, list[dict[str, Any]]] = defaultdict(list)
        right_by_step: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for item in target_values.get(left, []):
            left_by_step[int(item.get("step", 0) or 0)].append(item)
        for item in target_values.get(right, []):
            right_by_step[int(item.get("step", 0) or 0)].append(item)
        mismatches = []
        for step in sorted(set(left_by_step) & set(right_by_step)):
            left_values = non_empty_values(left_by_step[step])
            right_values = non_empty_values(right_by_step[step])
            if left_values and right_values and set(left_values) != set(right_values):
                mismatches.append(
                    {
                        "step": step,
                        "api": left_by_step[step][0].get("api", right_by_step[step][0].get("api", "")),
                        "status": left_by_step[step][0].get("status", right_by_step[step][0].get("status", 0)),
                        "left_parameter": left,
                        "left_values": left_values,
                        "right_parameter": right,
                        "right_values": right_values,
                        "left_occurrences": compact_param_occurrences(left_by_step[step]),
                        "right_occurrences": compact_param_occurrences(right_by_step[step]),
                    }
                )
        if mismatches:
            hits.append(
                {
                    "reason": "target_parameter_relation_mismatch",
                    "relation": spec.get("relation", "same_value"),
                    "relation_source": spec.get("source", ""),
                    "left_parameter": left,
                    "right_parameter": right,
                    "mismatches": mismatches[:10],
                    "key_target_steps": [
                        occurrence
                        for mismatch in mismatches[:10]
                        for occurrence in (mismatch.get("left_occurrences", []) + mismatch.get("right_occurrences", []))
                    ],
                    "changed_parameters": [
                        {
                            "parameter_relation": f"{left} == {right}",
                            "parameter": right,
                            "from_value": ",".join(mismatch.get("left_values", [])),
                            "to_value": ",".join(mismatch.get("right_values", [])),
                            "from_step": mismatch.get("step"),
                            "to_step": mismatch.get("step"),
                            "from_api": mismatch.get("api", ""),
                            "to_api": mismatch.get("api", ""),
                            "from_status": mismatch.get("status", 0),
                            "to_status": mismatch.get("status", 0),
                        }
                        for mismatch in mismatches[:10]
                    ],
                    "status_evidence": status_evidence,
                }
            )
    return hits


def detect_parameter_consistency(rule: dict[str, Any], expr: dict[str, Any], session: dict[str, Any]) -> list[dict[str, Any]]:
    scope = expr.get("scope", {}) if isinstance(expr.get("scope"), dict) else {}
    if "parameter" in scope and isinstance(scope.get("parameter"), dict):
        scope = scope["parameter"]
    if session_contains_keyword(session, scope_exclude_keywords(scope)):
        return []
    status_evidence = status_constraints_evidence(rule, scope, session)
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
    hits.extend(target_parameter_pair_mismatches(target_values, target_parameter_pair_specs(scope, wanted_params), status_evidence))
    min_distinct_target_values = parse_int(scope.get("min_distinct_target_values")) or 2
    for name in wanted_params:
        target_items = target_values.get(name, [])
        context_items = context_values.get(name, [])
        target_distinct = non_empty_values(target_items)
        context_distinct = non_empty_values(context_items)
        param_context = parameter_context_summary(name, target_items, context_items)

        if len(target_distinct) >= min_distinct_target_values:
            hits.append(
                {
                    "reason": "parameter_value_switch",
                    "parameter": name,
                    "distinct_value_count": len(target_distinct),
                    "values": target_distinct[:20],
                    "steps": evidence_steps(target_items),
                    "examples": target_items[:10],
                    "key_target_steps": compact_param_occurrences(target_items),
                    "key_context_steps": compact_param_occurrences(context_items),
                    "changed_parameters": parameter_value_changes(name, target_items),
                    "parameter_context": param_context,
                    "status_evidence": status_evidence,
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
                    "key_target_steps": compact_param_occurrences(target_items),
                    "key_context_steps": compact_param_occurrences(context_items),
                    "changed_parameters": parameter_value_changes(name, target_items),
                    "parameter_context": param_context,
                    "status_evidence": status_evidence,
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
                        "key_target_steps": compact_param_occurrences(target_items),
                        "key_context_steps": compact_param_occurrences(context_items),
                        "changed_parameters": parameter_value_changes(name, target_items),
                        "parameter_context": param_context,
                        "status_evidence": status_evidence,
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


def collect_hit_context_summary(expr_hits: list[dict[str, Any]]) -> dict[str, Any]:
    key_context_steps = []
    key_target_steps = []
    changed_parameters = []
    parameter_contexts = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.get("key_context_steps", []) or []:
                if isinstance(item, dict):
                    key_context_steps.append(item)
            for item in value.get("key_target_steps", []) or []:
                if isinstance(item, dict):
                    key_target_steps.append(item)
            for item in value.get("changed_parameters", []) or []:
                if isinstance(item, dict):
                    changed_parameters.append(item)
            if isinstance(value.get("parameter_context"), dict):
                parameter_contexts.append(value["parameter_context"])
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(expr_hits)

    def unique_items(items: list[dict[str, Any]], keys: tuple[str, ...], limit: int = 30) -> list[dict[str, Any]]:
        output = []
        seen = set()
        for item in items:
            marker = tuple(str(item.get(key, "")) for key in keys)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(item)
            if len(output) >= limit:
                break
        return output

    return {
        "key_context_steps": unique_items(key_context_steps, ("step", "api", "parameter", "value")),
        "key_target_steps": unique_items(key_target_steps, ("step", "api", "parameter", "value")),
        "changed_parameters": unique_items(changed_parameters, ("parameter", "from_step", "to_step", "from_value", "to_value")),
        "parameter_contexts": unique_items(parameter_contexts, ("parameter",)),
    }


def summarize_hit(rule: dict[str, Any], session: dict[str, Any], expr_hits: list[dict[str, Any]]) -> dict[str, Any]:
    source = rule.get("source", {})
    summary = rule.get("scenario_summary", {})
    hit_context_summary = collect_hit_context_summary(expr_hits)
    return {
        "fol_id": rule.get("fol_id", ""),
        "scenario_id": source.get("scenario_id", ""),
        "scenario_title": source.get("scenario_title", ""),
        "security_type": summary.get("security_type", source.get("security_type", "")),
        "risk_level": summary.get("risk_level", ""),
        "session_id": session.get("session_id", ""),
        "source_ip": session.get("source_ip", ""),
        "session_label": session.get("label", ""),
        "session_is_anomalous": bool(session.get("is_anomalous")),
        "session_user_types": session.get("user_types", []),
        "business_pattern_name": source.get("business_pattern_name", ""),
        "overall_reason": summary.get("overall_reason", ""),
        "expression_hits": expr_hits,
        "hit_context_summary": hit_context_summary,
        "session_context": {
            "raw_sequence": session.get("raw_sequence", []),
            "api_sequence": session.get("api_sequence", []),
            "filtered_frontend_noise_count": session.get("filtered_frontend_noise_count", 0),
            "label": session.get("label", ""),
            "is_anomalous": bool(session.get("is_anomalous")),
            "user_types": session.get("user_types", []),
            "label_source": session.get("label_source", ""),
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
                "anomalous_session_count": 0,
                "true_positive_session_count": 0,
                "false_positive_session_count": 0,
                "hit_session_ids": [],
                "affected_session_ids": [],
                "sampled_anomalous_sessions": [],
                "sampled_false_positive_sessions": [],
                "hit_sessions": [],
            },
        )
        hit_session_sets.setdefault(fol_id, set())
        if session_id:
            hit_session_sets[fol_id].add(session_id)
        bucket["hit_count"] += len(finding.get("expression_hits", []) or [])
        bucket["hit_sessions"].append(
            {
                "session_id": session_id,
                "source_ip": finding.get("source_ip", ""),
                "session_label": finding.get("session_label", ""),
                "session_is_anomalous": bool(finding.get("session_is_anomalous")),
                "session_user_types": finding.get("session_user_types", []),
                "expression_hits": finding.get("expression_hits", []),
                "hit_context_summary": finding.get("hit_context_summary", {}),
                "session_context": finding.get("session_context", {}),
            }
        )
    for fol_id, session_ids in hit_session_sets.items():
        grouped[fol_id]["hit_session_ids"] = sorted(session_ids)
        grouped[fol_id]["hit_session_count"] = len(session_ids)
        grouped[fol_id]["anomalous_session_count"] = len(session_ids)
        grouped[fol_id]["affected_session_ids"] = sorted(session_ids)
        grouped[fol_id]["sampled_anomalous_sessions"] = sorted(session_ids)[:20]
    return grouped


def apply_rule_count_totals(
    rule_findings: dict[str, dict[str, Any]],
    rule_hit_counter: Counter[str],
    rule_session_sets: dict[str, set[str]],
    session_labels: dict[str, bool] | None = None,
) -> None:
    session_labels = session_labels or {}
    for fol_id, hit_count in rule_hit_counter.items():
        session_ids = sorted(rule_session_sets.get(fol_id, set()))
        true_positive_ids = [session_id for session_id in session_ids if session_labels.get(session_id)]
        false_positive_ids = [session_id for session_id in session_ids if session_id in session_labels and not session_labels.get(session_id)]
        bucket = rule_findings.setdefault(
            fol_id,
            {
                "fol_id": fol_id,
                "scenario_id": "",
                "scenario_title": "",
                "security_type": "",
                "risk_level": "",
                "hit_sessions": [],
            },
        )
        bucket["hit_count"] = int(hit_count)
        bucket["hit_session_count"] = len(session_ids)
        bucket["anomalous_session_count"] = len(session_ids)
        bucket["true_positive_session_count"] = len(true_positive_ids)
        bucket["false_positive_session_count"] = len(false_positive_ids)
        bucket["hit_session_ids"] = session_ids
        bucket["affected_session_ids"] = session_ids
        bucket["sampled_anomalous_sessions"] = session_ids[:20]
        bucket["sampled_false_positive_sessions"] = false_positive_ids[:20]


def build_detection_evaluation(
    sessions: list[dict[str, Any]],
    hit_session_ids: list[str],
    rule_session_sets: dict[str, set[str]],
) -> dict[str, Any]:
    session_labels = {str(session.get("session_id", "")): bool(session.get("is_anomalous")) for session in sessions if session.get("session_id")}
    actual_anomalous_ids = {session_id for session_id, is_anomalous in session_labels.items() if is_anomalous}
    actual_normal_ids = set(session_labels) - actual_anomalous_ids
    predicted_anomalous_ids = set(hit_session_ids)
    true_positive_ids = sorted(predicted_anomalous_ids & actual_anomalous_ids)
    false_positive_ids = sorted(predicted_anomalous_ids & actual_normal_ids)
    false_negative_ids = sorted(actual_anomalous_ids - predicted_anomalous_ids)
    true_negative_ids = sorted(actual_normal_ids - predicted_anomalous_ids)
    precision = len(true_positive_ids) / (len(true_positive_ids) + len(false_positive_ids)) if true_positive_ids or false_positive_ids else 0.0
    recall = len(true_positive_ids) / (len(true_positive_ids) + len(false_negative_ids)) if true_positive_ids or false_negative_ids else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "label_rule": "session is normal only when every API user_type is 0; otherwise abnormal",
        "labeled_session_count": len(session_labels),
        "actual_normal_session_count": len(actual_normal_ids),
        "actual_anomalous_session_count": len(actual_anomalous_ids),
        "predicted_normal_session_count": len(session_labels) - len(predicted_anomalous_ids & set(session_labels)),
        "predicted_anomalous_session_count": len(predicted_anomalous_ids & set(session_labels)),
        "confusion_matrix": {
            "true_positive": len(true_positive_ids),
            "false_positive": len(false_positive_ids),
            "false_negative": len(false_negative_ids),
            "true_negative": len(true_negative_ids),
        },
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "sampled_true_positive_session_ids": true_positive_ids[:20],
        "sampled_false_positive_session_ids": false_positive_ids[:20],
        "sampled_false_negative_session_ids": false_negative_ids[:20],
        "sampled_true_negative_session_ids": true_negative_ids[:20],
        "rule_true_positive_session_count": {
            fol_id: len(set(session_ids) & actual_anomalous_ids) for fol_id, session_ids in sorted(rule_session_sets.items())
        },
        "rule_false_positive_session_count": {
            fol_id: len(set(session_ids) & actual_normal_ids) for fol_id, session_ids in sorted(rule_session_sets.items())
        },
    }


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
        and not item.get("disabled")
        and not item.get("refinement", {}).get("disabled")
    ]
    files = discover_input_files(input_dir, args.bucket, args.site_id, args.filter_input_site)
    if not files:
        raise FileNotFoundError(f"no input sequence files found in {input_dir}")

    sessions = []
    seen_session_ids: set[str] = set()
    filtered_frontend_noise_count = 0
    for session in iter_sessions(files):
        if args.filter_input_site and args.site_id and session.get("site_id") != args.site_id:
            continue
        session_id = str(session.get("session_id", ""))
        if session_id and session_id in seen_session_ids:
            continue
        if session_id:
            seen_session_ids.add(session_id)
        session = apply_business_focus_filter(session, args.include_frontend_noise)
        filtered_frontend_noise_count += int(session.get("filtered_frontend_noise_count", 0) or 0)
        if not session.get("api_sequence"):
            continue
        sessions.append(session)
        if args.max_sessions > 0 and len(sessions) >= args.max_sessions:
            break

    findings = []
    rule_hit_counter: Counter[str] = Counter()
    rule_session_sets: dict[str, set[str]] = defaultdict(set)
    emitted_rule_counter: Counter[str] = Counter()
    for session in sessions:
        for rule in rules:
            expr_hits = detect_rule_on_session(rule, session)
            if not expr_hits:
                continue
            rule_id = str(rule.get("fol_id", ""))
            session_id = str(session.get("session_id", ""))
            rule_hit_counter[rule_id] += len(expr_hits)
            if session_id:
                rule_session_sets[rule_id].add(session_id)
            if args.max_evidence_per_rule > 0 and emitted_rule_counter[rule_id] >= args.max_evidence_per_rule:
                continue
            emitted_rule_counter[rule_id] += 1
            findings.append(summarize_hit(rule, session, expr_hits))

    rule_findings = group_findings_by_rule(findings)
    session_labels = {str(session.get("session_id", "")): bool(session.get("is_anomalous")) for session in sessions if session.get("session_id")}
    apply_rule_count_totals(rule_findings, rule_hit_counter, rule_session_sets, session_labels)
    hit_session_ids = sorted({session_id for session_ids in rule_session_sets.values() for session_id in session_ids})
    total_rule_hit_count = sum(rule_hit_counter.values())
    detection_evaluation = build_detection_evaluation(sessions, hit_session_ids, rule_session_sets)
    payload = {
        "site_id": args.site_id,
        "fol_file": str(fol_file),
        "input_dir": str(input_dir),
        "session_count": len(sessions),
        "labeling": {
            "source": "user_type",
            "normal_condition": "all API events in a session have user_type == 0",
            "abnormal_condition": "any API event in a session has user_type != 0",
        },
        "actual_normal_session_count": detection_evaluation["actual_normal_session_count"],
        "actual_anomalous_session_count": detection_evaluation["actual_anomalous_session_count"],
        "frontend_noise_filter": {
            "enabled": not args.include_frontend_noise,
            "filtered_event_count": filtered_frontend_noise_count,
        },
        "rule_count": len(rules),
        "finding_count": len(findings),
        "hit_count": total_rule_hit_count,
        "hit_session_count": len(hit_session_ids),
        "anomalous_session_count": len(hit_session_ids),
        "detection_evaluation": detection_evaluation,
        "hit_session_ids": hit_session_ids,
        "affected_session_ids": hit_session_ids,
        "rule_hit_count": dict(rule_hit_counter),
        "rule_anomalous_session_count": {
            fol_id: len(session_ids) for fol_id, session_ids in sorted(rule_session_sets.items())
        },
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
