# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import parse_qsl, unquote, urlparse


# Default input/output paths. Edit these values to pin the runtime locations.
INPUT_PATH = "D:\\browser\\Innovation\\sequence\\log_process"
PARAMETER_PROFILE_OUTPUT_DIR = "D:\\browser\\Innovation\\sequence\\log_process\\parameter_profiles"
API_DOCUMENT_OUTPUT_DIR = "D:\\browser\\Innovation\\sequence\\log_process\\API document"
OPENAPI_VERSION = "3.2.0"

# Local LLM settings for OpenAPI document generation.
LOCAL_LLM_URL = "https://www.autodl.art/api/v1/chat/completions"
MODEL_NAME = "GLM-5.1"
USE_JSON_RESPONSE_FORMAT = False

LONG_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ISSUE_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]+-\d+$")
INT_RE = re.compile(r"^-?\d+$")
FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
SENSITIVE_NAME_RE = re.compile(r"(password|passwd|pwd|secret|token|authorization|cookie|session|credential|key)", re.IGNORECASE)
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
PASSIVE_API_KEYWORDS = {
    "asset",
    "assets",
    "static",
    "css",
    "js",
    "img",
    "image",
    "images",
    "font",
    "fonts",
    "favicon",
    "synchrony",
    "bayeux",
    "heartbeat",
    "poll",
    "batch",
    "resource",
    "resources",
    "wrm",
}
ACTIVE_API_KEYWORDS = {
    "login",
    "logout",
    "auth",
    "search",
    "comment",
    "comments",
    "post",
    "issue",
    "project",
    "space",
    "user",
    "profile",
    "setting",
    "settings",
    "admin",
    "upload",
    "download",
    "delete",
    "create",
    "edit",
    "update",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build path-clustered API parameter profiles and optional OpenAPI 3.2 docs.")
    parser.add_argument(
        "--input",
        default=os.getenv("SEQ_LOG_SEQUENCE_DIR", os.getenv("SEQ_URL_DATASET", INPUT_PATH)),
        help="Split site session dir, session_site_*.jsonl file, or url_dataset.jsonl file.",
    )
    parser.add_argument("--output-dir", default=os.getenv("SEQ_PARAM_PROFILE_DIR", PARAMETER_PROFILE_OUTPUT_DIR))
    parser.add_argument("--site-id", default="", help="Only process one site_id.")
    parser.add_argument("--max-examples", type=int, default=8)
    parser.add_argument("--top-param-sets", type=int, default=20)
    parser.add_argument(
        "--top-paths",
        "--max-profile-paths",
        "--max-profile-apis",
        dest="top_paths",
        type=int,
        default=0,
        help="Max API paths kept in the generated parameter profile. 0 means keep all paths.",
    )
    parser.add_argument("--sample-per-method", type=int, default=40)
    parser.add_argument(
        "--max-samples-per-path",
        type=int,
        default=40,
        help="Max log samples kept for each API path across all methods. 0 means keep all collected samples.",
    )
    parser.add_argument(
        "--generate-openapi-llm",
        dest="generate_openapi_llm",
        action="store_true",
        default=True,
        help="Generate OpenAPI documents by LLM. Enabled by default.",
    )
    parser.add_argument(
        "--no-generate-openapi-llm",
        dest="generate_openapi_llm",
        action="store_false",
        help="Only build parameter profiles; do not call LLM.",
    )
    parser.add_argument(
        "--openapi-output-dir",
        default=os.getenv("SEQ_API_DOCUMENT_DIR", API_DOCUMENT_OUTPUT_DIR),
        help="Directory for generated OpenAPI API documents.",
    )
    parser.add_argument(
        "--max-openapi-paths",
        "--max-api-docs",
        dest="max_openapi_paths",
        type=int,
        default=50,
        help="Max API paths per site sent to LLM for API document generation. 0 means all.",
    )
    parser.add_argument(
        "--max-openapi-prompt-chars",
        type=int,
        default=100000,
        help="Max characters in one OpenAPI LLM prompt. Keep below provider input limit.",
    )
    parser.add_argument(
        "--max-llm-request-bytes",
        type=int,
        default=120000,
        help="Max encoded JSON request body bytes sent to the LLM provider. Keep below provider input limit.",
    )
    parser.add_argument("--llm-url", default=os.getenv("LOCAL_LLM_URL", LOCAL_LLM_URL), help="OpenAI-compatible chat completions API URL.")
    parser.add_argument("--model", default=os.getenv("LOCAL_LLM_MODEL", MODEL_NAME), help="OpenAI-compatible model name.")
    parser.add_argument("--api-key", default=os.getenv("API_KEY", ""), help="Bearer token for the LLM API. Defaults to API_KEY env var.")
    parser.add_argument(
        "--skip-existing-openapi-paths",
        dest="skip_existing_openapi_paths",
        action="store_true",
        default=True,
        help="Skip paths already present in site_<site_id>_openapi.json. Enabled by default.",
    )
    parser.add_argument(
        "--no-skip-existing-openapi-paths",
        dest="skip_existing_openapi_paths",
        action="store_false",
        help="Regenerate paths even if they already exist in the OpenAPI document.",
    )
    parser.add_argument("--request-timeout", type=int, default=300)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--retry-sleep", type=int, default=5)
    return parser.parse_args()


def normalize_path(path: str) -> str:
    parts: list[str] = []
    for raw_part in str(path or "").split("/"):
        if raw_part == "":
            continue
        part = unquote(raw_part)
        lowered = part.lower()
        if part.startswith("{") and part.endswith("}"):
            parts.append(lowered)
        elif UUID_RE.match(part):
            parts.append("{uuid}")
        elif INT_RE.match(part):
            parts.append("{int}")
        elif ISSUE_KEY_RE.match(part):
            parts.append("{issue_key}")
        elif LONG_HEX_RE.match(part):
            parts.append("{hex}")
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", part):
            parts.append("{date}")
        elif re.fullmatch(r"[A-Za-z0-9_-]{24,}", part):
            parts.append("{token}")
        else:
            parts.append(lowered)
    return "/" + "/".join(parts)


def strip_request_parameters(target: str, method: str = "") -> str:
    text = str(target or "").strip()
    if method and text.upper().startswith(method.upper() + " "):
        text = text.split(" ", 1)[1].strip()
    if " BODY " in text:
        text = text.split(" BODY ", 1)[0].strip()
    parse_target = "http://local_gateway_placeholder" + text if text.startswith("/") else text
    parsed = urlparse(parse_target)
    path = parsed.path if parsed.scheme or parsed.netloc else text.split("?", 1)[0]
    return unquote(path or "/")


def api_template_from_record(record: dict[str, Any]) -> str:
    method = str(record.get("method") or "GET").upper()
    explicit_pattern = str(record.get("path_pattern") or "").strip()
    if explicit_pattern:
        return normalize_path(strip_request_parameters(explicit_pattern, method))
    return normalize_path(strip_request_parameters(extract_target_from_record(record), method))


def api_summary_from_template(method: str, path_template: str) -> str:
    segments = [segment for segment in str(path_template or "").strip("/").split("/") if segment]
    resource = "/".join(segments[-3:]) if segments else "/"
    method_verbs = {
        "GET": "Read or access",
        "POST": "Submit or create",
        "PUT": "Update",
        "PATCH": "Partially update",
        "DELETE": "Delete",
        "HEAD": "Check metadata for",
        "OPTIONS": "Inspect options for",
    }
    return f"{method_verbs.get(method.upper(), 'Call')} {resource} API"


def is_user_initiated_api(method: str, path_template: str) -> bool:
    method = method.upper()
    segments = {segment.lower().strip("{}") for segment in str(path_template or "").strip("/").split("/") if segment}
    if segments & PASSIVE_API_KEYWORDS:
        return False
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    if method == "GET" and segments & ACTIVE_API_KEYWORDS:
        return True
    return False


def openapi_path_template(path: str) -> str:
    seen: Counter[str] = Counter()
    parts: list[str] = []
    for raw_part in str(path or "").split("/"):
        if not raw_part:
            continue
        if raw_part.startswith("{") and raw_part.endswith("}"):
            name = re.sub(r"[^A-Za-z0-9_]", "_", raw_part[1:-1]).strip("_") or "path_param"
            seen[name] += 1
            if seen[name] > 1:
                name = f"{name}_{seen[name]}"
            parts.append("{" + name + "}")
        else:
            parts.append(raw_part)
    return "/" + "/".join(parts)


def value_type(value: str) -> str:
    text = str(value or "").strip()
    lowered = text.lower()
    if text == "":
        return "EMPTY"
    if INT_RE.match(text):
        return "INT"
    if FLOAT_RE.match(text):
        return "FLOAT"
    if UUID_RE.match(text):
        return "UUID"
    if lowered in ("true", "false"):
        return "BOOL"
    if text.startswith("{") and text.endswith("}"):
        return "JSON"
    if text.startswith("[") and text.endswith("]"):
        return "ARRAY"
    if text.startswith(("http://", "https://")):
        return "URL"
    if "@" in text and "." in text:
        return "EMAIL"
    if "," in text:
        return "LIST"
    if len(text) >= 24 and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", text):
        return "TOKEN"
    return "STR"


def sanitize_example(name: str, value: str) -> str:
    if SENSITIVE_NAME_RE.search(str(name or "")):
        return "<redacted>"
    text = str(value)
    if len(text) > 256:
        return text[:253] + "..."
    return text


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as fin:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                yield payload


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
    yield from iter_jsonl(path)


def discover_input_paths(input_path: Path, site_id: str) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if not input_path.exists():
        raise FileNotFoundError(f"input path not found: {input_path}")
    pattern = f"session_site_{site_id}.jsonl" if site_id else "session_site_*.jsonl"
    files = sorted(input_path.glob(pattern))
    if files:
        return files
    files = sorted(input_path.glob(f"**/{pattern}"))
    if files:
        return files
    raise FileNotFoundError(f"no session files found in {input_path}")


def records_from_session(session_obj: dict[str, Any]):
    site_id = str(session_obj.get("site_id") or "unknown_site")
    sequence = session_obj.get("sequence", {})
    if not isinstance(sequence, dict):
        return
    for _, event in sorted(sequence.items(), key=lambda item: int(item[0])):
        if not isinstance(event, dict):
            continue
        record = dict(event)
        record.setdefault("site_id", site_id)
        record.setdefault("session_id", session_obj.get("session_id", ""))
        record.setdefault("source_ip", session_obj.get("source_ip", ""))
        record.setdefault("api_request", event.get("full_api_request", ""))
        yield record


def iter_records(input_path: Path, site_id_filter: str = ""):
    for path in discover_input_paths(input_path, site_id_filter):
        if path.name.startswith("session_site_"):
            for session_obj in iter_json_blocks(path):
                yield from records_from_session(session_obj)
        else:
            yield from iter_jsonl(path)


def get_path_method(record: dict[str, Any]) -> tuple[str, str]:
    method = str(record.get("method") or "GET").upper()
    return api_template_from_record(record), method


def normalize_pairs(record: dict[str, Any], key: str) -> list[tuple[str, str]]:
    pairs = record.get(key, [])
    output: list[tuple[str, str]] = []
    if not isinstance(pairs, list):
        return output
    for item in pairs:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            output.append((str(item[0]), str(item[1])))
    return output


def flatten_json_params(payload: Any, prefix: str = "") -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            next_key = f"{prefix}.{key}" if prefix else str(key)
            pairs.extend(flatten_json_params(value, next_key))
    elif isinstance(payload, list):
        if not payload:
            pairs.append((prefix, "[]"))
        for value in payload:
            next_key = f"{prefix}[]" if prefix else "[]"
            pairs.extend(flatten_json_params(value, next_key))
    elif prefix:
        pairs.append((prefix, "" if payload is None else str(payload)))
    return pairs


def extract_target_from_record(record: dict[str, Any]) -> str:
    method = str(record.get("method") or "GET").upper()
    for key in ("raw_url", "full_url_path", "api_request", "full_api_request", "path"):
        value = str(record.get(key) or "").strip()
        if not value:
            continue
        if value.upper().startswith(method + " "):
            value = value.split(" ", 1)[1].strip()
        if " BODY " in value:
            value = value.split(" BODY ", 1)[0].strip()
        return value
    return ""


def parsed_url_from_record(record: dict[str, Any]):
    target = extract_target_from_record(record)
    if not target:
        return urlparse("")
    parse_target = "http://local_gateway_placeholder" + target if target.startswith("/") else target
    return urlparse(parse_target)


def raw_path_from_record(record: dict[str, Any]) -> str:
    explicit = str(record.get("path") or "").strip()
    if explicit:
        return strip_request_parameters(explicit, str(record.get("method") or "GET").upper())
    return unquote(parsed_url_from_record(record).path or "")


def query_pairs_from_record(record: dict[str, Any]) -> list[tuple[str, str]]:
    pairs = normalize_pairs(record, "param_pairs")
    if pairs:
        return pairs
    query = str(record.get("query") or "")
    if not query:
        query = unquote(parsed_url_from_record(record).query or "")
    return [(str(key), str(value)) for key, value in parse_qsl(query, keep_blank_values=True)]


def body_text_from_record(record: dict[str, Any]) -> str:
    for key in ("requestBody", "request_body", "body", "request_body_text"):
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    full_api_request = str(record.get("full_api_request") or "")
    if " BODY " in full_api_request:
        return full_api_request.split(" BODY ", 1)[1].strip()
    return ""


def body_pairs_from_record(record: dict[str, Any]) -> list[tuple[str, str]]:
    pairs = normalize_pairs(record, "body_param_pairs")
    if pairs:
        return pairs
    body = body_text_from_record(record)
    if not body or body in ("{}", "[]"):
        return []
    if body.startswith("{") or body.startswith("["):
        try:
            return flatten_json_params(json.loads(body))
        except json.JSONDecodeError:
            return []
    if "=" in body:
        return [(str(key), str(value)) for key, value in parse_qsl(body, keep_blank_values=True)]
    return []


def path_pairs_from_record(record: dict[str, Any]) -> list[tuple[str, str]]:
    pattern = api_template_from_record(record)
    path = raw_path_from_record(record)
    pattern_parts = [part for part in pattern.split("/") if part]
    path_parts = [unquote(part) for part in path.split("/") if part]
    if len(pattern_parts) != len(path_parts):
        return []

    seen: Counter[str] = Counter()
    output: list[tuple[str, str]] = []
    for pattern_part, path_part in zip(pattern_parts, path_parts):
        if pattern_part.startswith("{") and pattern_part.endswith("}"):
            name = re.sub(r"[^A-Za-z0-9_]", "_", pattern_part[1:-1]).strip("_") or "path_param"
            seen[name] += 1
            if seen[name] > 1:
                name = f"{name}_{seen[name]}"
            output.append((name, path_part))
    return output


def headers_from_record(record: dict[str, Any]) -> dict[str, str]:
    for key in ("headers", "request_headers", "header_params", "requestHeaders"):
        value = record.get(key)
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        if isinstance(value, list):
            return {str(item[0]): str(item[1]) for item in value if isinstance(item, (list, tuple)) and len(item) >= 2}
        if isinstance(value, str) and value.strip():
            try:
                payload = json.loads(value)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                return {str(k): str(v) for k, v in payload.items()}
    return {}


def type_pattern_from_pairs(pairs: list[tuple[str, str]]) -> str:
    return "&".join(f"{name}=<{value_type(value)}>" for name, value in pairs)


def name_set_from_pairs(pairs: list[tuple[str, str]]) -> str:
    return ",".join(sorted(set(name for name, _ in pairs if name)))


def parse_type_pattern(type_pattern: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in str(type_pattern or "").split("&"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip().strip("<>").upper()
        if key:
            result[key] = value or "UNKNOWN"
    return result


def add_example(examples: list[str], value: str, max_examples: int) -> None:
    if value in examples or len(examples) >= max_examples:
        return
    examples.append(value)


def new_param_profile() -> dict[str, Any]:
    return {
        "count": 0,
        "present_count": 0,
        "empty_count": 0,
        "type_counter": Counter(),
        "value_counter": Counter(),
        "examples": [],
    }


def new_method_profile() -> dict[str, Any]:
    return {
        "request_count": 0,
        "path_param_request_count": 0,
        "query_request_count": 0,
        "header_request_count": 0,
        "body_request_count": 0,
        "path_param_set_counter": Counter(),
        "query_param_set_counter": Counter(),
        "header_param_set_counter": Counter(),
        "query_type_pattern_counter": Counter(),
        "header_type_pattern_counter": Counter(),
        "query_repeated_param_counter": Counter(),
        "body_param_set_counter": Counter(),
        "body_type_pattern_counter": Counter(),
        "body_repeated_param_counter": Counter(),
        "path_params": defaultdict(new_param_profile),
        "query_params": defaultdict(new_param_profile),
        "header_params": defaultdict(new_param_profile),
        "body_params": defaultdict(new_param_profile),
        "samples": [],
    }


def param_name_set(record: dict[str, Any], names_key: str, set_key: str) -> str:
    value = str(record.get(set_key) or "")
    if value:
        return value
    names = record.get(names_key, [])
    if isinstance(names, list):
        return ",".join(sorted(set(str(name) for name in names if str(name))))
    return ""


def body_pairs_to_dict(pairs: list[tuple[str, str]]) -> dict[str, str]:
    return {str(key): sanitize_example(str(key), str(value)) for key, value in pairs}


def parse_status_code(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return 0


def build_log_sample(record: dict[str, Any]) -> dict[str, Any]:
    method = str(record.get("method") or "GET").upper()
    url = extract_target_from_record(record)
    if url.startswith(method + " "):
        url = url.split(" ", 1)[1]
    body_pairs = body_pairs_from_record(record)
    headers = headers_from_record(record)
    sample: dict[str, Any] = {
        "request": {
            "url": url,
            "method": method,
            "query": str(record.get("query") or ""),
        },
        "response": {
            "status": parse_status_code(record.get("status_code") or record.get("ser_status_code")),
            "content_type": str(record.get("res_content_type") or ""),
            "content_length": str(record.get("res_content_len") or ""),
        },
    }
    if body_pairs:
        sample["request"]["body"] = body_pairs_to_dict(body_pairs)
    if headers:
        sample["request"]["headers"] = {key: sanitize_example(key, value) for key, value in headers.items()}
    return sample


def update_param_profiles(
    params: dict[str, Any],
    pairs: list[tuple[str, str]],
    types_by_name: dict[str, str],
    max_examples: int,
) -> None:
    seen_names: set[str] = set()
    for name, value in pairs:
        param = params[name]
        param["count"] += 1
        if name not in seen_names:
            param["present_count"] += 1
            seen_names.add(name)
        if value == "":
            param["empty_count"] += 1
        value_type = types_by_name.get(name, "UNKNOWN")
        param["type_counter"][value_type] += 1
        safe_value = sanitize_example(name, value)
        param["value_counter"][safe_value] += 1
        add_example(param["examples"], safe_value, max_examples)


def update_method_profile(profile: dict[str, Any], record: dict[str, Any], args: argparse.Namespace) -> None:
    profile["request_count"] += 1

    path_pairs = path_pairs_from_record(record)
    if path_pairs:
        profile["path_param_request_count"] += 1
    path_set = name_set_from_pairs(path_pairs)
    profile["path_param_set_counter"][path_set or "<NO_PATH_PARAMS>"] += 1
    update_param_profiles(profile["path_params"], path_pairs, {name: value_type(value) for name, value in path_pairs}, args.max_examples)

    query_pairs = query_pairs_from_record(record)
    if query_pairs:
        profile["query_request_count"] += 1
    query_set = param_name_set(record, "param_names", "param_name_set") or name_set_from_pairs(query_pairs)
    profile["query_param_set_counter"][query_set or "<NO_QUERY>"] += 1
    query_type_pattern = str(record.get("param_type_pattern") or "") or type_pattern_from_pairs(query_pairs)
    profile["query_type_pattern_counter"][query_type_pattern or "<NO_QUERY>"] += 1
    for name in record.get("repeated_params", []) if isinstance(record.get("repeated_params", []), list) else []:
        profile["query_repeated_param_counter"][str(name)] += 1
    update_param_profiles(profile["query_params"], query_pairs, parse_type_pattern(query_type_pattern), args.max_examples)

    headers = headers_from_record(record)
    header_pairs = sorted(headers.items())
    if header_pairs:
        profile["header_request_count"] += 1
    header_set = name_set_from_pairs(header_pairs)
    header_type_pattern = type_pattern_from_pairs(header_pairs)
    profile["header_param_set_counter"][header_set or "<NO_HEADERS>"] += 1
    profile["header_type_pattern_counter"][header_type_pattern or "<NO_HEADERS>"] += 1
    update_param_profiles(profile["header_params"], header_pairs, parse_type_pattern(header_type_pattern), args.max_examples)

    body_pairs = body_pairs_from_record(record)
    if body_pairs:
        profile["body_request_count"] += 1
    body_set = param_name_set(record, "body_param_names", "body_param_name_set") or name_set_from_pairs(body_pairs)
    profile["body_param_set_counter"][body_set or "<NO_BODY>"] += 1
    body_type_pattern = str(record.get("body_param_type_pattern") or "") or type_pattern_from_pairs(body_pairs)
    profile["body_type_pattern_counter"][body_type_pattern or "<NO_BODY>"] += 1
    for name in record.get("body_repeated_params", []) if isinstance(record.get("body_repeated_params", []), list) else []:
        profile["body_repeated_param_counter"][str(name)] += 1
    update_param_profiles(profile["body_params"], body_pairs, parse_type_pattern(body_type_pattern), args.max_examples)

    if len(profile["samples"]) < args.sample_per_method:
        profile["samples"].append(build_log_sample(record))


def compact_param_sets(counter: Counter, total: int, limit: int) -> list[dict[str, Any]]:
    output = []
    for value, count in counter.most_common(limit):
        if value in ("<NO_PATH_PARAMS>", "<NO_QUERY>", "<NO_HEADERS>", "<NO_BODY>", ""):
            continue
        params = [item for item in str(value).split(",") if item]
        output.append({"params": params, "count": count, "ratio": round(count / total, 6) if total else 0})
    return output


def compact_type_patterns(counter: Counter, total: int, limit: int) -> list[dict[str, Any]]:
    output = []
    for value, count in counter.most_common(limit):
        if value in ("<NO_PATH_PARAMS>", "<NO_QUERY>", "<NO_HEADERS>", "<NO_BODY>", ""):
            continue
        output.append({"pattern": value, "count": count, "ratio": round(count / total, 6) if total else 0})
    return output


def finalize_params(params: dict[str, Any], request_count: int, max_examples: int) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for name, param in sorted(params.items()):
        count = int(param["count"])
        present_count = int(param.get("present_count", count))
        payload[name] = {
            "required_ratio": round(present_count / request_count, 6) if request_count else 0,
            "count": count,
            "present_count": present_count,
            "empty_ratio": round(int(param["empty_count"]) / count, 6) if count else 0,
            "types": [item[0] for item in param["type_counter"].most_common()],
            "examples": list(param["examples"])[:max_examples],
        }
    return payload


def finalize_method_profile(method: str, profile: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    total = int(profile["request_count"])
    path_param_count = int(profile["path_param_request_count"])
    query_count = int(profile["query_request_count"])
    header_count = int(profile["header_request_count"])
    body_count = int(profile["body_request_count"])
    return {
        "method": method,
        "request_count": total,
        "path": {
            "request_count": path_param_count,
            "request_ratio": round(path_param_count / total, 6) if total else 0,
            "param_sets": compact_param_sets(profile["path_param_set_counter"], total, args.top_param_sets),
            "params": finalize_params(profile["path_params"], total, args.max_examples),
        },
        "query": {
            "request_count": query_count,
            "request_ratio": round(query_count / total, 6) if total else 0,
            "param_sets": compact_param_sets(profile["query_param_set_counter"], total, args.top_param_sets),
            "type_patterns": compact_type_patterns(profile["query_type_pattern_counter"], total, args.top_param_sets),
            "params": finalize_params(profile["query_params"], total, args.max_examples),
        },
        "header": {
            "request_count": header_count,
            "request_ratio": round(header_count / total, 6) if total else 0,
            "param_sets": compact_param_sets(profile["header_param_set_counter"], total, args.top_param_sets),
            "type_patterns": compact_type_patterns(profile["header_type_pattern_counter"], total, args.top_param_sets),
            "params": finalize_params(profile["header_params"], total, args.max_examples),
        },
        "body": {
            "request_count": body_count,
            "request_ratio": round(body_count / total, 6) if total else 0,
            "param_sets": compact_param_sets(profile["body_param_set_counter"], total, args.top_param_sets),
            "type_patterns": compact_type_patterns(profile["body_type_pattern_counter"], total, args.top_param_sets),
            "params": finalize_params(profile["body_params"], total, args.max_examples),
        },
        "samples": profile.get("samples", []),
    }


def limit_samples_per_path(methods: dict[str, dict[str, Any]], max_samples: int) -> dict[str, dict[str, Any]]:
    if max_samples <= 0:
        return methods
    remaining = max_samples
    limited: dict[str, dict[str, Any]] = {}
    for method, method_item in methods.items():
        item = dict(method_item)
        samples = item.get("samples", [])
        if isinstance(samples, list):
            item["samples"] = samples[:remaining] if remaining > 0 else []
            remaining -= len(item["samples"])
        limited[method] = item
    return limited


def finalize_path_profile(path: str, method_profiles: dict[str, dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    methods = {
        method: finalize_method_profile(method, profile, args)
        for method, profile in sorted(method_profiles.items())
    }
    methods = limit_samples_per_path(methods, args.max_samples_per_path)
    return {
        "path": path,
        "openapi_path": openapi_path_template(path),
        "request_count": sum(item["request_count"] for item in methods.values()),
        "methods": methods,
    }


def load_api_config(args: argparse.Namespace) -> dict[str, str]:
    api_url = str(getattr(args, "llm_url", "") or LOCAL_LLM_URL).strip()
    model = str(getattr(args, "model", "") or MODEL_NAME).strip()
    api_key = str(getattr(args, "api_key", "") or "").strip()
    api_url = api_url.rstrip("/")
    if api_url and not api_url.lower().endswith("/chat/completions"):
        api_url = api_url + "/chat/completions"
    if not api_url or not model:
        raise ValueError("Local LLM requires --llm-url and --model.")
    return {"api_url": api_url, "model": model, "api_key": api_key}


def trim_params_for_prompt(params: object, max_params: int, max_examples: int) -> dict[str, Any]:
    if not isinstance(params, dict) or max_params <= 0:
        return {}
    items = sorted(
        params.items(),
        key=lambda item: (
            -float(item[1].get("required_ratio", 0)) if isinstance(item[1], dict) else 0,
            -int(item[1].get("count", 0)) if isinstance(item[1], dict) else 0,
            str(item[0]),
        ),
    )
    output: dict[str, Any] = {}
    for name, param in items[:max_params]:
        if not isinstance(param, dict):
            continue
        item = dict(param)
        examples = item.get("examples", [])
        if isinstance(examples, list):
            item["examples"] = examples[:max_examples] if max_examples > 0 else []
        output[str(name)] = item
    return output


def trim_method_for_prompt(method_item: dict[str, Any], max_params: int, max_examples: int, max_samples: int) -> dict[str, Any]:
    item = dict(method_item)
    for block_name in ("path", "query", "header", "body"):
        block = item.get(block_name)
        if not isinstance(block, dict):
            continue
        trimmed_block = dict(block)
        trimmed_block["params"] = trim_params_for_prompt(block.get("params", {}), max_params, max_examples)
        for list_name in ("param_sets", "type_patterns"):
            values = trimmed_block.get(list_name, [])
            if isinstance(values, list):
                trimmed_block[list_name] = values[:5]
        item[block_name] = trimmed_block
    samples = item.get("samples", [])
    if isinstance(samples, list):
        item["samples"] = samples[:max_samples] if max_samples > 0 else []
    return item


def trim_path_item_for_prompt(
    path_item: dict[str, Any],
    max_params: int,
    max_examples: int,
    max_samples_per_method: int,
) -> dict[str, Any]:
    trimmed = {
        "path": path_item.get("path", ""),
        "openapi_path": path_item.get("openapi_path", path_item.get("path", "")),
        "request_count": path_item.get("request_count", 0),
        "methods": {},
        "prompt_trimmed": True,
        "prompt_trim_policy": {
            "max_params_per_block": max_params,
            "max_examples_per_param": max_examples,
            "max_samples_per_method": max_samples_per_method,
        },
    }
    methods = path_item.get("methods", {})
    if isinstance(methods, dict):
        trimmed["methods"] = {
            method: trim_method_for_prompt(method_item, max_params, max_examples, max_samples_per_method)
            for method, method_item in methods.items()
            if isinstance(method_item, dict)
        }
    return trimmed


def render_openapi_prompt(site_id: str, path_item: dict[str, Any]) -> str:
    payload = {
        "site_id": site_id,
        "path_profile": path_item,
    }
    return (
        "Role: 你是一个资深的 Web 安全与架构专家。\n"
        f"Task: 请分析以下来自 WAF 网关的真实 API 流量日志样本和参数画像，逆向推导并合并生成该接口路径的 OpenAPI {OPENAPI_VERSION} 规范片段。\n\n"
        "要求:\n"
        "1. 使用 path_profile.openapi_path 作为 paths 的 key；path_profile.path 只作为原始聚类模板参考。\n"
        "2. 分析 path/query/header/body 四类参数画像、真实 URL 样本、Request Body、Response status/content_type/content_length。\n"
        "3. path 参数必须放在 operation.parameters 且 in=path，并且 required=true。\n"
        "4. Query 参数必须放在 operation.parameters 且 in=query；Header 参数必须放在 operation.parameters 且 in=header。\n"
        "5. Request Body 不能放在 parameters 中，必须使用 operation.requestBody.content.<media-type>.schema；默认使用 application/json，明确为表单时使用 application/x-www-form-urlencoded。\n"
        "6. OpenAPI 3.x 不允许 parameters[].in=body；不要输出 Swagger/OpenAPI 2.0 风格字段。\n"
        "7. 结合参数画像推导 schema type、format、enum、required；样本不足时不要编造约束或响应 body 字段。\n"
        "8. 只输出标准 JSON，顶层必须包含 openapi、info、paths；openapi 字段必须等于 "
        f"\"{OPENAPI_VERSION}\"。\n"
        "9. 只能输出 JSON 字符串，不要 markdown，不要 ```json。\n\n"
        f"WAF 流量日志样本与路径参数画像:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )


def estimate_llm_request_body_bytes(prompt: str) -> int:
    request_payload = {
        "model": MODEL_NAME.strip() or "model",
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        "temperature": 0,
    }
    return len(json.dumps(request_payload, ensure_ascii=False).encode("utf-8"))


def build_openapi_prompt(site_id: str, path_item: dict[str, Any], args: argparse.Namespace) -> str:
    prompt_char_limit = int(getattr(args, "max_openapi_prompt_chars", 0) or 0)
    request_byte_limit = int(getattr(args, "max_llm_request_bytes", 0) or 0)
    prompt = render_openapi_prompt(site_id, path_item)
    prompt_ok = prompt_char_limit <= 0 or len(prompt) <= prompt_char_limit
    body_ok = request_byte_limit <= 0 or estimate_llm_request_body_bytes(prompt) <= request_byte_limit
    if prompt_ok and body_ok:
        return prompt

    path = str(path_item.get("path", ""))
    trim_steps = [
        (200, 3, 10),
        (100, 2, 5),
        (50, 1, 3),
        (25, 1, 1),
        (10, 0, 0),
        (5, 0, 0),
        (0, 0, 0),
    ]
    for max_params, max_examples, max_samples in trim_steps:
        trimmed = trim_path_item_for_prompt(path_item, max_params, max_examples, max_samples)
        prompt = render_openapi_prompt(site_id, trimmed)
        body_bytes = estimate_llm_request_body_bytes(prompt)
        prompt_ok = prompt_char_limit <= 0 or len(prompt) <= prompt_char_limit
        body_ok = request_byte_limit <= 0 or body_bytes <= request_byte_limit
        if prompt_ok and body_ok:
            print(
                f"openapi_prompt_trimmed site={site_id} path={path} "
                f"chars={len(prompt)} char_limit={prompt_char_limit} "
                f"body_bytes={body_bytes} byte_limit={request_byte_limit} "
                f"max_params={max_params} max_examples={max_examples} max_samples={max_samples}"
            )
            return prompt

    print(
        f"openapi_prompt_minimal_still_large site={site_id} path={path} "
        f"chars={len(prompt)} char_limit={prompt_char_limit} "
        f"body_bytes={estimate_llm_request_body_bytes(prompt)} byte_limit={request_byte_limit}"
    )
    return prompt


def parse_llm_json_content(content: str) -> dict[str, Any]:
    text = str(content or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise
        payload = json.loads(text[start:end + 1])
    if not isinstance(payload, dict):
        raise ValueError("LLM response JSON must be an object.")
    return payload


def content_from_chat_completion_payload(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", [])
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict) and message.get("content") is not None:
                return str(message.get("content") or "")
            delta = first.get("delta")
            if isinstance(delta, dict) and delta.get("content") is not None:
                return str(delta.get("content") or "")
    return str(payload.get("message", {}).get("content", payload.get("response", "")))


def read_chat_completion_stream(response) -> str:
    chunks: list[str] = []
    for raw_line in response:
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        if line.startswith("data:"):
            line = line[5:].strip()
        if not line or line == "[DONE]":
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        chunks.append(content_from_chat_completion_payload(payload))
    return "".join(chunks)


def call_llm(prompt: str, config: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    request_payload = {
        "model": config["model"],
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        "temperature": 0,
    }
    body = json.dumps(request_payload, ensure_ascii=False).encode("utf-8")
    max_request_bytes = int(getattr(args, "max_llm_request_bytes", 0) or 0)
    if max_request_bytes > 0 and len(body) > max_request_bytes:
        raise ValueError(
            f"LLM request body is still too large after prompt trimming: body_bytes={len(body)} "
            f"prompt_chars={len(prompt)} byte_limit={max_request_bytes}. "
            "Lower --max-llm-request-bytes/--max-openapi-prompt-chars or reduce --max-examples/--max-samples-per-path."
        )
    last_error: Exception | None = None
    for attempt in range(1, args.max_retries + 1):
        headers = {"Content-Type": "application/json", "Connection": "close"}
        if config.get("api_key"):
            headers["Authorization"] = f"Bearer {config['api_key']}"
        http_request = request.Request(
            url=config["api_url"],
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=args.request_timeout) as response:
                content_type = str(response.headers.get("Content-Type", ""))
                if "text/event-stream" in content_type:
                    content = read_chat_completion_stream(response)
                else:
                    payload = json.loads(response.read().decode("utf-8"))
                    content = content_from_chat_completion_payload(payload)
            return parse_llm_json_content(content)
        except error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            last_error = RuntimeError(f"HTTP {exc.code} {exc.reason}: {response_text}")
            print(f"llm_http_error attempt={attempt}/{args.max_retries} status={exc.code} body={response_text[:2000]}")
            if attempt >= args.max_retries:
                break
            time.sleep(args.retry_sleep * attempt)
        except (error.URLError, TimeoutError, ConnectionError, OSError, json.JSONDecodeError, KeyError) as exc:
            last_error = exc
            if attempt >= args.max_retries:
                break
            time.sleep(args.retry_sleep * attempt)
    raise RuntimeError(f"LLM OpenAPI generation failed after {args.max_retries} retries: {last_error}")


def merge_openapi_doc(base_doc: dict[str, Any], fragment: dict[str, Any]) -> None:
    paths = fragment.get("paths", {})
    if isinstance(paths, dict):
        for path, item in paths.items():
            if isinstance(item, dict):
                base_doc.setdefault("paths", {}).setdefault(path, {}).update(normalize_path_item_openapi32(item, str(path)))
    components = fragment.get("components", {})
    if isinstance(components, dict):
        for key, value in components.items():
            if isinstance(value, dict):
                base_doc.setdefault("components", {}).setdefault(key, {}).update(value)


def clean_schema(schema: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(schema)
    if cleaned.get("enum") == ["[]"]:
        cleaned.pop("enum", None)
    if cleaned.get("format") is None:
        cleaned.pop("format", None)
    return cleaned


def body_parameter_to_request_body(parameter: dict[str, Any]) -> dict[str, Any]:
    name = str(parameter.get("name") or "body")
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {"type": "object"}
    schema = clean_schema(schema)
    if schema.get("type") != "object":
        schema = {
            "type": "object",
            "properties": {
                name: schema,
            },
            "required": [name] if parameter.get("required") else [],
        }
    return {
        "required": bool(parameter.get("required", False)),
        "content": {
            "application/json": {
                "schema": schema,
            }
        },
    }


def merge_request_body(existing: dict[str, Any] | None, incoming: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(existing, dict):
        return incoming
    merged = dict(existing)
    merged["required"] = bool(existing.get("required") or incoming.get("required"))
    merged.setdefault("content", {}).update(incoming.get("content", {}))
    return merged


def normalize_operation_openapi32(operation: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(operation)
    parameters = normalized.get("parameters", [])
    kept_parameters = []
    if isinstance(parameters, list):
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("in") or "").lower()
            if location == "body":
                request_body = body_parameter_to_request_body(parameter)
                normalized["requestBody"] = merge_request_body(normalized.get("requestBody"), request_body)
                continue
            if isinstance(parameter.get("schema"), dict):
                parameter = dict(parameter)
                parameter["schema"] = clean_schema(parameter["schema"])
            kept_parameters.append(parameter)
    normalized["parameters"] = kept_parameters
    return normalized


def operation_has_template_fields(operation: dict[str, Any]) -> bool:
    return "api_summary" in operation and "is_user_initiated" in operation


def render_operation_template_prompt(path: str, method: str) -> str:
    method_upper = method.upper()
    path_template = openapi_path_template(normalize_path(strip_request_parameters(path, method_upper)))
    payload = {
        "method": method_upper,
        "api_template": path_template,
    }
    return (
        "Role: 你是一个 Web API 行为分析专家。\n"
        "Task: 只根据 API 模板判断接口含义，不读取 query/body/header 参数，也不要推断具体参数值。\n"
        "请返回 JSON，必须且只能包含两个字段:\n"
        "1. api_summary: 用一句简短中文总结这个 API 的用途。\n"
        "2. is_user_initiated: boolean，判断它是否更像用户主动发起的业务行为；"
        "静态资源、心跳、轮询、批量资源加载、后台同步通常为 false。\n"
        "只能输出 JSON，不要 markdown。\n\n"
        f"API 模板:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )


def parse_operation_template_fields(payload: dict[str, Any], path: str, method: str) -> dict[str, Any]:
    summary = str(payload.get("api_summary") or "").strip()
    if not summary:
        summary = api_summary_from_template(method.upper(), openapi_path_template(normalize_path(strip_request_parameters(path, method))))
    initiated = payload.get("is_user_initiated")
    if not isinstance(initiated, bool):
        initiated = is_user_initiated_api(method.upper(), openapi_path_template(normalize_path(strip_request_parameters(path, method))))
    return {"api_summary": summary, "is_user_initiated": initiated}


def llm_operation_template_fields(path: str, method: str, config: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    prompt = render_operation_template_prompt(path, method)
    return parse_operation_template_fields(call_llm(prompt, config, args), path, method)


def enrich_operation_template_fields(operation: dict[str, Any], path: str, method: str) -> dict[str, Any]:
    enriched = dict(operation)
    if operation_has_template_fields(enriched):
        return enriched
    path_template = openapi_path_template(normalize_path(strip_request_parameters(path, method)))
    method_upper = method.upper()
    enriched["api_summary"] = api_summary_from_template(method_upper, path_template)
    enriched["is_user_initiated"] = is_user_initiated_api(method_upper, path_template)
    return enriched


def normalize_path_item_openapi32(path_item: dict[str, Any], path: str = "") -> dict[str, Any]:
    normalized = dict(path_item)
    for method in HTTP_METHODS:
        operation = normalized.get(method)
        if isinstance(operation, dict):
            normalized[method] = normalize_operation_openapi32(operation)
    return normalized


def enrich_openapi_doc_template_fields(doc: dict[str, Any]) -> None:
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        return
    for path, path_item in paths.items():
        if isinstance(path_item, dict):
            paths[path] = normalize_path_item_openapi32(path_item, str(path))


def enrich_openapi_doc_template_fields_llm(
    doc: dict[str, Any],
    config: dict[str, str],
    args: argparse.Namespace,
    output_path: Path,
) -> int:
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        return 0
    modified = 0
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            if operation_has_template_fields(operation):
                print(f"api_template_skip_modified method={method} path={path}")
                continue
            fields = llm_operation_template_fields(str(path), method, config, args)
            operation["api_summary"] = fields["api_summary"]
            operation["is_user_initiated"] = fields["is_user_initiated"]
            modified += 1
            output_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"api_template_enriched method={method} path={path} output={output_path}")
    return modified


def openapi_path_fingerprint(path: str) -> str:
    parts: list[str] = []
    for part in str(path or "").strip().split("/"):
        if not part:
            continue
        if part.startswith("{") and part.endswith("}"):
            parts.append("{}")
        else:
            parts.append(part.lower())
    return "/" + "/".join(parts)


def new_openapi_doc(site_id: str) -> dict[str, Any]:
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": f"Inferred OpenAPI specification for site {site_id}",
            "version": "1.0.0",
            "description": f"Generated from path-clustered WAF gateway samples and parameter profiles by LLM. Target OpenAPI version: {OPENAPI_VERSION}.",
        },
        "paths": {},
        "components": {"schemas": {}},
    }


def load_existing_openapi_doc(output_path: Path, site_id: str) -> dict[str, Any]:
    if not output_path.exists():
        return new_openapi_doc(site_id)
    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        backup_path = output_path.with_suffix(output_path.suffix + ".invalid")
        output_path.replace(backup_path)
        print(f"openapi_existing_invalid moved_to={backup_path}")
        return new_openapi_doc(site_id)
    if not isinstance(payload, dict):
        return new_openapi_doc(site_id)
    payload.setdefault("openapi", OPENAPI_VERSION)
    payload.setdefault("info", new_openapi_doc(site_id)["info"])
    if not isinstance(payload.get("paths"), dict):
        payload["paths"] = {}
    if not isinstance(payload.get("components"), dict):
        payload["components"] = {"schemas": {}}
    return payload


def generate_site_openapi(site_id: str, paths: list[dict[str, Any]], args: argparse.Namespace, output_dir: Path) -> Path:
    config = load_api_config(args)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"site_{site_id}_openapi.json"
    doc = load_existing_openapi_doc(output_path, site_id)
    enrich_openapi_doc_template_fields_llm(doc, config, args, output_path)
    existing_paths = set(doc.get("paths", {}).keys()) if isinstance(doc.get("paths"), dict) else set()
    existing_path_fingerprints = {openapi_path_fingerprint(path) for path in existing_paths}
    skipped = 0
    generated = 0
    for path_item in paths:
        if args.max_openapi_paths > 0 and generated >= args.max_openapi_paths:
            break
        openapi_path = str(path_item.get("openapi_path") or path_item.get("path") or "")
        openapi_fingerprint = openapi_path_fingerprint(openapi_path)
        if args.skip_existing_openapi_paths and (
            openapi_path in existing_paths or openapi_fingerprint in existing_path_fingerprints
        ):
            skipped += 1
            print(f"openapi_skip_existing site={site_id} path={openapi_path} fingerprint={openapi_fingerprint}")
            continue
        fragment = call_llm(build_openapi_prompt(site_id, path_item, args), config, args)
        merge_openapi_doc(doc, fragment)
        if isinstance(doc.get("paths"), dict):
            existing_paths = set(doc["paths"].keys())
            existing_path_fingerprints = {openapi_path_fingerprint(path) for path in existing_paths}
        enrich_openapi_doc_template_fields_llm(doc, config, args, output_path)
        output_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        generated += 1
        print(f"openapi_llm site={site_id} path={path_item.get('path', '')} methods={','.join(path_item.get('methods', {}).keys())}")
    enrich_openapi_doc_template_fields_llm(doc, config, args, output_path)
    output_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"openapi_done site={site_id} generated_paths={generated} skipped_existing={skipped} output={output_path}")
    return output_path


def flatten_apis(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for path_item in paths:
        path = path_item["path"]
        for method, method_item in path_item.get("methods", {}).items():
            output.append({"api": f"{method} {path}", **method_item})
    return output


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    site_profiles: dict[str, dict[str, dict[str, dict[str, Any]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(new_method_profile)))
    site_counts: Counter[str] = Counter()

    for record in iter_records(input_path, args.site_id):
        site_id = str(record.get("site_id") or "unknown_site")
        if args.site_id and site_id != args.site_id:
            continue
        path, method = get_path_method(record)
        if not path:
            continue
        update_method_profile(site_profiles[site_id][path][method], record, args)
        site_counts[site_id] += 1

    index = {
        "input": str(input_path),
        "output_dir": str(output_dir),
        "api_document_dir": str(Path(args.openapi_output_dir)),
        "generate_openapi_llm": bool(args.generate_openapi_llm),
        "max_profile_paths": args.top_paths,
        "max_samples_per_path": args.max_samples_per_path,
        "max_openapi_paths": args.max_openapi_paths,
        "skip_existing_openapi_paths": args.skip_existing_openapi_paths,
        "site_count": len(site_profiles),
        "sites": [],
    }

    for site_id, path_profiles in sorted(site_profiles.items()):
        finalized_paths = [
            finalize_path_profile(path, method_profiles, args)
            for path, method_profiles in path_profiles.items()
        ]
        finalized_paths.sort(key=lambda item: int(item["request_count"]), reverse=True)
        if args.top_paths > 0:
            finalized_paths = finalized_paths[: args.top_paths]

        payload = {
            "site_id": site_id,
            "total_records": site_counts[site_id],
            "path_count": len(finalized_paths),
            "paths": finalized_paths,
            "apis": flatten_apis(finalized_paths),
        }
        profile_path = output_dir / f"site_{site_id}_parameter_profile.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        openapi_file = ""
        if args.generate_openapi_llm:
            openapi_dir = Path(args.openapi_output_dir)
            openapi_file = str(generate_site_openapi(site_id, finalized_paths, args, openapi_dir))

        index["sites"].append(
            {
                "site_id": site_id,
                "total_records": site_counts[site_id],
                "path_count": len(finalized_paths),
                "profile_file": str(profile_path),
                "openapi_file": openapi_file,
            }
        )
        print(f"site={site_id} records={site_counts[site_id]} paths={len(finalized_paths)} profile={profile_path}")

    index_path = output_dir / "index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"index_file={index_path}")


if __name__ == "__main__":
    main()
