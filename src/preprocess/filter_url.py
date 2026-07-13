# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import base64
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from tqdm import tqdm


DEFAULT_INPUT = "D:\\browser\\Innovation\\sequence\\waf_10.67.10.72.access.json-20260705"
DEFAULT_OUTPUT_DIR = "D:\\browser\\Innovation\\sequence\\log_process\\log_sequence"

STATIC_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".txt", ".xml", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".map", ".bmp", ".webp", ".mp4",
)

FIELD_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*):(?P<value>.*?)(?=;[A-Za-z_][A-Za-z0-9_]*:|$)")
REQUEST_LINE_RE = re.compile(
    r"\b(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<target>\S+)\s+HTTP/(?P<version>[0-9.]+)",
    re.IGNORECASE,
)
LONG_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ISSUE_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]+-\d+$")
INT_RE = re.compile(r"^-?\d+$")
FLOAT_RE = re.compile(r"^-?\d+\.\d+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract API URL events from WAF logs.")
    parser.add_argument("--input", default=os.getenv("SEQ_INPUT", DEFAULT_INPUT))
    parser.add_argument("--output-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_OUTPUT_DIR))
    parser.add_argument("--output-name", default="url_dataset.jsonl")
    parser.add_argument("--keep-static", action="store_true")
    return parser.parse_args()


def load_outer_json(line: str) -> dict[str, Any]:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def extract_message(line: str, outer: dict[str, Any]) -> str:
    for key in ("raw_log", "msg", "message"):
        value = outer.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return line.strip()


def parse_semicolon_fields(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in FIELD_RE.finditer(message):
        key = match.group("key").strip()
        value = match.group("value").strip().strip(";")
        if key and key not in fields:
            fields[key] = value.replace("\\/", "/").replace('\\"', '"')
    return fields


def safe_base64_decode(value: str) -> str:
    if not value or not isinstance(value, str):
        return ""
    try:
        text = value.strip()
        missing_padding = len(text) % 4
        if missing_padding:
            text += "=" * (4 - missing_padding)
        return base64.b64decode(text, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def get_first_nonempty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def extract_request_line(http_text: str) -> tuple[str, str]:
    match = REQUEST_LINE_RE.search(http_text or "")
    if not match:
        return "", ""
    return match.group("method").upper(), match.group("target")


def split_http_body(http_text: str) -> str:
    if not http_text:
        return ""
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in http_text:
            return http_text.split(separator, 1)[1].strip()
    return ""


def classify_path(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith(STATIC_SUFFIXES):
        return "static_resource"
    if path in ("", "/", "/health", "/healthz") or path.startswith(("/health/", "/healthz/")):
        return "health_check"
    return "dynamic_request"


def normalize_path(path: str) -> str:
    parts = []
    for raw_part in path.split("/"):
        if raw_part == "":
            continue
        part = unquote(raw_part)
        lowered = part.lower()
        if UUID_RE.match(part):
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
        elif "." in part and LONG_HEX_RE.match(part.rsplit(".", 1)[0]):
            suffix = part.rsplit(".", 1)[1].lower()
            parts.append(f"{{file_hash}}.{suffix}")
        else:
            parts.append(lowered)
    return "/" + "/".join(parts)


def value_type(value: str) -> str:
    text = value.strip()
    if text == "":
        return "EMPTY"
    low = text.lower()
    if INT_RE.match(text):
        return "INT"
    if FLOAT_RE.match(text):
        return "FLOAT"
    if UUID_RE.match(text):
        return "UUID"
    if low in ("true", "false"):
        return "BOOL"
    if text.startswith("{") and text.endswith("}"):
        return "JSON"
    if text.startswith("[") and text.endswith("]"):
        return "ARRAY"
    if text.startswith(("http://", "https://")):
        return "URL"
    if "@" in text and "." in text:
        return "EMAIL"
    if len(text) >= 24 and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", text):
        return "TOKEN"
    if "," in text:
        return "LIST"
    return "STR"


def parse_query(query: str) -> dict[str, Any]:
    pairs = parse_qsl(query, keep_blank_values=True)
    names = [key for key, _ in pairs]
    counts = Counter(names)
    repeated = sorted(name for name, count in counts.items() if count > 1)
    name_set = sorted(set(names))

    typed_pairs = [[key, value_type(value)] for key, value in pairs]
    type_pattern = "&".join(f"{key}=<{kind}>" for key, kind in typed_pairs)

    return {
        "param_pairs": pairs,
        "param_names": names,
        "param_name_set": ",".join(name_set),
        "param_count": len(pairs),
        "repeated_params": repeated,
        "param_type_pattern": type_pattern,
    }


def flatten_json_params(payload: Any, prefix: str = "") -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            next_key = f"{prefix}.{key}" if prefix else str(key)
            pairs.extend(flatten_json_params(value, next_key))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            next_key = f"{prefix}[]" if prefix else f"[{index}]"
            pairs.extend(flatten_json_params(value, next_key))
    else:
        pairs.append((prefix, "" if payload is None else str(payload)))
    return [(key, value) for key, value in pairs if key]


def parse_body_params(body_text: str) -> dict[str, Any]:
    body = (body_text or "").strip()
    pairs: list[tuple[str, str]] = []
    if body:
        if body.startswith("{") or body.startswith("["):
            try:
                pairs = flatten_json_params(json.loads(body))
            except json.JSONDecodeError:
                pairs = []
        elif "=" in body:
            pairs = parse_qsl(body, keep_blank_values=True)

    names = [key for key, _ in pairs]
    counts = Counter(names)
    repeated = sorted(name for name, count in counts.items() if count > 1)
    name_set = sorted(set(names))
    typed_pairs = [[key, value_type(value)] for key, value in pairs]
    type_pattern = "&".join(f"{key}=<{kind}>" for key, kind in typed_pairs)

    return {
        "body_param_pairs": pairs,
        "body_param_names": names,
        "body_param_name_set": ",".join(name_set),
        "body_param_count": len(pairs),
        "body_repeated_params": repeated,
        "body_param_type_pattern": type_pattern,
    }


def parse_url_target(target: str) -> dict[str, Any] | None:
    if not target:
        return None
    clean = target.strip().replace("\\/", "/").strip('"')
    if clean.startswith("/"):
        parse_target = "http://local_gateway_placeholder" + clean
    else:
        parse_target = clean

    parsed = urlparse(parse_target)
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    if not path:
        return None

    query_info = parse_query(query)
    return {
        "raw_url": clean,
        "path": path,
        "path_pattern": normalize_path(path),
        "query": query,
        "url_type": classify_path(path),
        **query_info,
    }


def join_path_query(path: str, query: str) -> str:
    if query:
        return f"{path}?{query}"
    return path


def build_api_request_fields(method: str, url_info: dict[str, Any]) -> dict[str, str]:
    path = str(url_info.get("path") or "")
    path_pattern = str(url_info.get("path_pattern") or path)
    query = str(url_info.get("query") or "")
    param_type_pattern = str(url_info.get("param_type_pattern") or "")
    param_name_set = str(url_info.get("param_name_set") or "")

    return {
        # Complete original API request line for inspection and traceability.
        "api_request": f"{method} {join_path_query(path, query)}",
        # Stable API request token for sequence mining: path template + query value types.
        "api_request_pattern": f"{method} {join_path_query(path_pattern, param_type_pattern)}",
        # Stable API request token at param-name granularity.
        "api_request_param_names": f"{method} {join_path_query(path_pattern, param_name_set)}",
    }


def build_event(line: str) -> tuple[dict[str, Any] | None, str]:
    outer = load_outer_json(line)
    message = extract_message(line, outer)
    fields = parse_semicolon_fields(message)

    http_decoded = safe_base64_decode(get_first_nonempty(fields.get("http"), outer.get("http")))
    request_line_method, request_line_target = extract_request_line(http_decoded)
    body_info = parse_body_params(split_http_body(http_decoded))

    tag = get_first_nonempty(fields.get("tag"), outer.get("tag"))
    # Prefer the HTTP request line because WAF url fields are often path-only
    # while the decoded request line still contains the original query string.
    raw_url = get_first_nonempty(request_line_target, fields.get("url"), fields.get("uri"), outer.get("url"), outer.get("uri"))
    url_info = parse_url_target(raw_url)
    if not url_info:
        return None, "missing_url"

    method = get_first_nonempty(fields.get("method"), outer.get("method"), request_line_method, "GET").upper()
    raw_client_ip = get_first_nonempty(fields.get("raw_client_ip"), outer.get("raw_client_ip"))
    src_ip = get_first_nonempty(fields.get("src_ip"), outer.get("src_ip"), outer.get("source_ip"))
    api_request_fields = build_api_request_fields(method, url_info)

    event = {
        "timestamp": get_first_nonempty(fields.get("stat_time"), outer.get("stat_time"), outer.get("timestamp")),
        "site_id": get_first_nonempty(fields.get("site_id"), outer.get("site_id"), "unknown_site"),
        "tag": tag,
        "raw_client_ip": raw_client_ip,
        "src_ip": src_ip,
        "source_ip": raw_client_ip or src_ip or "unknown_ip",
        "request_id": get_first_nonempty(fields.get("request_id"), outer.get("request_id")),
        "method": method,
        **api_request_fields,
        "status_code": int(get_first_nonempty(fields.get("ser_status_code"), outer.get("ser_status_code"), "0") or 0),
        "waf_status_code": get_first_nonempty(fields.get("waf_status_code"), outer.get("waf_status_code")),
        "action": get_first_nonempty(fields.get("action"), outer.get("action")),
        "alertlevel": get_first_nonempty(fields.get("alertlevel"), outer.get("alertlevel")),
        "event_type": get_first_nonempty(fields.get("event_type"), outer.get("event_type")),
        "event_label": "abnormal" if tag == "waf_log_websec" else "normal",
        **url_info,
        **body_info,
    }
    return event, "ok"


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_path = output_dir / args.output_name
    bad_path = output_dir / "url_dataset_bad_records.jsonl"

    if not input_path.exists():
        raise FileNotFoundError(f"input file not found: {input_path}")
    output_dir.mkdir(parents=True, exist_ok=True)

    stats = Counter()
    with input_path.open("r", encoding="utf-8", errors="ignore") as fin, \
            output_path.open("w", encoding="utf-8", newline="\n") as fout, \
            bad_path.open("w", encoding="utf-8", newline="\n") as fbad:
        for line in tqdm(fin, desc="Extracting API events", unit="line"):
            line = line.strip()
            if not line:
                continue
            event, reason = build_event(line)
            stats[reason] += 1
            if not event:
                fbad.write(json.dumps({"reason": reason, "raw": line[:2000]}, ensure_ascii=False) + "\n")
                continue
            if event["url_type"] != "dynamic_request" and not args.keep_static:
                stats[event["url_type"]] += 1
                continue
            fout.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            if event["query"]:
                stats["with_query"] += 1
            if event.get("body_param_count", 0):
                stats["with_body_params"] += 1

    print("Final report")
    for key, value in sorted(stats.items()):
        print(f"{key}={value}")
    print(f"output_file={output_path}")
    print(f"bad_records_file={bad_path}")


if __name__ == "__main__":
    main()
