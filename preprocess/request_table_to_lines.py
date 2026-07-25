#!/usr/bin/env python3
"""Convert request tables into one-line request sequences.

Example output:
  "GET /confluence/rest/inlinecomments/1.0/comments?containerId=4426485&_=178304580"
  "POST /synchrony/v1/bayeux-sync1 BODY message=[{\"channel\":\"/sync1\"}]"
"""

from __future__ import annotations

import argparse
import ast
import csv
import glob
import json
import re
from pathlib import Path
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit


DEFAULT_METHOD_COLUMNS = ("method", "http_method", "Method", "METHOD")
DEFAULT_URL_COLUMNS = ("url", "URL", "uri", "URI", "path", "Path")
DEFAULT_BODY_COLUMNS = ("data", "body", "payload", "request_body", "post_data")
DEFAULT_GROUP_COLUMNS = ("user_index", "userindex", "userIndex", "UserIndex", "user_id", "userid")
DEFAULT_STATUS_COLUMNS = (
    "status",
    "status_code",
    "Status",
    "StatusCode",
    "response_status",
    "revised_status",
    "originial_status",
    "original_status",
    "code",
)
DEFAULT_TIMESTAMP_COLUMNS = ("timestamp", "time", "datetime", "created_at", "Timestamp", "Time")
DEFAULT_METADATA_COLUMNS = (
    "timestamp",
    "username",
    "api_endpoint",
    "originial_status",
    "original_status",
    "revised_status",
    "user_type",
    "data_type",
    "data_valid",
    "seq_valid",
)
KNOWN_SITE_IDS = ("humhub", "memos")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
DEFAULT_INPUT = Path(__file__).resolve().parents[1] / "test_data" / "APISet2"


def user_type_is_normal(value: Any) -> bool:
    return str(value if value is not None else "").strip() in {"0", "0.0"}


def label_from_user_types(values: Iterable[Any]) -> Dict[str, object]:
    user_types = [str(value if value is not None else "").strip() for value in values if str(value if value is not None else "").strip()]
    is_anomalous = any(not user_type_is_normal(value) for value in user_types)
    return {
        "user_types": sorted(set(user_types)),
        "label": "abnormal" if is_anomalous else "normal",
        "is_anomalous": is_anomalous,
        "label_source": "user_type_all_zero_normal_else_abnormal",
    }


def infer_site_id(source_file: str, target: str = "") -> str:
    target_lower = str(target or "").lower()
    if ":5230" in target_lower or "/api/v1/memo" in target_lower or "/api/v1/tag" in target_lower or "/api/v1/resource" in target_lower:
        return "memos"
    if "/index.php" in target_lower or ":8081" in target_lower or ":8082" in target_lower:
        return "humhub"
    lowered = Path(source_file).name.lower()
    for site_id in KNOWN_SITE_IDS:
        if site_id in lowered:
            return site_id
    stem = Path(source_file).stem
    return stem.split("_", 1)[0].lower() if stem else "unknown_site"


def infer_dataset_name(inputs: List[str]) -> str:
    text = " ".join(str(item).replace("\\", "/").lower() for item in inputs)
    if "train_data" in text or "/train" in text or text.endswith("train"):
        return "train"
    if "test_data" in text or "/test" in text or text.endswith("test"):
        return "test"
    return "dataset"


def pick_column(row: Dict[str, str], candidates: Iterable[str], explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    for name in candidates:
        if name in row:
            return name
    raise KeyError(f"Could not find any of these columns: {', '.join(candidates)}")


def read_csv(path: Path, delimiter: Optional[str]) -> List[Dict[str, str]]:
    dialect_delimiter = delimiter
    if dialect_delimiter is None:
        dialect_delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, delimiter=dialect_delimiter)
        try:
            headers = next(reader)
        except StopIteration:
            return []
        return [normalize_csv_values(headers, values) for values in reader]


def normalize_csv_values(headers: List[str], values: List[str]) -> Dict[str, str]:
    record = {header: values[index] if index < len(values) else "" for index, header in enumerate(headers)}
    method_header_index = next((index for index, name in enumerate(headers) if name in DEFAULT_METHOD_COLUMNS), -1)
    method_value_index = next((index for index, value in enumerate(values) if str(value).strip().upper() in HTTP_METHODS), -1)
    if method_header_index < 0 or method_value_index < 0 or method_value_index == method_header_index:
        return record

    # Some files mix rows with extra unnamed/timestamp and body-size columns under a shorter header.
    method = values[method_value_index].strip().upper()
    if method_value_index >= 2:
        record["user_index"] = values[0]
        record["username"] = values[1]
    if method_value_index >= 4:
        record["timestamp"] = values[method_value_index - 1]
        record["Unnamed: 0"] = values[method_value_index - 2]
    record["http_method"] = method
    record["url"] = values[method_value_index + 1] if method_value_index + 1 < len(values) else ""
    record["api_endpoint"] = values[method_value_index + 2] if method_value_index + 2 < len(values) else ""
    record["header"] = values[method_value_index + 3] if method_value_index + 3 < len(values) else ""
    record["data"] = values[method_value_index + 4] if method_value_index + 4 < len(values) else ""

    tail = values[method_value_index + 5 :]
    if len(tail) >= 9:
        record["request_body_size"] = tail[0]
        record["response_body_size"] = tail[1]
        record["originial_status"] = tail[2]
        record["revised_status"] = tail[3]
        record["execution_time"] = tail[4]
        record["user_type"] = tail[5]
        record["data_type"] = tail[6]
        record["data_valid"] = tail[7]
        record["seq_valid"] = tail[8]
    elif len(tail) >= 7:
        record["originial_status"] = tail[0]
        record["revised_status"] = tail[1]
        record["execution_time"] = tail[2]
        record["user_type"] = tail[3]
        record["data_type"] = tail[4]
        record["data_valid"] = tail[5]
        record["seq_valid"] = tail[6]
    return record


def read_xlsx(path: Path, sheet: Optional[str]) -> List[Dict[str, str]]:
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise RuntimeError("Reading .xlsx requires openpyxl: pip install openpyxl") from exc

    workbook = load_workbook(path, read_only=True, data_only=True)
    worksheet = workbook[sheet] if sheet else workbook.active
    rows = worksheet.iter_rows(values_only=True)
    try:
        headers = ["" if cell is None else str(cell) for cell in next(rows)]
    except StopIteration:
        return []

    records: List[Dict[str, str]] = []
    for values in rows:
        record = {}
        for index, header in enumerate(headers):
            if not header:
                continue
            value = values[index] if index < len(values) else None
            record[header] = "" if value is None else str(value)
        records.append(record)
    return records


def stringify_json_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def flatten_request_sessions(payload: Any) -> List[Dict[str, str]]:
    sessions = payload if isinstance(payload, list) else [payload]
    records: List[Dict[str, str]] = []
    for session_index, session_obj in enumerate(sessions, 1):
        if not isinstance(session_obj, dict):
            continue
        requests = session_obj.get("requests")
        if not isinstance(requests, list):
            records.append({str(key): stringify_json_cell(value) for key, value in session_obj.items()})
            continue

        parent_fields = {
            str(key): stringify_json_cell(value)
            for key, value in session_obj.items()
            if key != "requests" and not isinstance(value, (dict, list))
        }
        parent_fields.setdefault("session_index", str(session_index))
        for request_index, request_obj in enumerate(requests, 1):
            if not isinstance(request_obj, dict):
                continue
            record = dict(parent_fields)
            record["request_in_session_index"] = str(request_index)
            for key, value in request_obj.items():
                record[str(key)] = stringify_json_cell(value)
            records.append(record)
    return records


def read_json_table(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    if isinstance(payload, dict):
        for key in ("records", "rows", "data", "items", "sessions"):
            value = payload.get(key)
            if isinstance(value, list):
                payload = value
                break
    if isinstance(payload, (list, dict)):
        return flatten_request_sessions(payload)
    raise ValueError(f"Unsupported JSON structure: {path}")


def read_table(path: Path, delimiter: Optional[str], sheet: Optional[str]) -> List[Dict[str, str]]:
    suffix = path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        return read_csv(path, delimiter)
    if suffix == ".json":
        return read_json_table(path)
    if suffix in (".xlsx", ".xlsm"):
        return read_xlsx(path, sheet)
    raise ValueError(f"Unsupported file type: {path}")


def rows_with_source(rows: List[Dict[str, str]], source_path: Path) -> List[Dict[str, str]]:
    source = str(source_path.resolve())
    return [dict(row, source_file=source) for row in rows]


def read_tables(paths: List[Path], delimiter: Optional[str], sheet: Optional[str]) -> List[Dict[str, str]]:
    merged: List[Dict[str, str]] = []
    for path in paths:
        merged.extend(rows_with_source(read_table(path, delimiter, sheet), path))
    return merged


def read_tables_by_file(paths: List[Path], delimiter: Optional[str], sheet: Optional[str]) -> List[List[Dict[str, str]]]:
    return [rows_with_source(read_table(path, delimiter, sheet), path) for path in paths]


def sort_rows_by_timestamp(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    if not rows:
        return []
    timestamp_col = next((name for name in DEFAULT_TIMESTAMP_COLUMNS if name in rows[0]), None)
    if not timestamp_col:
        return rows
    return sorted(rows, key=lambda row: (row.get(timestamp_col, ""), row.get("source_file", "")))


def write_merged_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: List[str] = []
    seen = set()
    for row in rows:
        for name in row.keys():
            if name not in seen:
                seen.add(name)
                fieldnames.append(name)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def request_target(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc:
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        return target
    return url or "/"


def target_path(target: str) -> str:
    parsed = urlsplit(target)
    return parsed.path or "/"


def parse_mapping(value: str) -> Dict[str, str]:
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        try:
            payload = ast.literal_eval(text)
        except Exception:
            return {"raw": text}
    if isinstance(payload, dict):
        return {str(key): "" if child is None else str(child) for key, child in payload.items()}
    return {"raw": text}


def normalize_body(body: str, body_format: str) -> str:
    body = (body or "").strip()
    lowered = body.lower()
    if not body or lowered in {"nan", "none", "null"} or (lowered.startswith("nan") and len(lowered) <= 5):
        return ""
    if body_format == "raw":
        return body

    try:
        value = ast.literal_eval(body)
    except Exception:
        return body

    if body_format == "json" and isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    if body_format == "form" and isinstance(value, dict):
        return "&".join(f"{key}={value[key]}" for key in value)

    return body


def escape_for_quoted_line(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def convert_rows(
    rows: List[Dict[str, str]],
    method_column: Optional[str],
    url_column: Optional[str],
    body_column: Optional[str],
    body_format: str,
    quote_lines: bool,
) -> List[str]:
    if not rows:
        return []

    first = rows[0]
    method_col = pick_column(first, DEFAULT_METHOD_COLUMNS, method_column)
    url_col = pick_column(first, DEFAULT_URL_COLUMNS, url_column)
    body_col = body_column
    if body_col is None:
        body_col = next((name for name in DEFAULT_BODY_COLUMNS if name in first), None)

    converted = []
    for row in rows:
        method = row.get(method_col, "").strip().upper()
        if method not in HTTP_METHODS:
            continue
        target = request_target(row.get(url_col, "").strip())
        line = f"{method} {target}".strip()

        body = normalize_body(row.get(body_col, "") if body_col else "", body_format)
        if body:
            line = f"{line} BODY {body}"

        if quote_lines:
            line = f'"{escape_for_quoted_line(line)}"'
        converted.append(line)
    return converted


def convert_rows_to_json_records(
    rows: List[Dict[str, str]],
    method_column: Optional[str],
    url_column: Optional[str],
    body_column: Optional[str],
    group_column: Optional[str],
    status_column: Optional[str],
    body_format: str,
    first_column_as_group: bool,
    include_source_in_session_key: bool,
    site_id_override: str = "",
) -> List[Dict[str, object]]:
    if not rows:
        return []

    first = rows[0]
    method_col = pick_column(first, DEFAULT_METHOD_COLUMNS, method_column)
    url_col = pick_column(first, DEFAULT_URL_COLUMNS, url_column)
    body_col = body_column
    if body_col is None:
        body_col = next((name for name in DEFAULT_BODY_COLUMNS if name in first), None)
    header_col = next((name for name in ("header", "headers", "request_headers", "requestHeaders") if name in first), None)

    if first_column_as_group:
        group_col = next(iter(first.keys()))
    else:
        group_col = pick_column(first, DEFAULT_GROUP_COLUMNS, group_column)

    status_col = status_column
    if status_col is None:
        status_col = next((name for name in DEFAULT_STATUS_COLUMNS if name in first), None)

    session_ids: "OrderedDict[str, int]" = OrderedDict()
    records: List[Dict[str, object]] = []

    for request_index, row in enumerate(rows, 1):
        group_value = row.get(group_col, "").strip() or "EMPTY"
        source_file = row.get("source_file", "").strip()
        session_key = f"{source_file}::{group_value}" if include_source_in_session_key and source_file else group_value
        if session_key not in session_ids:
            session_ids[session_key] = len(session_ids) + 1

        method = row.get(method_col, "").strip().upper()
        if method not in HTTP_METHODS:
            continue
        target = request_target(row.get(url_col, "").strip())
        path_only = target_path(target)
        api = f"{method} {target}".strip()

        body = normalize_body(row.get(body_col, "") if body_col else "", body_format)
        if body:
            api = f"{api} BODY {body}"

        status_value = row.get(status_col, "").strip() if status_col else ""
        row_site_id = row.get("site_id", "").strip()
        site_id = site_id_override or row_site_id or infer_site_id(source_file, target)
        record: Dict[str, object] = {
            "site_id": site_id,
            "session_id": session_ids[session_key],
            "session_key": session_key,
            "source_file": source_file or None,
            "request_index": request_index,
            "api": api,
            "api_request": api,
            "full_api_request": api,
            "method": method,
            "path": path_only,
            "raw_url": target,
            "full_url_path": target,
            "body": body or None,
            "request_body": body or None,
            "status_code": status_value or None,
        }
        if header_col:
            record["request_headers"] = parse_mapping(row.get(header_col, ""))
        for metadata_col in DEFAULT_METADATA_COLUMNS:
            metadata_value = row.get(metadata_col, "").strip()
            if metadata_value and metadata_col not in record:
                record[metadata_col] = metadata_value
        if record.get("user_type") is not None:
            request_label = label_from_user_types([record.get("user_type")])
            record["label"] = request_label["label"]
            record["is_anomalous"] = request_label["is_anomalous"]
            record["label_source"] = request_label["label_source"]
        records.append(record)

    return records


def write_json_array_one_record_per_line(path: Path, records: List[Dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("[\n")
        for index, record in enumerate(records):
            suffix = "," if index < len(records) - 1 else ""
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            handle.write(suffix + "\n")
        handle.write("]\n")


def write_jsonl(path: Path, records: Iterable[Dict[str, object]]) -> int:
    count = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def write_json_blocks(path: Path, records: Iterable[Dict[str, object]]) -> int:
    count = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            if count:
                handle.write("\n\n")
            handle.write(json.dumps(record, ensure_ascii=False, indent=2))
            handle.write("\n")
            count += 1
    return count


def session_event(record: Dict[str, object], step: int) -> Dict[str, object]:
    event: Dict[str, object] = {
        "step": step,
        "full_api_request": record.get("full_api_request") or record.get("api") or "",
        "api_request_pattern": record.get("api") or "",
        "method": record.get("method") or "",
        "path": record.get("path") or "",
        "raw_url": record.get("raw_url") or "",
        "status_code": record.get("status_code"),
        "body": record.get("body"),
        "request_body": record.get("request_body"),
    }
    for key in (
        "request_headers",
        "timestamp",
        "username",
        "api_endpoint",
        "originial_status",
        "original_status",
        "revised_status",
        "user_type",
        "data_type",
        "data_valid",
        "seq_valid",
        "source_file",
    ):
        if record.get(key) is not None:
            event[key] = record[key]
    return event


def build_sessions(records: List[Dict[str, object]]) -> "OrderedDict[str, Dict[str, Any]]":
    sessions: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for record in records:
        site_id = str(record.get("site_id") or "unknown_site")
        session_key = str(record.get("session_key") or record.get("session_id") or "EMPTY")
        combined_key = f"{site_id}::{session_key}"
        if combined_key not in sessions:
            sessions[combined_key] = {
                "site_id": site_id,
                "session_id": f"{site_id}_{len([s for s in sessions.values() if s.get('site_id') == site_id]) + 1}",
                "source_ip": str(record.get("username") or ""),
                "start_time": str(record.get("timestamp") or ""),
                "end_time": str(record.get("timestamp") or ""),
                "source_files": [],
                "full_api_sequence": [],
                "sequence": OrderedDict(),
            }
        session = sessions[combined_key]
        source_file = str(record.get("source_file") or "")
        if source_file and source_file not in session["source_files"]:
            session["source_files"].append(source_file)
        if record.get("timestamp"):
            session["end_time"] = str(record.get("timestamp"))
        step = len(session["full_api_sequence"]) + 1
        full_api = str(record.get("full_api_request") or record.get("api") or "")
        session["full_api_sequence"].append(full_api)
        session["sequence"][str(step)] = session_event(record, step)
    for session in sessions.values():
        sequence = session.get("sequence", {})
        user_types = []
        if isinstance(sequence, dict):
            for event in sequence.values():
                if isinstance(event, dict) and event.get("user_type") is not None:
                    user_types.append(event.get("user_type"))
        session.update(label_from_user_types(user_types))
    return sessions


def safe_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return name.strip("._") or "sessions"


def write_session_jsonl(
    output_dir: Path,
    records: List[Dict[str, object]],
    file_tag: str = "",
    single_file_name: str = "",
) -> Dict[str, int]:
    sessions = build_sessions(records)
    output_dir.mkdir(parents=True, exist_ok=True)
    if single_file_name:
        path = output_dir / single_file_name
        return {str(path): write_json_blocks(path, sessions.values())}

    by_site: "OrderedDict[str, List[Dict[str, object]]]" = OrderedDict()
    for session in sessions.values():
        by_site.setdefault(str(session.get("site_id") or "unknown_site"), []).append(session)
    counts: Dict[str, int] = {}
    for site_id, site_sessions in by_site.items():
        suffix = f"_{safe_name(file_tag)}" if file_tag else ""
        path = output_dir / f"session_site_{site_id}{suffix}.jsonl"
        counts[str(path)] = write_json_blocks(path, site_sessions)
    return counts


def group_rows(
    rows: List[Dict[str, str]],
    group_column: Optional[str],
    first_column_as_group: bool,
    include_source_in_session_key: bool,
) -> "OrderedDict[str, List[Dict[str, str]]]":
    if not rows:
        return OrderedDict()

    first = rows[0]
    if first_column_as_group:
        group_col = next(iter(first.keys()))
    else:
        group_col = pick_column(first, DEFAULT_GROUP_COLUMNS, group_column)

    groups: "OrderedDict[str, List[Dict[str, str]]]" = OrderedDict()
    for row in rows:
        group_value = row.get(group_col, "").strip() or "EMPTY"
        source_file = row.get("source_file", "").strip()
        if include_source_in_session_key and source_file:
            group_value = f"{source_file}::{group_value}"
        groups.setdefault(group_value, []).append(row)
    return groups


def expand_inputs(patterns: List[str]) -> List[Path]:
    paths: List[Path] = []
    for pattern in patterns:
        candidate = Path(pattern)
        if candidate.is_dir():
            for suffix in ("*.csv", "*.tsv", "*.xlsx", "*.xlsm", "*.json"):
                paths.extend(sorted(candidate.glob(suffix)))
            continue
        matches = [Path(match) for match in glob.glob(pattern)]
        paths.extend(matches or [candidate])

    unique = []
    seen = set()
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert request tables to one-line request sequences."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        default=[str(DEFAULT_INPUT)],
        help="Input files, directories, or glob patterns. Defaults to <repo>/test_data/APISet2.",
    )
    parser.add_argument("-o", "--output-dir", default="", help="Default: artifacts/<dataset>/request_line_sequences")
    parser.add_argument("--method-column", help="Column containing HTTP method.")
    parser.add_argument("--url-column", help="Column containing URL/path.")
    parser.add_argument("--body-column", help="Column containing request body.")
    parser.add_argument("--body-format", choices=("json", "raw", "form"), default="json")
    parser.add_argument("--delimiter", help="CSV delimiter. Defaults to comma, tab for .tsv.")
    parser.add_argument("--sheet", help="Excel sheet name. Defaults to active sheet.")
    parser.add_argument("--no-quotes", action="store_true", help="Do not wrap each line in quotes.")
    parser.add_argument(
        "--group-column",
        default="user_index",
        help="Column used to split API sequences. Defaults to user_index.",
    )
    parser.add_argument(
        "--first-column-as-group",
        action="store_true",
        help="Use the first table column as the grouping key.",
    )
    parser.add_argument(
        "--no-group",
        action="store_true",
        help="Output one request per line instead of one grouped sequence per line.",
    )
    parser.add_argument(
        "--sequence-separator",
        default=" || ",
        help="Separator between requests inside one grouped sequence.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output a valid .json file with one API record per line inside the JSON array.",
    )
    parser.add_argument(
        "--request-jsonl",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Also write request-level JSONL for parameter profiling. Enabled by default.",
    )
    parser.add_argument(
        "--session-jsonl",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Also write session_site_<site_id>.jsonl files for clustering and rule detection. Enabled by default.",
    )
    parser.add_argument(
        "--session-output-dir",
        default="",
        help="Directory for session_site_<site_id>.jsonl files. Default: artifacts/<dataset>/log_sequence.",
    )
    parser.add_argument(
        "--session-per-source-file",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Write session files separately for each source file, using session_site_<site>_<file>.jsonl. Disabled by default.",
    )
    parser.add_argument(
        "--single-session-file",
        default="",
        help="Write all sessions into one JSONL file under --session-output-dir. Default for test_data/APISet2: session_all.jsonl.",
    )
    parser.add_argument("--status-column", help="Column containing HTTP response status code.")
    parser.add_argument(
        "--merge-inputs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Merge all input tables before session splitting. Enabled by default for train_data.",
    )
    parser.add_argument(
        "--merged-name",
        default="",
        help="Base output name used when --merge-inputs is enabled.",
    )
    parser.add_argument(
        "--no-source-in-session-key",
        action="store_true",
        help="Do not include source_file in session keys after merging.",
    )
    parser.add_argument(
        "--sort-by-timestamp",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Sort rows by timestamp inside each file when a timestamp column exists. Disabled by default to preserve original file order.",
    )
    parser.add_argument("--site-id", default="", help="Override inferred site_id in generated request/session records.")
    args = parser.parse_args()

    dataset_name = infer_dataset_name(args.inputs)
    if not args.merged_name:
        args.merged_name = f"{dataset_name}_data_merged"
    output_dir = Path(args.output_dir) if args.output_dir else Path("artifacts") / dataset_name / "request_line_sequences"
    session_output_dir = Path(args.session_output_dir) if args.session_output_dir else Path("artifacts") / dataset_name / "log_sequence"
    single_session_file = args.single_session_file
    if not single_session_file and dataset_name == "test":
        single_session_file = "session_all.jsonl"
    output_dir.mkdir(parents=True, exist_ok=True)

    input_paths = expand_inputs(args.inputs)
    if not input_paths:
        raise SystemExit("No input files found.")

    if args.merge_inputs:
        file_rows = read_tables_by_file(input_paths, args.delimiter, args.sheet)
        if args.sort_by_timestamp:
            file_rows = [sort_rows_by_timestamp(rows) for rows in file_rows]
        rows = [row for rows_for_file in file_rows for row in rows_for_file]

        merged_csv_path = output_dir / f"{args.merged_name}.csv"
        write_merged_csv(merged_csv_path, rows)
        print(f"{len(input_paths)} files -> {merged_csv_path} ({len(rows)} merged rows)")

        include_source = not args.no_source_in_session_key
        if args.json:
            records = []
            for rows_for_file in file_rows:
                records.extend(
                    convert_rows_to_json_records(
                        rows=rows_for_file,
                        method_column=args.method_column,
                        url_column=args.url_column,
                        body_column=args.body_column,
                        group_column=args.group_column,
                        status_column=args.status_column,
                        body_format=args.body_format,
                        first_column_as_group=args.first_column_as_group,
                        include_source_in_session_key=include_source,
                        site_id_override=args.site_id,
                    )
                )
            output_path = output_dir / f"{args.merged_name}_request_lines.json"
            write_json_array_one_record_per_line(output_path, records)
            print(f"{merged_csv_path} -> {output_path} ({len(records)} JSON request records)")
            if args.request_jsonl:
                jsonl_path = output_dir / f"{args.merged_name}_request_lines.jsonl"
                jsonl_count = write_jsonl(jsonl_path, records)
                print(f"{merged_csv_path} -> {jsonl_path} ({jsonl_count} JSONL request records)")
            if args.session_jsonl:
                if args.session_per_source_file:
                    for path, rows_for_file in zip(input_paths, file_rows):
                        file_records = convert_rows_to_json_records(
                            rows=rows_for_file,
                            method_column=args.method_column,
                            url_column=args.url_column,
                            body_column=args.body_column,
                            group_column=args.group_column,
                            status_column=args.status_column,
                            body_format=args.body_format,
                            first_column_as_group=args.first_column_as_group,
                            include_source_in_session_key=include_source,
                            site_id_override=args.site_id,
                        )
                        session_counts = write_session_jsonl(session_output_dir, file_records, path.stem)
                        for session_path, session_count in session_counts.items():
                            print(f"{path} -> {session_path} ({session_count} sessions)")
                else:
                    session_counts = write_session_jsonl(session_output_dir, records, single_file_name=single_session_file)
                    for session_path, session_count in session_counts.items():
                        print(f"{merged_csv_path} -> {session_path} ({session_count} sessions)")
            return 0

        if args.no_group:
            lines = convert_rows(
                rows=rows,
                method_column=args.method_column,
                url_column=args.url_column,
                body_column=args.body_column,
                body_format=args.body_format,
                quote_lines=not args.no_quotes,
            )
            output_path = output_dir / f"{args.merged_name}_request_lines.txt"
            output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            print(f"{merged_csv_path} -> {output_path} ({len(lines)} request lines)")
            return 0

        groups = group_rows(
            rows=rows,
            group_column=args.group_column,
            first_column_as_group=args.first_column_as_group,
            include_source_in_session_key=include_source,
        )
        lines = []
        for group_value, group in groups.items():
            request_lines = convert_rows(
                rows=group,
                method_column=args.method_column,
                url_column=args.url_column,
                body_column=args.body_column,
                body_format=args.body_format,
                quote_lines=False,
            )
            sequence = args.sequence_separator.join(request_lines)
            line = f"{group_value}\t{sequence}"
            if not args.no_quotes:
                line = f"{group_value}\t\"{escape_for_quoted_line(sequence)}\""
            lines.append(line)

        output_path = output_dir / f"{args.merged_name}_api_sequences_by_user.txt"
        output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        print(f"{merged_csv_path} -> {output_path} ({len(lines)} grouped sequences, {len(rows)} requests)")
        return 0

    for path in input_paths:
        rows = read_table(path, args.delimiter, args.sheet)
        if args.json:
            records = convert_rows_to_json_records(
                rows=rows,
                method_column=args.method_column,
                url_column=args.url_column,
                body_column=args.body_column,
                group_column=args.group_column,
                status_column=args.status_column,
                body_format=args.body_format,
                first_column_as_group=args.first_column_as_group,
                include_source_in_session_key=False,
                site_id_override=args.site_id,
            )
            output_path = output_dir / f"{path.stem}_request_lines.json"
            write_json_array_one_record_per_line(output_path, records)
            print(f"{path} -> {output_path} ({len(records)} JSON request records)")
            if args.request_jsonl:
                jsonl_path = output_dir / f"{path.stem}_request_lines.jsonl"
                jsonl_count = write_jsonl(jsonl_path, records)
                print(f"{path} -> {jsonl_path} ({jsonl_count} JSONL request records)")
            if args.session_jsonl:
                session_counts = write_session_jsonl(session_output_dir, records)
                for session_path, session_count in session_counts.items():
                    print(f"{path} -> {session_path} ({session_count} sessions)")
            continue

        if args.no_group:
            lines = convert_rows(
                rows=rows,
                method_column=args.method_column,
                url_column=args.url_column,
                body_column=args.body_column,
                body_format=args.body_format,
                quote_lines=not args.no_quotes,
            )
            output_path = output_dir / f"{path.stem}_request_lines.txt"
            output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            print(f"{path} -> {output_path} ({len(lines)} request lines)")
            continue

        groups = group_rows(
            rows=rows,
            group_column=args.group_column,
            first_column_as_group=args.first_column_as_group,
            include_source_in_session_key=False,
        )
        lines = []
        for group_value, group in groups.items():
            request_lines = convert_rows(
                rows=group,
                method_column=args.method_column,
                url_column=args.url_column,
                body_column=args.body_column,
                body_format=args.body_format,
                quote_lines=False,
            )
            sequence = args.sequence_separator.join(request_lines)
            line = f"{group_value}\t{sequence}"
            if not args.no_quotes:
                line = f"{group_value}\t\"{escape_for_quoted_line(sequence)}\""
            lines.append(line)

        output_path = output_dir / f"{path.stem}_api_sequences_by_user.txt"
        output_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        print(f"{path} -> {output_path} ({len(lines)} grouped sequences, {len(rows)} requests)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
