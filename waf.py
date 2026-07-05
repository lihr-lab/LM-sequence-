#!/usr/bin/env python3
import argparse
import gzip
import json
from datetime import datetime, timedelta
from pathlib import Path
import re
import sys
from typing import Dict, Optional, Set, Tuple

DEFAULT_START = "2026-06-16T00:00:00+08:00"
DEFAULT_END = "2026-06-17T00:00:00+08:00"

ACCESS_TAG = "tag:waf_log_webaccess"
SECURITY_TAG = "tag:waf_log_websec"

TIMESTAMP_PATTERN = re.compile(r'"timestamp"\s*:\s*"([^"]+)"')
REQUEST_ID_PATTERN = re.compile(r"request_id:([^;\"\s]+)")
EVENT_TYPE_PATTERN = re.compile(r"event_type:([^;]+)")
EVENT_TYPE_REPLACE_PATTERN = re.compile(r"(event_type:)([^;]*)(;)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Split WAF logs by tag, match access/security logs by request_id, "
            "and build labeled training data (train.jsonl)."
        )
    )
    parser.add_argument("input_file", type=Path, help="Source mixed WAF log file path")
    parser.add_argument("--access-output", type=Path, default=None)
    parser.add_argument("--security-output", type=Path, default=None)
    parser.add_argument("--unknown-output", type=Path, default=None)
    parser.add_argument(
        "--matched-security-output",
        type=Path,
        default=None,
        help="Optional output for security logs whose request_id matched an access log.",
    )
    parser.add_argument(
        "--unmatched-security-output",
        type=Path,
        default=None,
        help="Optional output for security logs whose request_id did not match an access log.",
    )
    parser.add_argument(
        "--labeled-output",
        type=Path,
        default=Path("train.jsonl"),
        help="Output JSONL for labeled access logs in train mode (default: train.jsonl)",
    )
    parser.add_argument(
        "--start-time",
        default=DEFAULT_START,
        help=f"Inclusive start timestamp (default: {DEFAULT_START})",
    )
    parser.add_argument(
        "--end-time",
        default=DEFAULT_END,
        help=f"Inclusive end timestamp (default: {DEFAULT_END})",
    )
    return parser.parse_args()


def open_text(path: Path, mode: str):
    if "b" in mode:
        raise ValueError("open_text only supports text mode")
    if path.suffix == ".gz":
        return gzip.open(path, mode, encoding="utf-8", errors="ignore")
    return path.open(mode, encoding="utf-8", errors="ignore")


def default_output_paths(input_file: Path) -> Tuple[Path, Path, Path]:
    base = input_file.with_suffix("")
    return (
        Path(f"{base}.access{input_file.suffix}"),
        Path(f"{base}.security{input_file.suffix}"),
        Path(f"{base}.unknown{input_file.suffix}"),
    )


def parse_iso8601(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    normalized = re.sub(r"T:(\d{2}:\d{2}(?:\.\d+)?)$", r"T00:\1", normalized)
    day_end_match = re.match(
        r"^(\d{4}-\d{2}-\d{2})T24:00:00(?:\.0+)?((?:[+-]\d{2}:\d{2})?)$",
        normalized,
    )
    if day_end_match:
        base_date = datetime.fromisoformat(f"{day_end_match.group(1)}T00:00:00")
        normalized = (
            f"{(base_date + timedelta(days=1)).date().isoformat()}T00:00:00"
            f"{day_end_match.group(2)}"
        )
    dt_value = datetime.fromisoformat(normalized)
    if dt_value.tzinfo is None:
        dt_value = datetime.fromisoformat(f"{normalized}+08:00")
    return dt_value


def extract_line_timestamp(line: str) -> Optional[datetime]:
    match = TIMESTAMP_PATTERN.search(line)
    if not match:
        return None
    try:
        return parse_iso8601(match.group(1))
    except ValueError:
        return None


def extract_request_id(line: str) -> Optional[str]:
    match = REQUEST_ID_PATTERN.search(line)
    return match.group(1) if match else None


def extract_event_type(line: str) -> str:
    match = EVENT_TYPE_PATTERN.search(line)
    return match.group(1).strip() if match else ""


def append_fields_to_line(
    line: str, label: int, security_event_type: str, matched_request_id: str
) -> str:
    stripped = line.rstrip("\n")
    if stripped.endswith("}"):
        return (
            f'{stripped[:-1]},"label":{label},"security_event_type":'
            f"{json.dumps(security_event_type, ensure_ascii=False)},"
            f'"matched_request_id":{json.dumps(matched_request_id, ensure_ascii=False)}}}\n'
        )
    return (
        json.dumps(
            {
                "raw_line": stripped,
                "label": label,
                "security_event_type": security_event_type,
                "matched_request_id": matched_request_id,
            },
            ensure_ascii=False,
        )
        + "\n"
    )


def replace_access_event_type(line: str, security_event_type: str) -> str:
    return EVENT_TYPE_REPLACE_PATTERN.sub(
        lambda m: f"{m.group(1)}{security_event_type}{m.group(3)}",
        line,
        count=1,
    )


def split_by_tag(
    input_file: Path,
    access_output: Path,
    security_output: Path,
    unknown_output: Optional[Path],
    start_dt: datetime,
    end_dt: datetime,
) -> Dict[str, int]:
    stats = {
        "matched_by_time": 0,
        "filtered_out_by_time": 0,
        "missing_or_invalid_timestamp": 0,
        "access": 0,
        "security": 0,
        "unknown": 0,
    }
    access_output.parent.mkdir(parents=True, exist_ok=True)
    security_output.parent.mkdir(parents=True, exist_ok=True)
    if unknown_output is not None:
        unknown_output.parent.mkdir(parents=True, exist_ok=True)

    with (
        open_text(input_file, "rt") as src,
        open_text(access_output, "wt") as access_dst,
        open_text(security_output, "wt") as security_dst,
    ):
        unknown_dst = (
            open_text(unknown_output, "wt")
            if unknown_output is not None
            else None
        )
        try:
            for line in src:
                if not line.strip():
                    continue
                line_timestamp = extract_line_timestamp(line)
                if line_timestamp is None:
                    stats["missing_or_invalid_timestamp"] += 1
                    continue
                if line_timestamp < start_dt or line_timestamp > end_dt:
                    stats["filtered_out_by_time"] += 1
                    continue

                stats["matched_by_time"] += 1
                if ACCESS_TAG in line:
                    access_dst.write(line)
                    stats["access"] += 1
                elif SECURITY_TAG in line:
                    security_dst.write(line)
                    stats["security"] += 1
                else:
                    stats["unknown"] += 1
                    if unknown_dst is not None:
                        unknown_dst.write(line)
        finally:
            if unknown_dst is not None:
                unknown_dst.close()
    return stats


def build_security_map(security_file: Path) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, int]]:
    request_id_to_event_type: Dict[str, str] = {}
    request_id_to_line: Dict[str, str] = {}
    stats = {"total": 0, "missing_request_id": 0, "missing_event_type": 0}
    with open_text(security_file, "rt") as src:
        for line in src:
            if not line.strip():
                continue
            stats["total"] += 1
            request_id = extract_request_id(line)
            if request_id is None:
                stats["missing_request_id"] += 1
                continue
            event_type = extract_event_type(line)
            if not event_type:
                stats["missing_event_type"] += 1
            if request_id not in request_id_to_event_type:
                request_id_to_event_type[request_id] = event_type
                request_id_to_line[request_id] = line
    return request_id_to_event_type, request_id_to_line, stats


def label_access_logs(
    access_file: Path,
    output_file: Path,
    security_event_types: Dict[str, str],
) -> Tuple[Set[str], Dict[str, int]]:
    matched_security_ids: Set[str] = set()
    stats = {
        "total": 0,
        "missing_request_id": 0,
        "matched_label_1": 0,
        "unmatched_label_0": 0,
    }
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with (
        open_text(access_file, "rt") as src,
        open_text(output_file, "wt") as dst,
    ):
        for line in src:
            if not line.strip():
                continue
            stats["total"] += 1
            request_id = extract_request_id(line)
            if request_id is None:
                stats["missing_request_id"] += 1
                stats["unmatched_label_0"] += 1
                dst.write(append_fields_to_line(line, 0, "", ""))
                continue

            if request_id in security_event_types:
                security_event_type = security_event_types[request_id]
                matched_security_ids.add(request_id)
                stats["matched_label_1"] += 1
                dst.write(
                    append_fields_to_line(
                        replace_access_event_type(line, security_event_type),
                        1,
                        security_event_type,
                        request_id,
                    )
                )
            else:
                stats["unmatched_label_0"] += 1
                dst.write(append_fields_to_line(line, 0, "", request_id))
    return matched_security_ids, stats


def write_security_match_files(
    request_id_to_line: Dict[str, str],
    matched_ids: Set[str],
    matched_output: Optional[Path],
    unmatched_output: Optional[Path],
) -> None:
    if matched_output is None and unmatched_output is None:
        return
    matched_dst = None
    unmatched_dst = None
    try:
        if matched_output is not None:
            matched_output.parent.mkdir(parents=True, exist_ok=True)
            matched_dst = open_text(matched_output, "wt")
        if unmatched_output is not None:
            unmatched_output.parent.mkdir(parents=True, exist_ok=True)
            unmatched_dst = open_text(unmatched_output, "wt")
        for request_id, line in request_id_to_line.items():
            if request_id in matched_ids:
                if matched_dst is not None:
                    matched_dst.write(line)
            elif unmatched_dst is not None:
                unmatched_dst.write(line)
    finally:
        if matched_dst is not None:
            matched_dst.close()
        if unmatched_dst is not None:
            unmatched_dst.close()


def main() -> None:
    args = parse_args()
    if not args.input_file.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_file}")

    start_dt = parse_iso8601(args.start_time)
    end_dt = parse_iso8601(args.end_time)
    if start_dt > end_dt:
        raise ValueError("start-time must be earlier than or equal to end-time")

    default_access, default_security, _ = default_output_paths(args.input_file)
    access_output = args.access_output or default_access
    security_output = args.security_output or default_security

    print("Step 1/2: split logs by tag...")
    split_stats = split_by_tag(
        args.input_file,
        access_output,
        security_output,
        args.unknown_output,
        start_dt,
        end_dt,
    )

    print("Step 2/2: match by request_id and label logs...")
    security_event_types, security_lines, security_stats = build_security_map(security_output)
    
    matched_ids, access_stats = label_access_logs(
        access_output, args.labeled_output, security_event_types
    )
    write_security_match_files(
        security_lines,
        matched_ids,
        args.matched_security_output,
        args.unmatched_security_output,
    )

    print("\n" + "="*40)
    print(f"Input file: {args.input_file}")
    print(f"Time range: {start_dt.isoformat()} -> {end_dt.isoformat()}")
    print(f"Split stats: {split_stats}")
    print(f"Access output: {access_output}")
    print(f"Security output: {security_output}")
    print(f"Security stats: {security_stats}")
    print(f"Security unique request_id count: {len(security_event_types)}")
    print("-"*40)
    print(f"Train labeled output: {args.labeled_output}")
    print(f"Access train stats: {access_stats}")
    print(f"Matched security request_id count: {len(matched_ids)}")


if __name__ == "__main__":
    main()