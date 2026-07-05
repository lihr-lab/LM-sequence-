# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tqdm import tqdm


DEFAULT_INPUT = "/home/syslog-project/logs/sequence/log_process/url_dataset.jsonl"
DEFAULT_OUTPUT_DIR = "/home/syslog-project/logs/sequence/log_process"
DEFAULT_SESSION_TIMEOUT_SEC = 600
DEFAULT_MAX_SESSION_DURATION_SEC = 7200
DEFAULT_MAX_EVENTS_PER_SESSION = 500


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split API events into site/client sessions.")
    parser.add_argument("--input", default=os.getenv("SEQ_URL_DATASET", DEFAULT_INPUT))
    parser.add_argument("--output-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_OUTPUT_DIR))
    parser.add_argument("--timeout-sec", type=int, default=int(os.getenv("SEQ_SESSION_TIMEOUT", DEFAULT_SESSION_TIMEOUT_SEC)))
    parser.add_argument("--max-duration-sec", type=int, default=DEFAULT_MAX_SESSION_DURATION_SEC)
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS_PER_SESSION)
    return parser.parse_args()


def parse_time(ts_str: str) -> float | None:
    text = (ts_str or "").strip()
    if not text:
        return None
    candidates = [
        text,
        text[:26],
        text[:23],
        text[:19],
    ]
    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    )
    for candidate in candidates:
        normalized = candidate.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            pass
        for fmt in formats:
            try:
                dt = datetime.strptime(candidate, fmt)
                if candidate.endswith("Z"):
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
    return None


def sequence_token(event: dict[str, Any]) -> str:
    api_request_pattern = str(event.get("api_request_pattern") or "").strip()
    method = str(event.get("method", "GET")).upper()
    path_pattern = str(event.get("path_pattern") or event.get("path") or "")
    param_type_pattern = str(event.get("param_type_pattern") or "")
    param_name_set = str(event.get("param_name_set") or "")
    body_param_type_pattern = str(event.get("body_param_type_pattern") or "").strip()
    body_param_name_set = str(event.get("body_param_name_set") or "").strip()

    if api_request_pattern:
        token = api_request_pattern
    elif param_type_pattern:
        token = f"{method} {path_pattern}?{param_type_pattern}"
    elif param_name_set:
        token = f"{method} {path_pattern}?{param_name_set}"
    else:
        token = f"{method} {path_pattern}"

    if body_param_type_pattern:
        token = f"{token} BODY {body_param_type_pattern}"
    elif body_param_name_set:
        token = f"{token} BODY {body_param_name_set}"
    return token


def join_path_query(path: str, query: str) -> str:
    path = str(path or "").strip()
    query = str(query or "").strip()
    if query:
        return f"{path}?{query}"
    return path


def full_api_request(event: dict[str, Any]) -> str:
    api_request = str(event.get("api_request") or "").strip()
    if api_request:
        base = api_request
    else:
        method = str(event.get("method") or "GET").strip().upper()
        raw_url = str(event.get("raw_url") or "").strip()
        if raw_url:
            base = f"{method} {raw_url}"
        else:
            base = f"{method} {join_path_query(str(event.get('path') or ''), str(event.get('query') or ''))}".strip()
    body_text = body_pairs_text(event)
    if body_text:
        return f"{base} BODY {body_text}"
    return base


def body_pairs_text(event: dict[str, Any]) -> str:
    pairs = event.get("body_param_pairs", [])
    if not isinstance(pairs, list):
        return ""
    parts: list[str] = []
    for item in pairs:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            key = str(item[0])
            value = str(item[1])
            if key:
                parts.append(f"{key}={value}")
    return "&".join(parts)


def build_visual_sequence(session_list: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    visual_seq: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(session_list, start=1):
        visual_seq[str(index)] = {
            "timestamp": event.get("timestamp", ""),
            "method": event.get("method", "GET"),
            "raw_url": event.get("raw_url", ""),
            "full_api_request": full_api_request(event),
            "api_request_pattern": event.get("api_request_pattern", sequence_token(event)),
            "api_request_param_names": event.get("api_request_param_names", ""),
            "path": event.get("path", ""),
            "path_pattern": event.get("path_pattern", ""),
            "query": event.get("query", ""),
            "param_name_set": event.get("param_name_set", ""),
            "param_type_pattern": event.get("param_type_pattern", ""),
            "body_param_pairs": event.get("body_param_pairs", []),
            "body_param_names": event.get("body_param_names", []),
            "body_param_name_set": event.get("body_param_name_set", ""),
            "body_param_count": event.get("body_param_count", 0),
            "body_repeated_params": event.get("body_repeated_params", []),
            "body_param_type_pattern": event.get("body_param_type_pattern", ""),
            "token": sequence_token(event),
            "status_code": event.get("status_code", 0),
            "waf_status_code": event.get("waf_status_code", ""),
            "action": event.get("action", ""),
            "alertlevel": event.get("alertlevel", ""),
            "event_label": event.get("event_label", "normal"),
            "request_id": event.get("request_id", ""),
        }
    return visual_seq


def build_api_sequence(session_list: list[dict[str, Any]]) -> list[str]:
    return [sequence_token(event) for event in session_list]


def build_full_api_sequence(session_list: list[dict[str, Any]]) -> list[str]:
    return [full_api_request(event) for event in session_list]


def session_label(session_list: list[dict[str, Any]]) -> str:
    for event in session_list:
        if event.get("event_label") == "abnormal":
            return "abnormal"
    return "normal"


def write_session(
    fout,
    site_id: str,
    client_key: str,
    current_session: list[dict[str, Any]],
    counters: Counter,
) -> None:
    if not current_session:
        return
    start_ts = int(current_session[0]["unix_timestamp"])
    session_data = {
        "site_id": site_id,
        "client_key": client_key,
        "source_ip": current_session[0].get("source_ip", ""),
        "raw_client_ip": current_session[0].get("raw_client_ip", ""),
        "src_ip": current_session[0].get("src_ip", ""),
        "session_id": f"sess_{site_id}_{client_key}_{start_ts}",
        "session_label": session_label(current_session),
        "session_length": len(current_session),
        "start_time": current_session[0].get("timestamp", ""),
        "end_time": current_session[-1].get("timestamp", ""),
        "api_sequence": build_api_sequence(current_session),
        "full_api_sequence": build_full_api_sequence(current_session),
        "sequence": build_visual_sequence(current_session),
    }
    fout.write(json.dumps(session_data, ensure_ascii=False, indent=2))
    fout.write("\n\n")
    counters["sessions"] += 1
    counters[f"length_{len(current_session)}"] += 1
    counters[f"label_{session_data['session_label']}"] += 1


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    session_dir = output_dir / "log_sequence"
    tmp_dir = output_dir / "session_blocks"
    bad_time_path = output_dir / "session_bad_time.jsonl"

    if not input_path.exists():
        raise FileNotFoundError(f"input file not found: {input_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    session_dir.mkdir(parents=True, exist_ok=True)
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    site_handlers: dict[str, Any] = {}
    counters = Counter()

    try:
        with input_path.open("r", encoding="utf-8") as fin, bad_time_path.open("w", encoding="utf-8") as fbad:
            for line in tqdm(fin, desc="Grouping by site", unit="line"):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    counters["bad_json"] += 1
                    continue
                ts = parse_time(str(record.get("timestamp", "")))
                if ts is None:
                    counters["bad_time"] += 1
                    fbad.write(line + "\n")
                    continue
                record["unix_timestamp"] = ts
                site_id = str(record.get("site_id") or "unknown_site")
                if site_id not in site_handlers:
                    site_handlers[site_id] = (tmp_dir / f"site_{site_id}.tmp").open("w", encoding="utf-8", newline="\n")
                site_handlers[site_id].write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                counters["events"] += 1
    finally:
        for handler in site_handlers.values():
            handler.close()

    tmp_files = sorted(tmp_dir.glob("site_*.tmp"))
    for tmp_file in tmp_files:
        site_id = tmp_file.name[len("site_"):-len(".tmp")]
        site_output_file = session_dir / f"session_site_{site_id}.jsonl"
        client_events: dict[str, list[dict[str, Any]]] = defaultdict(list)

        with tmp_file.open("r", encoding="utf-8") as fin:
            for line in fin:
                record = json.loads(line)
                client_key = str(
                    record.get("raw_client_ip")
                    or record.get("source_ip")
                    or record.get("src_ip")
                    or "unknown_ip"
                )
                client_events[client_key].append(record)

        with site_output_file.open("w", encoding="utf-8", newline="\n") as fout:
            for client_key, events in client_events.items():
                events.sort(key=lambda item: (float(item["unix_timestamp"]), str(item.get("request_id", ""))))
                current_session: list[dict[str, Any]] = []
                first_ts: float | None = None
                last_ts: float | None = None

                for event in events:
                    current_ts = float(event["unix_timestamp"])
                    should_split = False
                    if current_session and last_ts is not None and current_ts - last_ts > args.timeout_sec:
                        should_split = True
                    if current_session and first_ts is not None and current_ts - first_ts > args.max_duration_sec:
                        should_split = True
                    if current_session and len(current_session) >= args.max_events:
                        should_split = True

                    if should_split:
                        write_session(fout, site_id, client_key, current_session, counters)
                        current_session = []
                        first_ts = None

                    if first_ts is None:
                        first_ts = current_ts
                    current_session.append(event)
                    last_ts = current_ts

                write_session(fout, site_id, client_key, current_session, counters)

    shutil.rmtree(tmp_dir)

    summary_path = output_dir / "session_summary.json"
    summary_path.write_text(json.dumps(counters, ensure_ascii=False, indent=2), encoding="utf-8")

    print("Final session report")
    for key in ("events", "sessions", "label_normal", "label_abnormal", "bad_json", "bad_time"):
        if key in counters:
            print(f"{key}={counters[key]}")
    print(f"session_dir={session_dir}")
    print(f"summary_file={summary_path}")
    print(f"bad_time_file={bad_time_path}")


if __name__ == "__main__":
    main()
