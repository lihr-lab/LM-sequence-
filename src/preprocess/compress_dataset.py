# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


DEFAULT_BASE_DIR = "/home/syslog-project/logs/sequence/log_process"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert session JSONL to compact sequence text.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--input-dir", default="")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--bucket", default="main_3_50", choices=["short_1_2", "main_3_50", "long_51_plus", "all"])
    parser.add_argument("--site-id", default="")
    return parser.parse_args()


def iter_jsonl(path: Path):
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


def api_only_token(token: str) -> str:
    text = str(token or "").strip()
    if not text:
        return ""

    if " BODY " in text:
        text = text.split(" BODY ", 1)[0].strip()
    if "?" in text:
        text = text.split("?", 1)[0].strip()
        
    return text


def api_sequence_tokens(session_obj: dict) -> list[str]:
    api_sequence = session_obj.get("api_sequence", [])
    if not isinstance(api_sequence, list):
        return []
    tokens: list[str] = []
    for token in api_sequence:
        text = api_only_token(str(token))
        if text:
            tokens.append(text)
    return tokens


def collect_session_files(input_dir: Path, bucket: str, site_id: str = "") -> list[Path]:
    file_pattern = f"session_site_{site_id}.jsonl" if site_id else "session_site_*.jsonl"
    
    if bucket == "all":
        return sorted(input_dir.glob(f"*/{file_pattern}")) + sorted(input_dir.glob(file_pattern))
    bucket_dir = input_dir / bucket
    if bucket_dir.exists():
        return sorted(bucket_dir.glob(file_pattern))
    return sorted(input_dir.glob(file_pattern))


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    input_dir = Path(args.input_dir) if args.input_dir else base_dir / "filtered_sequences"
    output_dir = Path(args.output_dir) if args.output_dir else input_dir / "compressed_input"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_dir.exists():
        raise FileNotFoundError(f"input session dir not found: {input_dir}")

    session_files = collect_session_files(input_dir, args.bucket, args.site_id)
    if not session_files:
        raise FileNotFoundError(f"no session files found in {input_dir} for bucket={args.bucket}")

    total_sessions = 0
    for session_file in session_files:
        site_id = session_file.stem.split("session_site_", 1)[-1]
        bucket_label = session_file.parent.name if session_file.parent != input_dir else args.bucket
        output_txt_file = output_dir / f"compressed_{bucket_label}_site_{site_id}.txt"

        sample_count = 0
        with output_txt_file.open("w", encoding="utf-8", newline="\n") as fout:
            for session_obj in iter_jsonl(session_file):
                sample_count += 1
                total_sessions += 1
                fout.write(
                    f"=== Session {session_obj.get('session_id', sample_count)} "
                    f"Label:{session_obj.get('session_label', 'normal')} "
                    f"Length:{session_obj.get('session_length', 0)} ===\n"
                )
                tokens = api_sequence_tokens(session_obj)
                for step_num, token in enumerate(tokens, start=1):
                    fout.write(f"Step {step_num}: {token}\n")
                fout.write("\n")

        print(f"saved={sample_count} file={output_txt_file}")

    print(f"total_compressed_sessions={total_sessions}")
    print(f"compressed_dir={output_dir}")


if __name__ == "__main__":
    main()