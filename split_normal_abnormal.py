# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def user_type_is_normal(value: Any) -> bool:
    text = str(value if value is not None else "").strip()
    return text in {"", "0", "0.0", "normal", "Normal", "NORMAL"}


def split_sessions(input_file: Path, output_dir: Path) -> dict[str, int]:
    sessions = json.loads(input_file.read_text(encoding="utf-8"))
    if not isinstance(sessions, list):
        raise ValueError(f"{input_file} must contain a JSON array of sessions.")

    normal = []
    abnormal = []
    for session in sessions:
        if not isinstance(session, dict):
            continue
        bucket = normal if user_type_is_normal(session.get("user_type")) else abnormal
        bucket.append(session)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "normal.json").write_text(json.dumps(normal, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "abnormal.json").write_text(json.dumps(abnormal, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"normal": len(normal), "abnormal": len(abnormal)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Split session JSON into normal.json and abnormal.json by top-level user_type.")
    parser.add_argument("inputs", nargs="+", help="Input JSON files.")
    parser.add_argument("--output-root", default="", help="Default: each input file parent directory.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for value in args.inputs:
        input_file = Path(value)
        output_dir = Path(args.output_root) / input_file.stem if args.output_root else input_file.parent
        counts = split_sessions(input_file, output_dir)
        print(f"{input_file} -> {output_dir} normal={counts['normal']} abnormal={counts['abnormal']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
