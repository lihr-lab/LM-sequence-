#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 fn_all_samples.json（或同结构的导出文件）中按「事件类型」筛选完整样本。

事件类型默认优先 record.matched_attack_type；若为空则自动使用 record.event_type
（兼容只含其一的导出 JSON）。

用法示例：
  # 列出文件中所有事件类型及条数
  python filter_samples_by_event_type.py --input artifacts/output/fn_all_samples.json --list-types

  # 只导出漏报里 HTTP_Protocol_Validation 的完整条目
  python filter_samples_by_event_type.py --input artifacts/output/fn_all_samples.json \\
    --event-type HTTP_Protocol_Validation --bucket fn --out artifacts/output/fn_HTTP_Protocol_Validation.json

  # 在所有分桶里筛（tp/fn/fp 非空列表）
  python filter_samples_by_event_type.py --input artifacts/output/fn_all_samples.json \\
    --event-type SQL_Injection --bucket all --match contains --out artifacts/output/samples_SQL.json
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from typing import Any, Dict, List, Tuple


BUCKET_KEYS = {
    "fn": "missed_anomalies_fn",
    "fp": "false_positive_anomalies_fp",
    "tp": "detected_anomalies_tp",
}


def _event_type_field_chain(field: str) -> Tuple[str, ...]:
    """按顺序尝试 record 上的字段；仅对默认的两种类型字段做互为回退。"""
    f = (field or "").strip() or "matched_attack_type"
    if f == "matched_attack_type":
        return ("matched_attack_type", "event_type")
    if f == "event_type":
        return ("event_type", "matched_attack_type")
    return (f,)


def _event_type_from_item(item: Dict[str, Any], field: str) -> str:
    # 兼容两种输入：
    # 1) 导出样本结构：item.record.{matched_attack_type/event_type}
    # 2) 原始检测样本：item.{event_type}
    rec = item.get("record") or {}
    if not isinstance(rec, dict):
        rec = {}

    for src in (rec, item):
        if not isinstance(src, dict):
            continue
        for key in _event_type_field_chain(field):
            v = src.get(key, "")
            if v is None:
                continue
            s = str(v).strip()
            if s and s.lower() != "nan":
                return s
    return ""


def _type_matches(want: str, got: str, match: str) -> bool:
    if not want:
        return False
    if match == "exact":
        return got == want
    if match == "contains":
        return want.lower() in got.lower() or got.lower() in want.lower()
    if match == "prefix":
        return got.lower().startswith(want.lower())
    return got == want


def _load_root(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _iter_buckets(root: Any, bucket: str) -> List[Tuple[str, List[Any]]]:
    # 原始 detection JSON 常见为顶层 list
    if isinstance(root, list):
        return [("raw", root)]

    if not isinstance(root, dict):
        return []

    if bucket == "all":
        out: List[Tuple[str, List[Any]]] = []
        for short, key in BUCKET_KEYS.items():
            lst = root.get(key)
            if isinstance(lst, list) and lst:
                out.append((short, lst))
        return out
    key = BUCKET_KEYS[bucket]
    lst = root.get(key)
    if not isinstance(lst, list):
        return []
    return [(bucket, lst)]


def main() -> None:
    ap = argparse.ArgumentParser(description="按事件类型（matched_attack_type）筛选完整样本并保存。")
    ap.add_argument("--input", "-i", default="artifacts/output/fn_all_samples.json", help="输入 JSON 路径")
    ap.add_argument("--event-type", "-t", default="", help="要筛选的事件类型（与 record 中字段比对）")
    ap.add_argument(
        "--type-field",
        default="matched_attack_type",
        help="作为「事件类型」的主字段；默认 matched_attack_type，若为空会自动回退到 event_type（反之亦然）。其它字段名不做回退。",
    )
    ap.add_argument(
        "--bucket",
        choices=["fn", "fp", "tp", "all"],
        default="fn",
        help="从哪个分桶筛选：fn=漏报 fp=误报 tp=检出 all=所有非空分桶",
    )
    ap.add_argument(
        "--match",
        choices=["exact", "contains", "prefix"],
        default="exact",
        help="匹配方式：精确 / 子串 / 前缀",
    )
    ap.add_argument("--out", "-o", default="", help="输出 JSON 路径（默认自动生成）")
    ap.add_argument(
        "--list-types",
        action="store_true",
        help="仅统计并打印各事件类型条数，不导出",
    )
    ap.add_argument("--include-empty-type", action="store_true", help="统计时包含空事件类型为 __empty__")
    args = ap.parse_args()

    root = _load_root(args.input)
    field = args.type_field

    if args.list_types:
        ctr: Counter = Counter()
        for short, lst in _iter_buckets(root, "all" if args.bucket == "all" else args.bucket):
            for item in lst:
                et = _event_type_from_item(item, field)
                if not et and args.include_empty_type:
                    et = "__empty__"
                if et:
                    ctr[et] += 1
                elif args.include_empty_type:
                    ctr["__empty__"] += 1
        print(json.dumps(dict(ctr.most_common()), ensure_ascii=False, indent=2))
        print(f"distinct_types={len(ctr)} total_count={sum(ctr.values())}")
        return

    if not args.event_type.strip():
        ap.error("请指定 --event-type，或使用 --list-types 查看可用类型")

    want = args.event_type.strip()
    matched: List[Dict[str, Any]] = []
    per_bucket: Dict[str, int] = {}

    for short, lst in _iter_buckets(root, args.bucket):
        n = 0
        for item in lst:
            if not isinstance(item, dict):
                continue
            got = _event_type_from_item(item, field)
            if _type_matches(want, got, args.match):
                matched.append(item)
                n += 1
        if n:
            per_bucket[short] = n

    out_path = args.out.strip()
    if not out_path:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in want)[:80]
        out_path = os.path.join(
            os.path.dirname(args.input) or ".",
            f"filtered_{args.bucket}_{safe}.json",
        )

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)

    payload = {
        "meta": {
            "source": os.path.abspath(args.input),
            "event_type_query": want,
            "type_field": field,
            "bucket": args.bucket,
            "match": args.match,
            "matched_count": len(matched),
            "matched_per_bucket": per_bucket,
        },
        "samples": matched,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(json.dumps(payload["meta"], ensure_ascii=False, indent=2))
    print(f"Saved: {os.path.abspath(out_path)}")


if __name__ == "__main__":
    main()
