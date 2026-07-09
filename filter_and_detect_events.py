#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 detection 文件中筛选事件，并可按指定 event_type 做异常检测。

功能：
1) 从输入文件中保留最多 N 条指定事件类型（默认 access）并写出新文件；
2) 可选：仅对指定事件类型样本做异常检测（调用现有无监督模型）。

说明：
- 支持 JSON 数组（超大文件流式解析）与 JSONL；
- 同时兼容字段名 event_type / event_typr（部分数据有拼写差异）。
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any, Dict, Iterator, List

import numpy as np
import pandas as pd

from waf_unsupervised.config import ModelConfig
from waf_unsupervised.model import WAFUnsupervisedModel


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="筛选 detection 事件并按类型执行异常检测")
    p.add_argument(
        "--input-path",
        required=True,
        help="输入检测文件路径（JSON 数组或 JSONL）",
    )
    p.add_argument(
        "--keep-event-type",
        default="access",
        help="用于保留样本的事件类型（默认 access）",
    )
    p.add_argument(
        "--keep-limit",
        type=int,
        default=1000,
        help="最多保留多少条（默认 1000）",
    )
    p.add_argument(
        "--keep-output",
        default="artifacts/output/detection_access_1000.json",
        help="保留样本输出路径（JSON）",
    )
    p.add_argument(
        "--detect-event-type",
        default="access",
        help="要做异常检测的事件类型（默认 access）",
    )
    p.add_argument(
        "--skip-detect",
        action="store_true",
        help="仅筛选输出，不做异常检测",
    )
    p.add_argument(
        "--model",
        choices=["isolation_forest", "one_class_svm", "autoencoder"],
        default="autoencoder",
        help="异常检测模型类型（需与训练时一致）",
    )
    p.add_argument(
        "--decision-threshold",
        type=float,
        default=None,
        help="检测阈值；不传则使用与 waf_unsupervised.detect 相同的默认策略",
    )
    p.add_argument(
        "--pred-out",
        default="artifacts/output/detect_event_type_predictions.json",
        help="异常检测结果输出路径（JSON）",
    )
    p.add_argument(
        "--sample-mode",
        choices=["first", "random"],
        default="first",
        help="保留策略：first=按出现顺序，random=蓄水池抽样",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="random 模式随机种子",
    )
    return p.parse_args()


def _event_type_of(rec: Dict[str, Any]) -> str:
    # 兼容 event_type / event_typr 两种字段
    v = rec.get("event_type", rec.get("event_typr", ""))
    return "" if v is None else str(v).strip()


def _iter_json_array(path: Path) -> Iterator[Dict[str, Any]]:
    """流式解析顶层 JSON 数组，避免一次性加载超大文件。"""
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        buf = ""
        pos = 0

        # 找到数组起始 '['
        while True:
            if pos >= len(buf):
                chunk = f.read(1024 * 1024)
                if not chunk:
                    raise ValueError("输入文件为空或不是有效 JSON")
                buf += chunk
            while pos < len(buf) and buf[pos].isspace():
                pos += 1
            if pos < len(buf):
                break
        if buf[pos] != "[":
            raise ValueError("JSON 不是数组格式")
        pos += 1

        while True:
            while True:
                if pos >= len(buf):
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        return
                    buf = buf[pos:]
                    pos = 0
                    buf += chunk
                    continue
                if buf[pos].isspace() or buf[pos] == ",":
                    pos += 1
                    continue
                break

            if pos < len(buf) and buf[pos] == "]":
                return

            while True:
                try:
                    obj, end = decoder.raw_decode(buf, pos)
                    pos = end
                    if isinstance(obj, dict):
                        yield obj
                    else:
                        # 若数组里不是对象，跳过
                        continue
                    break
                except json.JSONDecodeError:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        return
                    buf = buf[pos:]
                    pos = 0
                    buf += chunk


def _iter_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def iter_records(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        first = ""
        while True:
            ch = f.read(1)
            if not ch:
                break
            if ch.isspace():
                continue
            first = ch
            break
    if first == "[":
        yield from _iter_json_array(path)
    else:
        yield from _iter_jsonl(path)


def _pick_kept_samples(
    records: Iterator[Dict[str, Any]],
    keep_event_type: str,
    keep_limit: int,
    sample_mode: str,
    seed: int,
) -> List[Dict[str, Any]]:
    et = keep_event_type.lower().strip()
    limit = max(0, int(keep_limit))
    if limit == 0:
        return []

    if sample_mode == "first":
        kept: List[Dict[str, Any]] = []
        for rec in records:
            if _event_type_of(rec).lower() != et:
                continue
            kept.append(rec)
            if len(kept) >= limit:
                break
        return kept

    rnd = random.Random(seed)
    kept = []
    seen = 0
    for rec in records:
        if _event_type_of(rec).lower() != et:
            continue
        seen += 1
        if len(kept) < limit:
            kept.append(rec)
        else:
            j = rnd.randint(1, seen)
            if j <= limit:
                kept[j - 1] = rec
    return kept


def _resolve_threshold(args: argparse.Namespace, model: WAFUnsupervisedModel, cfg: ModelConfig) -> tuple[float, str]:
    model_threshold = None
    if hasattr(model, "model") and getattr(model, "model", None) is not None:
        model_threshold = getattr(model.model, "decision_threshold", None)

    if args.decision_threshold is not None:
        return float(args.decision_threshold), "cli"
    if args.model == "autoencoder":
        return 0.0, "autoencoder_default_0"
    if model_threshold is not None:
        return float(model_threshold), "model_saved"
    return float(cfg.decision_threshold), "config_default"


def main() -> None:
    args = parse_args()
    in_path = Path(args.input_path)
    if not in_path.is_file():
        raise FileNotFoundError(f"找不到输入文件: {in_path}")

    records_iter = iter_records(in_path)
    kept = _pick_kept_samples(
        records_iter,
        keep_event_type=args.keep_event_type,
        keep_limit=args.keep_limit,
        sample_mode=args.sample_mode,
        seed=args.seed,
    )

    keep_out = Path(args.keep_output)
    keep_out.parent.mkdir(parents=True, exist_ok=True)
    with keep_out.open("w", encoding="utf-8") as f:
        json.dump(kept, f, ensure_ascii=False, indent=2)

    print(
        f"[INFO] 已保留事件类型={args.keep_event_type!r} 的样本 {len(kept)} 条，输出: {keep_out}"
    )

    if args.skip_detect:
        print("[INFO] 已按 --skip-detect 跳过异常检测")
        return

    detect_et = args.detect_event_type.lower().strip()
    detect_rows = [r for r in kept if _event_type_of(r).lower() == detect_et]
    if not detect_rows:
        print(f"[WARN] 保留样本中无事件类型 {args.detect_event_type!r}，跳过检测")
        return

    df = pd.DataFrame(detect_rows)
    cfg = ModelConfig(model_type=args.model)
    model_path = cfg.model_path()
    model = WAFUnsupervisedModel.load(model_path)
    threshold, threshold_source = _resolve_threshold(args, model, cfg)

    scores = model.decision_function(df, label_column=None)
    scores = np.asarray(scores, dtype=float)
    y_pred = np.where(scores < threshold, -1, 1)
    anomaly_pred = np.where(y_pred == -1, 1, 0)

    pred_out = Path(args.pred_out)
    pred_out.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for i, rec in enumerate(detect_rows):
        item = dict(rec)
        item["_detect_index"] = i
        item["_event_type"] = _event_type_of(rec)
        item["_score"] = float(scores[i])
        item["_raw_pred"] = int(y_pred[i])
        item["_is_anomaly"] = bool(anomaly_pred[i] == 1)
        results.append(item)
    with pred_out.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    anomaly_count = int(anomaly_pred.sum())
    total = int(len(anomaly_pred))
    print(f"[INFO] 检测模型: {args.model}")
    print(f"[INFO] 决策阈值: {threshold} (source={threshold_source})")
    print(
        f"[INFO] 检测事件类型={args.detect_event_type!r} 样本数={total}，"
        f"异常={anomaly_count}，正常={total - anomaly_count}"
    )
    print(f"[INFO] 检测结果已输出: {pred_out}")


if __name__ == "__main__":
    main()
