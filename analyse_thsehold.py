#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在带标签的评估集上扫描 decision_function 阈值，辅助选择 decision_threshold。

约定（与 waf_unsupervised.detect 一致）：
  - 分数越小越异常；
  - 判异条件：score < threshold → 异常(1)，否则正常(0)；
  - 标签列：0=正常，1=异常。

用法示例：
  python analyze_decision_threshold.py \\
    --model one_class_svm \\
    --eval-path data/waf_attack_labeled_2000_parsed.json \\
    --label-column label

  python analyze_decision_threshold.py -m one_class_svm -e data/eval.json -l label \\
    --mode quantile --quantile-points 101 \\
    --optimize f1 --csv-out artifacts/output/threshold_sweep.csv
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

# 保证可从项目根目录运行
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from waf_unsupervised.config import ModelConfig
from waf_unsupervised.model import WAFUnsupervisedModel


def _load_table(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".json":
        return pd.read_json(path)
    return pd.read_csv(path)


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[int, int, int, int, float, float, float, float]:
    """y_true / y_pred: 0 正常, 1 异常。返回 tn,fp,fn,tp, acc, prec, rec, f1"""
    tn = fp = fn = tp = 0
    for yt, yp in zip(y_true.astype(int), y_pred.astype(int)):
        if yt == 0 and yp == 0:
            tn += 1
        elif yt == 0 and yp == 1:
            fp += 1
        elif yt == 1 and yp == 0:
            fn += 1
        else:
            tp += 1
    n = tn + fp + fn + tp
    acc = (tp + tn) / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return tn, fp, fn, tp, acc, prec, rec, f1


def _youden_j(tpr: float, fpr: float) -> float:
    return tpr - fpr


def _build_threshold_grid(scores: np.ndarray, mode: str, steps: int, lo: Optional[float], hi: Optional[float]) -> np.ndarray:
    s = np.asarray(scores, dtype=float)
    smin, smax = float(np.min(s)), float(np.max(s))
    if lo is not None:
        smin = lo
    if hi is not None:
        smax = hi
    if smin >= smax:
        smax = smin + 1e-9
    if mode == "linear":
        return np.linspace(smin, smax, steps)
    if mode == "quantile":
        qs = np.linspace(0.0, 1.0, steps)
        return np.unique(np.quantile(s, qs))
    raise ValueError(f"未知 mode: {mode}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="扫描无监督模型决策阈值并输出指标")
    p.add_argument("--model", "-m", choices=["isolation_forest", "one_class_svm", "autoencoder"], default="one_class_svm")
    p.add_argument("--eval-path", "-e", required=True, help="带标签的评估数据 JSON/CSV")
    p.add_argument("--label-column", "-l", default="label", help="标签列名，0=正常 1=异常")
    p.add_argument(
        "--mode",
        choices=["linear", "quantile"],
        default="quantile",
        help="阈值网格：quantile 按分数分位数（推荐）；linear 在 [min,max] 或自定义区间均匀取点",
    )
    p.add_argument("--steps", type=int, default=101, help="linear 模式下的采样点数；quantile 下为分位段数")
    p.add_argument("--threshold-min", type=float, default=None, help="linear 时下界（默认可用分数最小值）")
    p.add_argument("--threshold-max", type=float, default=None, help="linear 时上界（默认可用分数最大值）")
    p.add_argument(
        "--optimize",
        choices=["f1", "youden", "fbeta", "accuracy"],
        default="f1",
        help="主优化目标：异常类 F1 / Youden J(TPR-FPR) / Fbeta / 准确率",
    )
    p.add_argument("--beta", type=float, default=1.0, help="optimize=fbeta 时的 beta（>1 更重视召回）")
    p.add_argument(
        "--target-recall",
        type=float,
        default=None,
        help="若设置，在满足召回>=该值的前提下最小化 FP（若无可行解则打印提示）",
    )
    p.add_argument("--csv-out", type=str, default="", help="将扫描结果写入 CSV")
    p.add_argument("--json-summary", type=str, default="", help="将最佳阈值摘要写入 JSON")
    p.add_argument("--top-k", type=int, default=8, help="打印按主指标排序的前 K 个阈值")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    eval_path = Path(args.eval_path)
    if not eval_path.is_file():
        print(f"[ERROR] 找不到评估文件: {eval_path}", file=sys.stderr)
        sys.exit(1)

    df = _load_table(eval_path).reset_index(drop=True)
    if args.label_column not in df.columns:
        print(f"[ERROR] 缺少标签列: {args.label_column}", file=sys.stderr)
        sys.exit(1)

    y_true = df[args.label_column].values.astype(int)
    uniq = set(np.unique(y_true).tolist())
    if not uniq.issubset({0, 1}):
        print(f"[ERROR] 标签列应仅为 0/1，当前取值: {sorted(uniq)}", file=sys.stderr)
        sys.exit(1)
    if len(uniq) < 2:
        print("[WARN] 标签只有一类，无法计算有意义的 Precision/Recall/F1，仍会输出分数分布与阈值扫描。")

    config = ModelConfig(model_type=args.model)
    model_path = Path(config.model_path())
    if not model_path.is_file():
        print(f"[ERROR] 找不到模型文件: {model_path}，请先训练对应模型。", file=sys.stderr)
        sys.exit(1)

    model = WAFUnsupervisedModel.load(str(model_path))
    scores = model.decision_function(df, label_column=None)
    scores = np.asarray(scores, dtype=float)

    grid = _build_threshold_grid(
        scores,
        mode=args.mode,
        steps=max(3, int(args.steps)),
        lo=args.threshold_min,
        hi=args.threshold_max,
    )

    rows: List[dict] = []
    for t in grid:
        y_pred = np.where(scores < t, 1, 0).astype(int)
        tn, fp, fn, tp, acc, prec, rec, f1 = _metrics(y_true, y_pred)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fbeta = (
            (1 + args.beta**2) * prec * rec / (args.beta**2 * prec + rec)
            if (args.beta**2 * prec + rec) > 0
            else 0.0
        )
        youden = _youden_j(tpr, fpr)
        rows.append(
            {
                "threshold": float(t),
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
                "accuracy": acc,
                "precision_anomaly": prec,
                "recall_anomaly": rec,
                "f1_anomaly": f1,
                f"fbeta_{args.beta}": fbeta,
                "youden_j": youden,
                "fpr": fpr,
                "tpr": tpr,
            }
        )

    dfm = pd.DataFrame(rows)

    def score_row(r: pd.Series) -> float:
        if args.optimize == "f1":
            return float(r["f1_anomaly"])
        if args.optimize == "youden":
            return float(r["youden_j"])
        if args.optimize == "fbeta":
            return float(r[f"fbeta_{args.beta}"])
        return float(r["accuracy"])

    dfm["_obj"] = dfm.apply(score_row, axis=1)
    best_idx = int(dfm["_obj"].idxmax())
    best = dfm.loc[best_idx].drop(labels=["_obj"])

    print("=" * 60)
    print("决策阈值扫描（score < threshold → 判为异常）")
    print("=" * 60)
    print(f"模型类型:     {args.model}")
    print(f"模型文件:     {model_path}")
    print(f"评估数据:     {eval_path}  (n={len(df)})")
    print(f"标签列:       {args.label_column}")
    print(f"正例(异常)数: {int((y_true == 1).sum())}  负例(正常)数: {int((y_true == 0).sum())}")
    print(f"分数 min/max: {float(scores.min()):.6f} / {float(scores.max()):.6f}")
    print(f"扫描模式:     {args.mode}  网格点数: {len(dfm)}")
    print(f"优化目标:     {args.optimize}" + (f" (beta={args.beta})" if args.optimize == "fbeta" else ""))
    print("-" * 60)
    print("【推荐】主指标最优阈值:")
    print(best.to_string())
    print("-" * 60)

    if args.target_recall is not None:
        tr = float(args.target_recall)
        feasible = dfm[dfm["recall_anomaly"] >= tr - 1e-12].copy()
        if feasible.empty:
            print(f"[WARN] 无法满足目标召回 >= {tr}，请降低目标或检查模型/数据。")
        else:
            j = int(feasible["fp"].idxmin())
            r = feasible.loc[j]
            print(f"【约束】召回 >= {tr} 且 FP 最小:")
            print(r.drop(labels=["_obj"], errors="ignore").to_string())
    print("-" * 60)
    print(f"按 {args.optimize} 排序的前 {args.top_k} 个阈值:")
    top = dfm.sort_values("_obj", ascending=False).head(args.top_k)
    cols = [
        "threshold",
        "precision_anomaly",
        "recall_anomaly",
        "f1_anomaly",
        "youden_j",
        "accuracy",
        "fp",
        "fn",
    ]
    print(top[cols].to_string(index=False))
    print("=" * 60)
    print("说明: 阈值调高 → 更不容易判异（召回降、假阳降）；阈值调低 → 更容易判异。")
    print("将 config.decision_threshold 或 detect --decision-threshold 设为推荐值后重新评估即可。")

    if args.csv_out:
        out = Path(args.csv_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        dfm.drop(columns=["_obj"], errors="ignore").to_csv(out, index=False, encoding="utf-8-sig")
        print(f"[INFO] 已写入 CSV: {out.resolve()}")

    if args.json_summary:
        outj = Path(args.json_summary)
        outj.parent.mkdir(parents=True, exist_ok=True)
        best_metrics: dict = {}
        for k, v in best.items():
            if isinstance(v, (np.floating, np.integer, float, int)):
                best_metrics[str(k)] = float(v)
            else:
                best_metrics[str(k)] = v
        summary = {
            "model": args.model,
            "model_path": str(model_path.resolve()),
            "eval_path": str(eval_path.resolve()),
            "label_column": args.label_column,
            "n_samples": int(len(df)),
            "n_anomaly": int((y_true == 1).sum()),
            "n_normal": int((y_true == 0).sum()),
            "score_min": float(scores.min()),
            "score_max": float(scores.max()),
            "optimize": args.optimize,
            "beta": float(args.beta) if args.optimize == "fbeta" else None,
            "best_threshold": float(best["threshold"]),
            "best_metrics": best_metrics,
        }
        with outj.open("w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"[INFO] 已写入 JSON: {outj.resolve()}")


if __name__ == "__main__":
    main()
