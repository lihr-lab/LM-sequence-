from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report

from .config import ModelConfig, data_config
from .data_cleaning import clean_binary_noise_rows, clean_noncompliant_protocol_rows
from .model import WAFUnsupervisedModel
from .whitelist import is_whitelisted_path


def _json_default_serializer(obj):
    """兜底处理 pandas/numpy/datetime 等 JSON 不可序列化类型。"""
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    if isinstance(obj, (pd.Timestamp, dt.datetime, dt.date)):
        return obj.isoformat()
    return str(obj)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WAF 流量模型检测脚本")
    parser.add_argument(
        "--model",
        choices=["isolation_forest", "one_class_svm", "autoencoder"],
        default="isolation_forest",
        help="选择使用的模型类型（需与训练时一致）",
    )
    parser.add_argument(
        "--detect-path",
        default=data_config.detect_path,
        help="检测数据文件路径",
    )
    parser.add_argument(
        "--decision-threshold",
        type=float,
        default=None,
        help="决策阈值（越小越敏感，负数提高检出率）",
    )
    parser.add_argument(
        "--pred-out",
        default="artifacts/output/detect_predictions.json",
        help="预测结果输出 JSON 路径",
    )
    parser.add_argument(
        "--label-column",
        default=data_config.label_column,
        help="标签列名（如果有则输出混淆矩阵）",
    )
    parser.add_argument(
        "--event-type",
        default="",
        help="仅检测指定 event_type 的样本（例如 access）；为空时检测全部",
    )
    parser.add_argument(
        "--append-event-type",
        default="",
        help="按数据出现顺序追加指定 event_type 的样本到检测集（例如 access）",
    )
    parser.add_argument(
        "--append-event-count",
        type=int,
        default=0,
        help="追加样本数量（默认 0，不追加）",
    )
    parser.add_argument(
        "--append-only-normal",
        action="store_true",
        help="追加样本时仅保留 label=0（需存在 label 列）",
    )
    parser.add_argument(
        "--sample-seed",
        type=int,
        default=42,
        help="兼容旧命令保留；检测样本上限现在按出现顺序截取，不再使用随机种子",
    )
    parser.add_argument(
        "--max-detect-samples",
        type=int,
        default=0,
        metavar="N",
        help="参与检测的样本数上限（0 表示使用全量）",
    )
    parser.add_argument(
        "--sample-out",
        default="artifacts/output/random.json",
        help="当启用样本上限时，截取后的检测数据输出路径（默认 artifacts/output/random.json）",
    )
    parser.add_argument(
        "--keep-binary-noise",
        action="store_true",
        help="保留疑似二进制乱码样本（默认会自动丢弃）",
    )
    parser.add_argument(
        "--keep-noncompliant-protocol",
        action="store_true",
        help='保留协议不合规样本（method=UNKNOWN 或 http_parsed 为空）；默认自动丢弃',
    )
    parser.add_argument(
        "--optimize-threshold-f1",
        action="store_true",
        help="若有标签列，则自动搜索使异常类 F1 最优的阈值并用于检测",
    )
    parser.add_argument(
        "--threshold-grid-size",
        type=int,
        default=201,
        metavar="N",
        help="自动阈值搜索的网格点数（默认 201）",
    )
    parser.add_argument(
        "--ae-device",
        default="",
        help="仅 autoencoder 检测时生效：覆盖推理设备（auto/cpu/cuda/cuda:0）",
    )
    return parser.parse_args()


def print_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray) -> None:
    """打印格式化的混淆矩阵"""
    labels = [0, 1]
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    
    print("\n" + "=" * 50)
    print("混淆矩阵 (Confusion Matrix)")
    print("=" * 50)
    print(f"{'':>12} | 预测正常(0) | 预测异常(1)")
    print("-" * 50)
    print(f"{'真实正常(0)':>12} | {cm[0][0]:>10} | {cm[0][1]:>10}")
    print(f"{'真实异常(1)':>12} | {cm[1][0]:>10} | {cm[1][1]:>10}")
    print("=" * 50)
    
    # 计算指标
    tn, fp, fn, tp = cm.ravel()
    total = tp + tn + fp + fn
    
    if total > 0:
        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n检测指标:")
        print(f"  Accuracy  (准确率):  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  Precision (精确率):  {precision:.4f} ({precision*100:.2f}%)")
        print(f"  Recall    (召回率):  {recall:.4f} ({recall*100:.2f}%)")
        print(f"  F1-Score  (F1分数):  {f1:.4f}")
        print("=" * 50)


def _confusion_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    total = tp + tn + fp + fn
    acc = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "tn": float(tn),
        "fp": float(fp),
        "fn": float(fn),
        "tp": float(tp),
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }


def _best_threshold_by_f1(scores: np.ndarray, y_true: np.ndarray, grid_size: int) -> tuple[float, dict[str, float]]:
    grid_n = max(5, int(grid_size))
    s = np.asarray(scores, dtype=float)
    lo, hi = float(np.min(s)), float(np.max(s))
    if not np.isfinite(lo) or not np.isfinite(hi):
        return 0.0, {"f1": 0.0, "precision": 0.0, "recall": 0.0, "tn": 0.0, "fp": 0.0, "fn": 0.0, "tp": 0.0, "accuracy": 0.0}
    if hi <= lo:
        hi = lo + 1e-9

    thresholds = np.unique(np.quantile(s, np.linspace(0.0, 1.0, grid_n)))
    best_t = float(thresholds[0])
    best_m = None
    for t in thresholds:
        pred = np.where(s < float(t), 1, 0).astype(int)
        m = _confusion_metrics(y_true, pred)
        if best_m is None:
            best_t, best_m = float(t), m
            continue
        # 主目标：F1 最大；并列时优先 recall，再优先更低 FP
        if (
            m["f1"] > best_m["f1"]
            or (m["f1"] == best_m["f1"] and m["recall"] > best_m["recall"])
            or (m["f1"] == best_m["f1"] and m["recall"] == best_m["recall"] and m["fp"] < best_m["fp"])
        ):
            best_t, best_m = float(t), m
    return best_t, best_m or {"f1": 0.0, "precision": 0.0, "recall": 0.0, "tn": 0.0, "fp": 0.0, "fn": 0.0, "tp": 0.0, "accuracy": 0.0}


def main() -> None:
    args = parse_args()
    
    # 加载配置和模型
    config = ModelConfig(model_type=args.model)
    model_path = config.model_path()
    
    # 加载检测数据
    try:
        path = Path(args.detect_path)
        if path.suffix.lower() == ".json":
            df = pd.read_json(path)
        else:
            df = pd.read_csv(path)
    except FileNotFoundError:
        print(f"[ERROR] 找不到检测数据文件: {args.detect_path}", file=sys.stderr)
        sys.exit(1)
    df_all = df.copy()

    if not args.keep_binary_noise:
        before_n = len(df)
        df, dropped = clean_binary_noise_rows(df, http_col="http")
        if dropped > 0:
            print(f"[INFO] 检测数据清洗: 丢弃二进制乱码样本 {dropped} 条 ({before_n} -> {len(df)})")
        if len(df) == 0:
            print("[ERROR] 清洗后检测数据为空，请检查输入数据或使用 --keep-binary-noise", file=sys.stderr)
            sys.exit(1)
        # 与 df 保持同一清洗策略，避免追加源包含已判定脏数据
        df_all, _ = clean_binary_noise_rows(df_all, http_col="http")

    if not args.keep_noncompliant_protocol:
        before_n = len(df)
        df, dropped_stats = clean_noncompliant_protocol_rows(
            df,
            method_col="method",
            parsed_col="http_parsed",
            unknown_method_value="UNKNOWN",
        )
        dropped_total = int(dropped_stats.get("dropped_total", 0))
        if dropped_total > 0:
            print(
                "[INFO] 检测数据清洗: 丢弃协议不合规样本 "
                f"{dropped_total} 条 ({before_n} -> {len(df)}), "
                f"其中 method=UNKNOWN: {int(dropped_stats.get('dropped_method_unknown', 0))}, "
                f"http_parsed 为空: {int(dropped_stats.get('dropped_http_parsed_empty', 0))}"
            )
        if len(df) == 0:
            print("[ERROR] 清洗后检测数据为空，请检查输入数据或使用 --keep-noncompliant-protocol", file=sys.stderr)
            sys.exit(1)
        # 与 df 保持同一清洗策略，避免追加源包含协议不合规样本
        df_all, _ = clean_noncompliant_protocol_rows(
            df_all,
            method_col="method",
            parsed_col="http_parsed",
            unknown_method_value="UNKNOWN",
        )

    # 可选：按 event_type 过滤后再检测
    if args.event_type:
        if "event_type" not in df.columns:
            print(
                f"[ERROR] 指定了 --event-type={args.event_type}，但数据中不存在 event_type 字段",
                file=sys.stderr,
            )
            sys.exit(1)
        before_n = len(df)
        df = df[df["event_type"].astype(str).str.strip().str.lower() == args.event_type.strip().lower()].reset_index(
            drop=True
        )
        if len(df) == 0:
            print(f"[ERROR] event_type={args.event_type} 过滤后无可检测样本", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] event_type 过滤: {before_n} -> {len(df)} (event_type={args.event_type})")

    # 可选：按出现顺序追加某类 event_type（例如 access）样本，便于与目标攻击类做混合检测
    if args.append_event_count > 0:
        if "event_type" not in df_all.columns:
            print(
                "[ERROR] 指定了追加样本参数，但数据中不存在 event_type 字段",
                file=sys.stderr,
            )
            sys.exit(1)
        if not args.append_event_type:
            print(
                "[ERROR] 当 --append-event-count > 0 时，必须设置 --append-event-type",
                file=sys.stderr,
            )
            sys.exit(1)

        append_mask = (
            df_all["event_type"].astype(str).str.strip().str.lower()
            == args.append_event_type.strip().lower()
        )
        append_df = df_all[append_mask].copy()

        if args.append_only_normal:
            label_column = args.label_column
            if label_column and label_column in append_df.columns:
                append_df = append_df[append_df[label_column] == 0]
            else:
                print(
                    f"[WARN] --append-only-normal 已设置，但未找到标签列 '{label_column}'，将忽略该约束",
                    file=sys.stderr,
                )

        if args.event_type:
            target_et = args.event_type.strip().lower()
            append_df = append_df[
                append_df["event_type"].astype(str).str.strip().str.lower() != target_et
            ]

        if len(append_df) == 0:
            print(
                f"[WARN] 无可追加样本 (event_type={args.append_event_type})，跳过追加"
            )
        else:
            n_take = min(int(args.append_event_count), len(append_df))
            sampled = append_df.head(n_take)
            before_mix = len(df)
            df = pd.concat([df, sampled], ignore_index=True)
            print(
                f"[INFO] 追加样本: +{len(sampled)} (event_type={args.append_event_type}, mode=first)，"
                f"总样本: {before_mix} -> {len(df)}"
            )

    sampled_applied = False

    if args.max_detect_samples < 0:
        print("[ERROR] --max-detect-samples 不能为负数", file=sys.stderr)
        sys.exit(1)
    if args.max_detect_samples > 0 and len(df) > args.max_detect_samples:
        before_n = len(df)
        df = df.head(int(args.max_detect_samples)).reset_index(drop=True)
        sampled_applied = True
        print(
            f"[INFO] 检测样本顺序截取: {before_n} -> {len(df)} "
            f"(max_detect_samples={args.max_detect_samples}, mode=first)"
        )

    if sampled_applied and args.sample_out:
        sample_out = Path(args.sample_out)
        sample_out.parent.mkdir(parents=True, exist_ok=True)
        with sample_out.open("w", encoding="utf-8") as f:
            json.dump(
                df.to_dict(orient="records"),
                f,
                ensure_ascii=False,
                indent=2,
                default=_json_default_serializer,
            )
        print(f"[INFO] 截取后的检测数据已保存到: {sample_out}")
    
    # 加载模型
    try:
        model = WAFUnsupervisedModel.load(model_path)
    except FileNotFoundError:
        print(f"[ERROR] 找不到已训练模型文件: {model_path}，请先运行 train.py 训练模型。", file=sys.stderr)
        sys.exit(1)

    # 可选：覆盖 autoencoder 推理设备（优先级高于模型保存时 device_str）
    if args.ae_device and args.model == "autoencoder":
        ae = getattr(model, "model", None)
        if ae is None:
            print("[WARN] --ae-device 已设置，但当前加载模型为空，忽略设备覆盖。")
        elif not hasattr(ae, "device_str"):
            print("[WARN] --ae-device 已设置，但当前模型不是 Autoencoder，忽略设备覆盖。")
        else:
            import torch

            wanted = str(args.ae_device).strip()
            if wanted.lower() in ("", "auto"):
                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            else:
                device = torch.device(wanted)

            ae.device_str = wanted
            ae._device = device
            if getattr(ae, "_net", None) is not None:
                ae._net = ae._net.to(device)
                ae._net.eval()
            print(f"[INFO] Autoencoder 推理设备覆盖: {device}")
    
    # 决策阈值：优先使用命令行，其次使用已加载模型中的阈值，最后回退配置值。
    # 这样可避免“训练时/模型内阈值”与“配置文件默认阈值”不一致导致全量误判。
    model_threshold = None
    if hasattr(model, "model") and getattr(model, "model", None) is not None:
        model_threshold = getattr(model.model, "decision_threshold", None)
    threshold_source = "cli"
    if args.decision_threshold is not None:
        threshold = float(args.decision_threshold)
    elif args.model == "autoencoder":
        # Autoencoder 的 decision_function 为 (mse_ref - mse)，0 通常是更稳妥的默认分界。
        threshold = 0.0
        threshold_source = "autoencoder_default_0"
        if model_threshold is not None and abs(float(model_threshold)) > 1e-12:
            print(
                f"[WARN] 检测阶段未显式指定阈值；autoencoder 默认使用 0.0，"
                f"忽略模型内阈值 {float(model_threshold):.6f}。"
            )
    elif model_threshold is not None:
        threshold = float(model_threshold)
        threshold_source = "model_saved"
    else:
        threshold = float(config.decision_threshold)
        threshold_source = "config_default"
    
    print(f"[INFO] 模型: {args.model}")
    print(f"[INFO] 模型文件: {model_path}")
    print(f"[INFO] 决策阈值: {threshold} (source={threshold_source})")
    print(f"[INFO] 检测数据: {args.detect_path}，样本数: {len(df)}")
    
    # 获取决策分数
    try:
        scores = model.decision_function(df, label_column=None)
        if args.optimize_threshold_f1:
            label_column = args.label_column
            if not (label_column and label_column in df.columns):
                print("[WARN] --optimize-threshold-f1 已开启，但未找到标签列，继续使用当前阈值。")
            else:
                y_true_scan = df[label_column].values.astype(int)
                uniq = set(np.unique(y_true_scan).tolist())
                if not uniq.issubset({0, 1}) or len(uniq) < 2:
                    print("[WARN] --optimize-threshold-f1 已开启，但标签不是二分类或只有一类，继续使用当前阈值。")
                else:
                    best_t, best_m = _best_threshold_by_f1(scores, y_true_scan, args.threshold_grid_size)
                    threshold = float(best_t)
                    threshold_source = "f1_optimal"
                    print(
                        "[INFO] F1最优阈值搜索完成: "
                        f"threshold={threshold:.6f}, f1={best_m['f1']:.4f}, "
                        f"precision={best_m['precision']:.4f}, recall={best_m['recall']:.4f}, "
                        f"tn={int(best_m['tn'])}, fp={int(best_m['fp'])}, fn={int(best_m['fn'])}, tp={int(best_m['tp'])}"
                    )
                    print(f"[INFO] 使用阈值: {threshold:.6f} (source={threshold_source})")

        y_pred = np.where(scores < threshold, -1, 1)
        if len(scores) > 0:
            print(
                "[INFO] 分数统计: "
                f"min={float(np.min(scores)):.6f}, "
                f"p50={float(np.percentile(scores, 50)):.6f}, "
                f"p90={float(np.percentile(scores, 90)):.6f}, "
                f"max={float(np.max(scores)):.6f}"
            )
    except AttributeError:
        # 若不支持 decision_function，直接预测
        print("[WARN] 模型不支持 decision_function，使用 predict 方法")
        y_pred = model.predict(df, label_column=None)
        scores = np.zeros(len(df))
    
    # 转换为 0/1（1=异常）
    anomaly_pred = np.where(y_pred == -1, 1, 0)
    anomaly_pred_raw = anomaly_pred.copy()

    whitelist_mask = np.array([is_whitelisted_path(row) for _, row in df.iterrows()], dtype=bool)
    whitelist_suppressed = int(np.sum((anomaly_pred == 1) & whitelist_mask))
    if whitelist_suppressed > 0:
        anomaly_pred = np.where(whitelist_mask, 0, anomaly_pred)
        print(f"[INFO] 白名单抑制误报: {whitelist_suppressed} 条 (final is_anomaly=False, raw 保留)")
    
    # 保存预测结果
    out_path = Path(args.pred_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    predictions = []
    for i, (pred, raw_pred_binary, score) in enumerate(
        zip(anomaly_pred.tolist(), anomaly_pred_raw.tolist(), scores.tolist())
    ):
        whitelisted = bool(whitelist_mask[i])
        predictions.append(
            {
                "index": i,
                "is_anomaly": bool(pred == 1),
                "is_anomaly_raw": bool(raw_pred_binary == 1),
                "whitelisted": whitelisted,
                "whitelist_reason": "path_whitelist" if whitelisted else "",
                "raw_pred": int(y_pred[i]),
                "score": float(score),
                "threshold": float(threshold),
                "threshold_source": threshold_source,
            }
        )
    
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(
            predictions,
            f,
            ensure_ascii=False,
            indent=2,
            default=_json_default_serializer,
        )
    
    # 输出统计信息
    anomaly_count = anomaly_pred.sum()
    normal_count = len(anomaly_pred) - anomaly_count
    print(f"[INFO] 检测完成: 正常={normal_count}, 异常={anomaly_count}, 异常率={anomaly_count/len(anomaly_pred)*100:.2f}%")
    print(f"[INFO] 预测结果已保存到: {out_path}")
    
    # ========== 混淆矩阵输出（修复版） ==========
    label_column = args.label_column
    if label_column and label_column in df.columns:
        y_true = df[label_column].values
        unique_labels = np.unique(y_true)
        
        if len(unique_labels) == 1:
            print(f"\n[WARN] 检测数据中只有 {unique_labels[0]} 类样本，无法计算完整指标")
            if unique_labels[0] == 1:
                print("       (只有异常样本时，模型全判异常会显示100%准确率，但这是假象)")
            elif unique_labels[0] == 0:
                print("       (只有正常样本时，模型全判正常会显示100%准确率，但这是假象)")
            
            # 简单输出
            cm = confusion_matrix(y_true, anomaly_pred, labels=[0, 1])
            print(f"\n混淆矩阵:\n{cm}")
            print(f"真实样本数: {len(y_true)}")
            print(f"预测异常数: {anomaly_pred.sum()}")
        else:
            print_confusion_matrix(y_true, anomaly_pred)
            print("\n详细分类报告:")
            print(classification_report(y_true, anomaly_pred, digits=4, target_names=["正常", "异常"]))
    else:
        print(f"[INFO] 未找到标签列 '{label_column}'，跳过混淆矩阵计算")


if __name__ == "__main__":
    main()
