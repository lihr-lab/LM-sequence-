from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from .config import ModelConfig, data_config
from .data_cleaning import (
    _is_empty_http_parsed,
    clean_binary_noise_rows,
    clean_empty_path_rows,
    clean_noncompliant_protocol_rows,
    is_binary_noise,
)
from .features import _resolve_feature_n_jobs
from .model import train_model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WAF 无监督模型训练脚本")
    parser.add_argument(
        "--model",
        choices=["isolation_forest", "one_class_svm", "autoencoder"],
        default="isolation_forest",
        help="选择无监督模型类型",
    )
    parser.add_argument(
        "--train-path",
        default=data_config.train_path,
        help="训练数据文件路径（默认为 config 中指定路径）",
    )
    parser.add_argument(
        "--label-column",
        default="",
        help="训练数据中的标签列名（如纯正常样本可留空）",
    )
    parser.add_argument(
        "--max-train-samples",
        type=int,
        default=0,
        metavar="N",
        help="参与训练的样本数上限（0 表示使用全量）",
    )
    parser.add_argument(
        "--sample-seed",
        type=int,
        default=42,
        help="样本抽样随机种子（用于 --max-train-samples）",
    )
    parser.add_argument(
        "--keep-binary-noise",
        action="store_true",
        help="保留疑似二进制乱码样本（默认会自动丢弃）",
    )
    parser.add_argument(
        "--keep-noncompliant-protocol",
        action="store_true",
        help="保留协议不合规样本（method=UNKNOWN 或 http_parsed 为空）；默认会自动丢弃，与检测阶段保持一致",
    )
    parser.add_argument(
        "--keep-empty-path",
        action="store_true",
        help="保留 URL path 为空的样本；默认会自动丢弃，避免训练集学习空 path 分布",
    )
    parser.add_argument(
        "--augment-normal-detect-path",
        default=data_config.detect_path,
        help="用于补充训练集的检测数据路径（默认使用 config 中的 detection_1.json）",
    )
    parser.add_argument(
        "--augment-normal-count",
        type=int,
        default=50000,
        metavar="N",
        help="从检测数据中抽取 label=0 的干净正常样本追加到训练集；0 表示不追加（默认 50000）",
    )
    parser.add_argument(
        "--augment-label-column",
        default=data_config.label_column,
        help="检测数据中的正常/异常标签列名（默认 label，0 表示正常）",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="预估异常比例（IsolationForest 使用）",
    )
    parser.add_argument(
        "--ocsvm-nu",
        type=float,
        default=0.05,
        help="One-Class SVM 的 nu 参数",
    )
    parser.add_argument(
        "--ocsvm-backend",
        choices=["sklearn", "thundersvm"],
        default="sklearn",
        help="One-Class SVM 后端：sklearn(CPU) 或 thundersvm(GPU，需安装 https://github.com/Xtra-Computing/thundersvm)",
    )
    parser.add_argument(
        "--thundersvm-gpu-id",
        type=int,
        default=0,
        help="ThunderSVM 使用的 GPU 编号",
    )
    parser.add_argument(
        "--decision-threshold",
        type=float,
        default=None,
        help="决策阈值（默认使用 config 中的值，负数提高检出率）",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="强制显示特征提取进度条（默认：交互终端且样本≥500 时已自动显示）",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="关闭特征提取进度条",
    )
    parser.add_argument(
        "--feature-jobs",
        type=int,
        default=None,
        metavar="N",
        help="特征提取并行进程数（默认：环境变量 WAF_FEATURE_N_JOBS，否则为 CPU 核数-1 且不超过 16；设为 1 则禁用并行）",
    )
    parser.add_argument(
        "--train-progress",
        action="store_true",
        help="强制显示训练总进度 / 拟合 ETA 进度条（默认：交互终端开启）",
    )
    parser.add_argument(
        "--no-train-progress",
        action="store_true",
        help="关闭训练总进度与拟合预估进度条",
    )
    parser.add_argument(
        "--ae-hidden",
        type=int,
        default=None,
        metavar="N",
        help="自编码器隐层宽度（默认 config.ae_hidden_dim）",
    )
    parser.add_argument(
        "--ae-latent",
        type=int,
        default=None,
        metavar="N",
        help="自编码器瓶颈维数（默认 config.ae_latent_dim）",
    )
    parser.add_argument(
        "--ae-epochs",
        type=int,
        default=None,
        metavar="N",
        help="自编码器训练轮数（默认 config.ae_epochs）",
    )
    parser.add_argument(
        "--ae-batch-size",
        type=int,
        default=None,
        metavar="N",
        help="自编码器 batch 大小（默认 config.ae_batch_size）",
    )
    parser.add_argument(
        "--ae-lr",
        type=float,
        default=None,
        help="自编码器学习率（默认 config.ae_lr）",
    )
    parser.add_argument(
        "--ae-mse-percentile",
        type=float,
        default=None,
        help="训练集重构 MSE 参考分位数，用于 decision_function 标定（默认 90）",
    )
    parser.add_argument(
        "--ae-max-train-samples",
        type=int,
        default=None,
        metavar="N",
        help="自编码器最多使用的训练样本数，0 表示全量（大图可 subsample 加速）",
    )
    parser.add_argument(
        "--ae-device",
        default=None,
        help='自编码器设备：auto / cpu / cuda / cuda:0（默认 auto）',
    )
    parser.add_argument(
        "--ae-loss-alpha",
        type=float,
        default=None,
        help="自编码器连续特征重构损失权重 alpha（MSE）",
    )
    parser.add_argument(
        "--ae-loss-beta",
        type=float,
        default=None,
        help="自编码器二值特征重构损失权重 beta（BCE）",
    )
    parser.add_argument(
        "--ae-input-dropout",
        type=float,
        default=None,
        help="自编码器训练输入 dropout 概率（用于去噪）",
    )
    parser.add_argument(
        "--ae-binary-flip-prob",
        type=float,
        default=None,
        help="自编码器训练时二值位 0->1 翻转概率（用于稀疏位去噪）",
    )
    return parser.parse_args()


def _iter_json_array(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[dict[str, Any]]:
    """
    流式读取 JSON 数组文件，避免为了抽样检测集正常样本而一次性加载数 GB JSON。
    """
    decoder = json.JSONDecoder()
    buf = ""
    pos = 0
    started = False
    with path.open("r", encoding="utf-8") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf += chunk
            while True:
                n = len(buf)
                while pos < n and buf[pos].isspace():
                    pos += 1
                if not started:
                    if pos < n and buf[pos] == "[":
                        pos += 1
                        started = True
                    else:
                        break
                while pos < n and buf[pos].isspace():
                    pos += 1
                if pos < n and buf[pos] == ",":
                    pos += 1
                    continue
                if pos < n and buf[pos] == "]":
                    return
                try:
                    obj, end = decoder.raw_decode(buf, pos)
                except json.JSONDecodeError:
                    break
                if isinstance(obj, dict):
                    yield obj
                pos = end
            if pos > 0:
                buf = buf[pos:]
                pos = 0


def _record_path(record: dict[str, Any]) -> str:
    parsed = record.get("http_parsed")
    if isinstance(parsed, dict):
        path = parsed.get("path")
        if path is not None:
            return str(path)
        url = parsed.get("url")
        if isinstance(url, str) and url:
            return url.split("?", 1)[0]
    path = record.get("path", "")
    return "" if path is None else str(path)


def _is_clean_training_record(
    record: dict[str, Any],
    *,
    keep_binary_noise: bool,
    keep_noncompliant_protocol: bool,
    keep_empty_path: bool,
) -> bool:
    if not keep_binary_noise and is_binary_noise(record.get("http")):
        return False
    if not keep_noncompliant_protocol:
        method_unknown = str(record.get("method", "")).strip().upper() == "UNKNOWN"
        parsed_empty = _is_empty_http_parsed(record.get("http_parsed"))
        if method_unknown or parsed_empty:
            return False
    if not keep_empty_path and not _record_path(record).strip():
        return False
    return True


def _sample_normal_records_from_detection(
    detect_path: Path,
    *,
    sample_size: int,
    seed: int,
    label_column: str,
    keep_binary_noise: bool,
    keep_noncompliant_protocol: bool,
    keep_empty_path: bool,
) -> tuple[pd.DataFrame, dict[str, int]]:
    if sample_size <= 0:
        return pd.DataFrame(), {"seen": 0, "sampled": 0}

    rng = random.Random(seed)
    sample: list[dict[str, Any]] = []
    seen = 0
    total = 0
    for record in _iter_json_array(detect_path):
        total += 1
        if label_column and str(record.get(label_column, "")).strip() != "0":
            continue
        if not _is_clean_training_record(
            record,
            keep_binary_noise=keep_binary_noise,
            keep_noncompliant_protocol=keep_noncompliant_protocol,
            keep_empty_path=keep_empty_path,
        ):
            continue

        seen += 1
        if len(sample) < sample_size:
            sample.append(record)
        else:
            j = rng.randrange(seen)
            if j < sample_size:
                sample[j] = record

    stats = {"total_scanned": total, "seen": seen, "sampled": len(sample)}
    return pd.DataFrame(sample), stats


def _sample_records_from_json(path: Path, *, sample_size: int, seed: int) -> tuple[pd.DataFrame, int]:
    rng = random.Random(seed)
    sample: list[dict[str, Any]] = []
    seen = 0
    for record in _iter_json_array(path):
        seen += 1
        if len(sample) < sample_size:
            sample.append(record)
        else:
            j = rng.randrange(seen)
            if j < sample_size:
                sample[j] = record
    return pd.DataFrame(sample), seen


def main() -> None:
    args = parse_args()

    if args.progress and args.no_progress:
        print("[WARN] 同时指定 --progress 与 --no-progress，将关闭进度条。", file=sys.stderr)
        args.no_progress = True
        args.progress = False

    if args.train_progress and args.no_train_progress:
        print("[WARN] 同时指定 --train-progress 与 --no-train-progress，将关闭训练总进度。", file=sys.stderr)
        args.no_train_progress = True
        args.train_progress = False

    if args.progress:
        os.environ["WAF_FEATURE_PROGRESS"] = "1"
    elif args.no_progress:
        os.environ["WAF_FEATURE_PROGRESS"] = "0"

    if args.train_progress:
        os.environ["WAF_TRAIN_PROGRESS"] = "1"
    elif args.no_train_progress:
        os.environ["WAF_TRAIN_PROGRESS"] = "0"

    if args.feature_jobs is not None:
        os.environ["WAF_FEATURE_N_JOBS"] = str(max(1, int(args.feature_jobs)))

    label_column = args.label_column or None

    try:
        path = Path(args.train_path)
        if path.suffix.lower() == ".json":
            if args.max_train_samples > 0:
                df_train, total_seen = _sample_records_from_json(
                    path,
                    sample_size=int(args.max_train_samples),
                    seed=int(args.sample_seed),
                )
                print(
                    f"[INFO] 训练 JSON 流式抽样读取: {total_seen} -> {len(df_train)} "
                    f"(max_train_samples={args.max_train_samples}, seed={args.sample_seed})"
                )
            else:
                df_train = pd.read_json(path)
        else:
            df_train = pd.read_csv(path)
    except FileNotFoundError:
        print(f"[ERROR] 找不到训练数据文件: {args.train_path}", file=sys.stderr)
        sys.exit(1)
    except MemoryError:
        print(
            "[ERROR] 训练 JSON 过大，pd.read_json 内存不足。"
            "请使用 --max-train-samples N 启用流式抽样读取。",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.keep_binary_noise:
        before_n = len(df_train)
        df_train, dropped = clean_binary_noise_rows(df_train, http_col="http")
        if dropped > 0:
            print(f"[INFO] 训练数据清洗: 丢弃二进制乱码样本 {dropped} 条 ({before_n} -> {len(df_train)})")
        if len(df_train) == 0:
            print("[ERROR] 清洗后训练数据为空，请检查输入数据或使用 --keep-binary-noise", file=sys.stderr)
            sys.exit(1)

    if not args.keep_noncompliant_protocol:
        before_n = len(df_train)
        df_train, dropped_stats = clean_noncompliant_protocol_rows(
            df_train,
            method_col="method",
            parsed_col="http_parsed",
            unknown_method_value="UNKNOWN",
        )
        dropped_total = int(dropped_stats.get("dropped_total", 0))
        if dropped_total > 0:
            print(
                "[INFO] 训练数据清洗: 丢弃协议不合规样本 "
                f"{dropped_total} 条 ({before_n} -> {len(df_train)}), "
                f"其中 method=UNKNOWN: {int(dropped_stats.get('dropped_method_unknown', 0))}, "
                f"http_parsed 为空: {int(dropped_stats.get('dropped_http_parsed_empty', 0))}"
            )
        if len(df_train) == 0:
            print(
                "[ERROR] 协议清洗后训练数据为空，请检查输入数据或使用 --keep-noncompliant-protocol",
                file=sys.stderr,
            )
            sys.exit(1)

    if not args.keep_empty_path:
        before_n = len(df_train)
        df_train, dropped = clean_empty_path_rows(df_train, path_col="path", parsed_col="http_parsed")
        if dropped > 0:
            print(f"[INFO] 训练数据清洗: 丢弃 path 为空样本 {dropped} 条 ({before_n} -> {len(df_train)})")
        if len(df_train) == 0:
            print("[ERROR] path 清洗后训练数据为空，请检查输入数据或使用 --keep-empty-path", file=sys.stderr)
            sys.exit(1)

    if args.max_train_samples < 0:
        print("[ERROR] --max-train-samples 不能为负数", file=sys.stderr)
        sys.exit(1)
    if args.max_train_samples > 0 and len(df_train) > args.max_train_samples:
        before_n = len(df_train)
        df_train = df_train.sample(
            n=int(args.max_train_samples),
            random_state=int(args.sample_seed),
            replace=False,
        ).reset_index(drop=True)
        print(
            f"[INFO] 训练样本抽样: {before_n} -> {len(df_train)} "
            f"(max_train_samples={args.max_train_samples}, seed={args.sample_seed})"
        )

    if args.augment_normal_count < 0:
        print("[ERROR] --augment-normal-count 不能为负数", file=sys.stderr)
        sys.exit(1)
    if args.augment_normal_count > 0:
        detect_path = Path(args.augment_normal_detect_path)
        if not detect_path.exists():
            print(f"[WARN] 找不到检测数据文件，跳过正常样本补充: {detect_path}", file=sys.stderr)
        else:
            df_aug, aug_stats = _sample_normal_records_from_detection(
                detect_path,
                sample_size=int(args.augment_normal_count),
                seed=int(args.sample_seed),
                label_column=str(args.augment_label_column or data_config.label_column),
                keep_binary_noise=args.keep_binary_noise,
                keep_noncompliant_protocol=args.keep_noncompliant_protocol,
                keep_empty_path=args.keep_empty_path,
            )
            if len(df_aug) > 0:
                before_n = len(df_train)
                df_train = pd.concat([df_train, df_aug], ignore_index=True)
                print(
                    "[INFO] 训练集补充近期正常检测样本: "
                    f"+{len(df_aug)} 条 ({before_n} -> {len(df_train)}), "
                    f"候选正常干净样本 {aug_stats.get('seen', 0)} 条, "
                    f"扫描总数 {aug_stats.get('total_scanned', 0)} 条"
                )
            else:
                print(
                    "[WARN] 未从检测数据中抽到可补充的 label=0 干净样本，"
                    f"扫描总数 {aug_stats.get('total_scanned', 0)} 条",
                    file=sys.stderr,
                )

    # 使用命令行参数覆盖配置
    config = ModelConfig(
        model_type=args.model,
        contamination=args.contamination,
        ocsvm_nu=args.ocsvm_nu,
        ocsvm_backend=args.ocsvm_backend,
        thundersvm_gpu_id=int(args.thundersvm_gpu_id),
    )
    if args.ae_hidden is not None:
        config.ae_hidden_dim = int(args.ae_hidden)
    if args.ae_latent is not None:
        config.ae_latent_dim = int(args.ae_latent)
    if args.ae_epochs is not None:
        config.ae_epochs = int(args.ae_epochs)
    if args.ae_batch_size is not None:
        config.ae_batch_size = int(args.ae_batch_size)
    if args.ae_lr is not None:
        config.ae_lr = float(args.ae_lr)
    if args.ae_mse_percentile is not None:
        config.ae_mse_percentile = float(args.ae_mse_percentile)
    if args.ae_max_train_samples is not None:
        config.ae_max_train_samples = int(args.ae_max_train_samples)
    if args.ae_device is not None:
        config.ae_device = str(args.ae_device)
    if args.ae_loss_alpha is not None:
        config.ae_loss_alpha = float(args.ae_loss_alpha)
    if args.ae_loss_beta is not None:
        config.ae_loss_beta = float(args.ae_loss_beta)
    if args.ae_input_dropout is not None:
        config.ae_input_dropout = float(args.ae_input_dropout)
    if args.ae_binary_flip_prob is not None:
        config.ae_binary_flip_prob = float(args.ae_binary_flip_prob)
    
    # 如果命令行指定了阈值，覆盖配置
    if args.decision_threshold is not None:
        config.decision_threshold = args.decision_threshold

    print(f"[INFO] 使用模型: {config.model_type}")
    if config.model_type == "one_class_svm":
        print(f"[INFO] One-Class SVM 后端: {config.ocsvm_backend}", end="")
        if config.ocsvm_backend == "thundersvm":
            print(f" (GPU id={config.thundersvm_gpu_id})")
        else:
            print()
    elif config.model_type == "autoencoder":
        try:
            import torch

            dev = config.ae_device or "auto"
            cuda_ok = torch.cuda.is_available()
            print(
                f"[INFO] 自编码器: hidden={config.ae_hidden_dim}, latent={config.ae_latent_dim}, "
                f"epochs={config.ae_epochs}, batch={config.ae_batch_size}, lr={config.ae_lr}, device={dev!r}, "
                f"alpha={config.ae_loss_alpha}, beta={config.ae_loss_beta}, "
                f"dropout={config.ae_input_dropout}, flip={config.ae_binary_flip_prob}, "
                f"torch.cuda.is_available()={cuda_ok}"
            )
        except ImportError:
            print(
                "[ERROR] 未安装 PyTorch，无法训练 autoencoder。请执行: pip install torch",
                file=sys.stderr,
            )
            sys.exit(1)
    print(f"[INFO] 训练数据: {args.train_path}, 样本数: {len(df_train)}")
    print(f"[INFO] 决策阈值: {config.decision_threshold}")
    _fj = _resolve_feature_n_jobs()
    if len(df_train) >= 2000:
        print(
            f"[INFO] 特征提取并行度: {_fj} 个进程"
            f"（`--feature-jobs N` 或环境变量 WAF_FEATURE_N_JOBS；N=1 关闭并行）"
        )

    model, path = train_model(df_train, config=config, label_column=label_column)
    print(f"[INFO] 训练完成，模型已保存到: {path}")


if __name__ == "__main__":
    main()
