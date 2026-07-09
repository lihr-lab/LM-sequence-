from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from waf_unsupervised.data_cleaning import (
    _is_empty_http_parsed,
    is_binary_noise,
)

# 示例：
# python export_detection_cases.py --data data/detection_1.json --pred artifacts/output/detect_predictions.json --case_type fn --limit 999999 --out artifacts/output/fn_all_samples.json


def _to_binary_label(value: Any) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return 1 if int(value) != 0 else 0
    text = str(value).strip().lower()
    return 1 if text in {"1", "true", "yes", "y", "abnormal", "anomaly"} else 0


def _to_binary_pred(pred_item: dict, pred_key: str) -> int:
    raw = pred_item.get(pred_key, False)
    if isinstance(raw, bool):
        return 1 if raw else 0
    if isinstance(raw, (int, float)):
        # is_anomaly/is_anomaly_raw: 1 表示异常；raw_pred 不应走这里。
        return 1 if int(raw) == 1 else 0
    text = str(raw).strip().lower()
    return 1 if text in {"1", "true", "yes", "y", "abnormal", "anomaly"} else 0


def _load_pred_list(pred_obj: Any, method: str) -> List[dict]:
    if isinstance(pred_obj, list):
        return pred_obj
    if isinstance(pred_obj, dict):
        if method in pred_obj and isinstance(pred_obj[method], list):
            return pred_obj[method]
        methods = pred_obj.get("methods")
        if isinstance(methods, dict) and method in methods and isinstance(methods[method], list):
            return methods[method]
    raise ValueError(f"Cannot find prediction list for method '{method}'")


def _iter_json_array(path: Path, chunk_size: int = 1024 * 1024) -> Iterator[dict[str, Any]]:
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


def _extract_path(record: dict) -> str:
    parsed = record.get("http_parsed", {})
    if isinstance(parsed, dict) and parsed.get("path"):
        return str(parsed["path"])
    uri = str(record.get("uri", "") or "")
    if "?" in uri:
        uri = uri.split("?", 1)[0]
    if uri.startswith(("http://", "https://")):
        parts = uri.split("/", 3)
        if len(parts) >= 4:
            return "/" + parts[3]
    return uri


def _passes_detect_filters(
    record: dict,
    *,
    keep_binary_noise: bool,
    keep_noncompliant_protocol: bool,
    event_type: str,
    method_filter: str,
) -> bool:
    if method_filter != "ALL":
        method = str(record.get("method", "")).strip().upper()
        if method_filter == "OTHER":
            if method == "GET":
                return False
        elif method != method_filter:
            return False

    if not keep_binary_noise and is_binary_noise(record.get("http")):
        return False

    if not keep_noncompliant_protocol:
        method_unknown = str(record.get("method", "")).strip().upper() == "UNKNOWN"
        parsed_empty = _is_empty_http_parsed(record.get("http_parsed"))
        if method_unknown or parsed_empty:
            return False

    if event_type:
        actual = str(record.get("event_type", "")).strip().lower()
        if actual != event_type.strip().lower():
            return False

    return True


def _iter_aligned_data_rows(
    data_path: Path,
    *,
    keep_binary_noise: bool,
    keep_noncompliant_protocol: bool,
    event_type: str,
    method_filter: str,
    already_aligned: bool,
    max_detect_samples: int,
) -> Iterator[tuple[int, int, dict]]:
    clean_index = 0
    max_rows = int(max_detect_samples)
    for original_index, record in enumerate(_iter_json_array(data_path)):
        if not already_aligned and not _passes_detect_filters(
            record,
            keep_binary_noise=keep_binary_noise,
            keep_noncompliant_protocol=keep_noncompliant_protocol,
            event_type=event_type,
            method_filter=method_filter,
        ):
            continue
        if max_rows > 0 and clean_index >= max_rows:
            break
        yield clean_index, original_index, record
        clean_index += 1


def _empty_output(each_limit: int, filter_path: Optional[str], case_type: str) -> Dict[str, Any]:
    return {
        "detected_anomalies_tp": [],
        "missed_anomalies_fn": [],
        "false_positive_anomalies_fp": [],
        "summary": {
            "compared": 0,
            "tp_collected": 0,
            "fn_collected": 0,
            "fp_collected": 0,
            "requested_each_limit": each_limit,
            "filter_path": filter_path,
            "case_type": case_type,
            "max_detect_samples": 0,
        },
    }


def _collect_cases_from_aligned_iter(
    data_iter: Iterator[tuple[int, int, dict]],
    pred_rows: List[dict],
    label_key: str,
    pred_key: str,
    each_limit: int,
    *,
    filter_path: Optional[str],
    case_type: str,
    max_detect_samples: int,
) -> Dict[str, Any]:
    output = _empty_output(each_limit, filter_path, case_type)
    tp_cases = output["detected_anomalies_tp"]
    fn_cases = output["missed_anomalies_fn"]
    fp_cases = output["false_positive_anomalies_fp"]
    compared = 0

    for clean_index, original_index, record in data_iter:
        if clean_index >= len(pred_rows):
            break

        pred_item = pred_rows[clean_index]
        y_true = _to_binary_label(record.get(label_key, 0))
        y_pred = _to_binary_pred(pred_item, pred_key)
        compared += 1

        if filter_path:
            path = _extract_path(record)
            if filter_path not in path:
                continue

        collect_tp = (case_type in ("all", "tp")) and (y_true == 1 and y_pred == 1)
        collect_fn = (case_type in ("all", "fn")) and (y_true == 1 and y_pred == 0)
        collect_fp = (case_type in ("all", "fp")) and (y_true == 0 and y_pred == 1)

        if not (collect_tp or collect_fn or collect_fp):
            continue

        item = {
            "index": clean_index,
            "clean_index": clean_index,
            "original_index": original_index,
            "pred_index": pred_item.get("index", clean_index),
            "y_true": y_true,
            "y_pred": y_pred,
            "label_name": "anomaly" if y_true == 1 else "normal",
            "prediction_name": "anomaly" if y_pred == 1 else "normal",
            "prediction": pred_item,
            "record": record,
        }

        if collect_tp and len(tp_cases) < each_limit:
            tp_cases.append(item)
        elif collect_fn and len(fn_cases) < each_limit:
            fn_cases.append(item)
        elif collect_fp and len(fp_cases) < each_limit:
            fp_cases.append(item)

        if (
            (case_type == "all" and len(tp_cases) >= each_limit and len(fn_cases) >= each_limit and len(fp_cases) >= each_limit)
            or (case_type == "tp" and len(tp_cases) >= each_limit)
            or (case_type == "fn" and len(fn_cases) >= each_limit)
            or (case_type == "fp" and len(fp_cases) >= each_limit)
        ):
            break

    output["summary"].update(
        {
            "compared": compared,
            "prediction_count": len(pred_rows),
            "tp_collected": len(tp_cases),
            "fn_collected": len(fn_cases),
            "fp_collected": len(fp_cases),
            "max_detect_samples": int(max_detect_samples),
        }
    )
    if compared != len(pred_rows):
        output["summary"]["warning"] = (
            "data rows after filtering do not match prediction count; "
            "check --keep-* / --event-type / --data-already-aligned options."
        )
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="导出检测样本：TP/FN/FP，默认按 detect.py 的清洗逻辑对齐预测结果。"
    )
    parser.add_argument("--data", required=True, help="带标签的数据 JSON 列表路径")
    parser.add_argument("--pred", required=True, help="预测结果 JSON 路径")
    parser.add_argument("--method", default="ALL", help="当 pred 为 GET/OTHER 分组时选择 GET/OTHER/ALL")
    parser.add_argument("--label_key", default="label", help="真实标签字段名")
    parser.add_argument("--pred_key", default="is_anomaly_raw", choices=["is_anomaly_raw", "is_anomaly"])
    parser.add_argument("--limit", type=int, default=20, help="每类样本导出数量（默认 20）")
    parser.add_argument("--out", default="artifacts/output/detection_case_samples.json", help="输出 JSON 文件路径")
    parser.add_argument("--filter_path", type=str, default=None, help="仅收集路径中包含该字符串的样本")
    parser.add_argument("--case_type", choices=["all", "tp", "fn", "fp"], default="all")
    parser.add_argument("--event-type", default="", help="若检测时使用了 --event-type，这里必须传同样的值")
    parser.add_argument(
        "--max-detect-samples",
        type=int,
        default=0,
        metavar="N",
        help="若检测时使用了 --max-detect-samples，这里传同样的值以按顺序截取并对齐预测结果",
    )
    parser.add_argument("--keep-binary-noise", action="store_true", help="若检测时保留二进制噪声，这里也传同样参数")
    parser.add_argument("--keep-noncompliant-protocol", action="store_true", help="若检测时保留协议不合规样本，这里也传同样参数")
    parser.add_argument(
        "--data-already-aligned",
        action="store_true",
        help="当 --data 是 detect.py --sample-out 产物或已与预测结果逐行对齐时使用，跳过清洗/过滤",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    with open(args.pred, "r", encoding="utf-8") as f:
        pred_obj = json.load(f)

    method = str(args.method).strip().upper()
    each_limit = max(int(args.limit), 1)
    if args.max_detect_samples < 0:
        raise ValueError("--max-detect-samples cannot be negative")

    if isinstance(pred_obj, dict) and ("GET" in pred_obj or "OTHER" in pred_obj):
        methods = ["GET", "OTHER"] if method == "ALL" else [method]
        output: Dict[str, Any] = {}
        for m in methods:
            pred_rows = _load_pred_list(pred_obj, m)
            data_iter = _iter_aligned_data_rows(
                data_path,
                keep_binary_noise=args.keep_binary_noise,
                keep_noncompliant_protocol=args.keep_noncompliant_protocol,
                event_type=args.event_type,
                method_filter=m,
                already_aligned=args.data_already_aligned,
                max_detect_samples=args.max_detect_samples,
            )
            output[m] = _collect_cases_from_aligned_iter(
                data_iter,
                pred_rows,
                args.label_key,
                args.pred_key,
                each_limit,
                filter_path=args.filter_path,
                case_type=args.case_type,
                max_detect_samples=args.max_detect_samples,
            )
    else:
        pred_rows = _load_pred_list(pred_obj, method)
        data_iter = _iter_aligned_data_rows(
            data_path,
            keep_binary_noise=args.keep_binary_noise,
            keep_noncompliant_protocol=args.keep_noncompliant_protocol,
            event_type=args.event_type,
            method_filter="ALL",
            already_aligned=args.data_already_aligned,
            max_detect_samples=args.max_detect_samples,
        )
        output = _collect_cases_from_aligned_iter(
            data_iter,
            pred_rows,
            args.label_key,
            args.pred_key,
            each_limit,
            filter_path=args.filter_path,
            case_type=args.case_type,
            max_detect_samples=args.max_detect_samples,
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"Saved case samples to: {out_path}")


if __name__ == "__main__":
    main()
