from __future__ import annotations

import argparse
import json
import re
import textwrap
import time
from pathlib import Path
from typing import Any
from urllib import error, request


BUCKET_KEYS = {
    "fp": "false_positive_anomalies_fp",
    "fn": "missed_anomalies_fn",
    "tp": "detected_anomalies_tp",
}


def _first_line_http(http: str) -> str:
    text = (http or "").replace("\\r\\n", "\n").replace("\r\n", "\n")
    return text.split("\n", 1)[0] if text else ""


def _truncate(value: Any, max_len: int) -> str:
    text = str(value or "")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _extract_path_query(record: dict[str, Any]) -> tuple[str, str]:
    parsed = record.get("http_parsed")
    if isinstance(parsed, dict):
        path = str(parsed.get("path") or "")
        query_obj = parsed.get("query")
        if isinstance(query_obj, dict):
            parts = []
            for key, value in query_obj.items():
                if isinstance(value, list):
                    for item in value:
                        parts.append(f"{key}={item}")
                else:
                    parts.append(f"{key}={value}")
            query = "&".join(parts)
        else:
            query = str(query_obj or "")
        if path or query:
            return path, query

    uri = str(record.get("uri") or "")
    if "?" in uri:
        path, query = uri.split("?", 1)
        return path, query
    return uri, ""


def _extract_headers(record: dict[str, Any]) -> dict[str, str]:
    parsed = record.get("http_parsed")
    if isinstance(parsed, dict) and isinstance(parsed.get("headers"), dict):
        headers = parsed["headers"]
        keep = {}
        for key in ("host", "user-agent", "content-type", "referer", "x-forwarded-for"):
            if key in {str(k).lower() for k in headers}:
                for original_key, value in headers.items():
                    if str(original_key).lower() == key:
                        keep[key] = _truncate(value, 160)
                        break
        return keep
    return {}


def _case_brief(case: dict[str, Any], ordinal: int) -> dict[str, Any]:
    record = case.get("record") if isinstance(case.get("record"), dict) else case
    prediction = case.get("prediction") if isinstance(case.get("prediction"), dict) else {}
    path, query = _extract_path_query(record)
    return {
        "case_no": ordinal,
        "clean_index": case.get("clean_index", case.get("index")),
        "original_index": case.get("original_index"),
        "y_true": case.get("y_true"),
        "y_pred": case.get("y_pred"),
        "score": prediction.get("score"),
        "threshold": prediction.get("threshold"),
        "event_type": record.get("event_type"),
        "method": record.get("method"),
        "path": _truncate(path, 240),
        "query": _truncate(query, 500),
        "first_line": _truncate(_first_line_http(str(record.get("http") or "")), 500),
        "headers": _extract_headers(record),
        "label": record.get("label"),
    }


def _load_cases(path: Path, bucket: str, limit: int) -> list[dict[str, Any]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    bucket_key = BUCKET_KEYS[bucket]

    if isinstance(obj, list):
        cases = obj
    elif isinstance(obj, dict) and bucket_key in obj:
        cases = obj.get(bucket_key) or []
    elif isinstance(obj, dict):
        cases = []
        for method_obj in obj.values():
            if isinstance(method_obj, dict):
                cases.extend(method_obj.get(bucket_key) or [])
    else:
        raise ValueError(f"Unsupported case file format: {path}")

    if limit > 0:
        cases = cases[:limit]
    return cases


def _ollama_chat(endpoint: str, model: str, prompt: str, timeout: int) -> str:
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是资深 WAF/HTTP 安全检测分析专家。"
                    "你要基于样本字段解释误报或漏报原因，避免泛泛而谈。"
                    "输出中文，结构化、可执行。"
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        endpoint.rstrip("/") + "/api/chat",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach Ollama endpoint {endpoint!r}. "
            "请确认 SSH 隧道仍在运行，并且本机 11434 端口可访问。"
        ) from exc

    obj = json.loads(body)
    message = obj.get("message") if isinstance(obj, dict) else None
    if isinstance(message, dict):
        return str(message.get("content") or "")
    return str(obj.get("response") or body)


def _strip_think(text: str) -> str:
    return re.sub(r"(?is)<think>.*?</think>", "", text).strip()


def _build_prompt(bucket: str, cases: list[dict[str, Any]], start_no: int) -> str:
    case_name = {"fp": "误报 FP（真实正常，预测异常）", "fn": "漏报 FN（真实异常，预测正常）", "tp": "正确检出 TP"}[bucket]
    briefs = [_case_brief(case, start_no + i) for i, case in enumerate(cases)]
    return textwrap.dedent(
        f"""
        请分析下面这些 WAF 无监督检测样本的 {case_name} 原因。

        背景：
        - 模型分数越小越异常。
        - 判定逻辑是 score < threshold 判为异常。
        - 当前整体指标显示召回很高但精确率偏低，所以 FP 重点关注“正常流量为什么像攻击/异常”。

        请按以下结构输出：
        1. 批次总体判断：主要误报/漏报模式是什么。
        2. 逐条样本分析：每条给出 1-3 个最可能原因。
        3. 可落地修复建议：包括阈值、训练正常样本补充、特征工程或白名单/降权建议。
        4. 需要人工复核的样本编号。

        样本 JSON：
        {json.dumps(briefs, ensure_ascii=False, indent=2)}
        """
    ).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Use local Ollama LLM to analyze exported WAF detection cases.")
    parser.add_argument("--cases", required=True, help="Path to export_detection_cases.py output JSON.")
    parser.add_argument("--bucket", choices=["fp", "fn", "tp"], default="fp", help="Which case bucket to analyze.")
    parser.add_argument("--limit", type=int, default=20, help="Max cases to analyze. 0 means all cases.")
    parser.add_argument("--batch-size", type=int, default=5, help="Cases per LLM request.")
    parser.add_argument("--model", default="deepseek-r1:14b", help="Ollama model name.")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434", help="Ollama endpoint.")
    parser.add_argument("--timeout", type=int, default=300, help="Request timeout seconds.")
    parser.add_argument("--out", default="artifacts/output/llm_detection_case_analysis.md", help="Output markdown path.")
    parser.add_argument("--keep-thinking", action="store_true", help="Keep DeepSeek-R1 <think>...</think> text.")
    args = parser.parse_args()

    if args.limit < 0:
        raise ValueError("--limit cannot be negative")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be positive")

    cases = _load_cases(Path(args.cases), args.bucket, int(args.limit))
    if not cases:
        raise ValueError(f"No cases found in bucket {args.bucket!r}: {args.cases}")

    sections = [
        f"# LLM Detection Case Analysis",
        "",
        f"- model: `{args.model}`",
        f"- endpoint: `{args.endpoint}`",
        f"- bucket: `{args.bucket}`",
        f"- cases: `{len(cases)}`",
        "",
    ]

    for start in range(0, len(cases), int(args.batch_size)):
        batch = cases[start : start + int(args.batch_size)]
        batch_no = start // int(args.batch_size) + 1
        print(f"[INFO] Analyzing batch {batch_no}: cases {start + 1}-{start + len(batch)}")
        prompt = _build_prompt(args.bucket, batch, start + 1)
        answer = _ollama_chat(args.endpoint, args.model, prompt, int(args.timeout))
        if not args.keep_thinking:
            answer = _strip_think(answer)
        sections.extend([f"## Batch {batch_no}", "", answer.strip(), ""])
        time.sleep(0.2)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(sections).strip() + "\n", encoding="utf-8")
    print(f"Saved LLM analysis to: {out_path}")


if __name__ == "__main__":
    main()
