# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import copy
import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from fol_rule_detect import (
    apply_business_focus_filter,
    detect_rule_on_session,
    discover_input_files,
    group_findings_by_rule,
    iter_sessions,
    summarize_hit,
)
from llm_cluster_review import extract_json, normalize_openai_base_url


DEFAULT_BASE_DIR = "artifacts/train"
DEFAULT_LLM_URL = os.getenv("AUTODL_BASE_URL", os.getenv("LLM_URL", "https://www.autodl.art/api/v1"))
DEFAULT_MODEL = os.getenv("AUTODL_MODEL", os.getenv("LLM_MODEL", "GLM-5"))
CONTROL_CHARS = {chr(code) for code in list(range(0, 32)) + [127]}

SYSTEM_PROMPT = """你是 API 访问控制规则误报修正 agent。
你必须逐规则分析正常样本中的误报原因，然后提出最小、可回放验证的规则修改。
不要创建新规则，不要修改非目标 fol_id，不要编造证据中不存在的 API、参数、dimension 或 scope key。
只输出合法 JSON。"""

SUPPORTED_ACTIONS = {
    "raise_threshold",
    "add_context_requirement",
    "add_precondition",
    "narrow_api_scope",
    "change_dimension",
    "replace_expression",
    "disable",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rewrite rule update agent: analyze false positives per rule with LLM and verify each candidate by replay.",
    )
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--input-dir", default="", help="Default: <base-dir>/log_sequence")
    parser.add_argument(
        "--validation-input-dir",
        default="",
        help="Optional labeled validation log_sequence dir. When set, anomalous sessions are included and per-rule F1 is optimized.",
    )
    parser.add_argument("--fol-file", default="", help="Default: <base-dir>/fol_expressions/site_<site_id>_fol_expressions.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/fol_rule_updates")
    parser.add_argument("--next-rules-file", default="", help="Default: <base-dir>/fol_expressions/site_<site_id>_fol_expressions_next.json")
    parser.add_argument("--bucket", default="all", choices=["short_1_2", "main_3_50", "long_51_plus", "all"])
    parser.add_argument("--max-sessions", type=int, default=0)
    parser.add_argument("--include-labeled-anomalous", action="store_true")
    parser.add_argument("--include-frontend-noise", action="store_true")
    parser.add_argument("--max-iterations-per-rule", type=int, default=3)
    parser.add_argument("--max-candidates-per-rule", type=int, default=5)
    parser.add_argument("--max-evidence-sessions-per-rule", type=int, default=5)
    parser.add_argument(
        "--target-fol-id",
        action="append",
        default=[],
        help="Only update the specified fol_id. Can be passed multiple times.",
    )
    parser.add_argument("--target-rule-fp-rate", type=float, default=0.10, help="Per-rule false-positive session-rate threshold.")
    parser.add_argument("--target-rule-min-f1", type=float, default=0.50, help="Per-rule F1 threshold used when labeled validation data is available.")
    parser.add_argument("--min-rule-fp-sessions", type=int, default=1)
    parser.add_argument("--allow-disable", action="store_true", help="Allow LLM disable candidates to be verified and accepted.")
    parser.add_argument("--dry-run", action="store_true", help="Only write replay/evidence/prompt files; do not call LLM.")
    parser.add_argument("--llm-url", default=DEFAULT_LLM_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-key", default=os.getenv("AUTODL_API_KEY", os.getenv("LLM_API_KEY", "")))
    parser.add_argument("--request-timeout", type=int, default=180)
    parser.add_argument("--retry", type=int, default=2)
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def default_fol_file(base_dir: Path, site_id: str) -> Path:
    next_file = default_next_rules_file(base_dir, site_id)
    if next_file.exists():
        return next_file
    return base_dir / "fol_expressions" / f"site_{site_id}_fol_expressions.json"


def default_next_rules_file(base_dir: Path, site_id: str) -> Path:
    return base_dir / "fol_expressions" / f"site_{site_id}_fol_expressions_next.json"


def clean_fol_id(value: Any) -> str:
    return "".join(char for char in str(value or "") if char not in CONTROL_CHARS).strip()


def active_rules(fol_payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for item in fol_payload.get("expressions", [])
        if isinstance(item, dict)
        and item.get("status") == "generated"
        and not item.get("disabled")
        and not item.get("refinement", {}).get("disabled")
    ]


def load_replay_sessions(args: argparse.Namespace, base_dir: Path) -> list[dict[str, Any]]:
    validation_input_dir = str(getattr(args, "validation_input_dir", "") or "").strip()
    input_dir = Path(validation_input_dir) if validation_input_dir else Path(args.input_dir) if args.input_dir else base_dir / "log_sequence"
    optimize_with_labels = bool(validation_input_dir)
    files = discover_input_files(input_dir, args.bucket, args.site_id, False)
    sessions: list[dict[str, Any]] = []
    seen_session_ids: set[str] = set()
    for session in iter_sessions(files):
        session_id = str(session.get("session_id", ""))
        if session_id and session_id in seen_session_ids:
            continue
        if session_id:
            seen_session_ids.add(session_id)
        if not optimize_with_labels and not args.include_labeled_anomalous and bool(session.get("is_anomalous")):
            continue
        session = apply_business_focus_filter(session, args.include_frontend_noise)
        if session.get("api_sequence"):
            sessions.append(session)
        if args.max_sessions > 0 and len(sessions) >= args.max_sessions:
            break
    return sessions


def replay_rules(fol_payload: dict[str, Any], sessions: list[dict[str, Any]], max_evidence_per_rule: int) -> dict[str, Any]:
    findings = []
    rule_hit_counter: Counter[str] = Counter()
    rule_session_sets: dict[str, set[str]] = defaultdict(set)
    emitted_rule_counter: Counter[str] = Counter()

    for session in sessions:
        for rule in active_rules(fol_payload):
            expr_hits = detect_rule_on_session(rule, session)
            if not expr_hits:
                continue
            fol_id = str(rule.get("fol_id", ""))
            session_id = str(session.get("session_id", ""))
            rule_hit_counter[fol_id] += len(expr_hits)
            if session_id:
                rule_session_sets[fol_id].add(session_id)
            if max_evidence_per_rule > 0 and emitted_rule_counter[fol_id] >= max_evidence_per_rule:
                continue
            emitted_rule_counter[fol_id] += 1
            findings.append(summarize_hit(rule, session, expr_hits))

    rule_findings = group_findings_by_rule(findings)
    hit_session_ids = sorted({session_id for session_ids in rule_session_sets.values() for session_id in session_ids})
    session_labels = {
        str(session.get("session_id", "")): bool(session.get("is_anomalous"))
        for session in sessions
        if session.get("session_id")
    }
    actual_anomalous_ids = {session_id for session_id, is_anomalous in session_labels.items() if is_anomalous}
    actual_normal_ids = set(session_labels) - actual_anomalous_ids
    labeled_scoring_available = bool(actual_anomalous_ids) and bool(actual_normal_ids)
    normal_session_count = len(actual_normal_ids) if labeled_scoring_available else len(sessions)
    per_rule = {}
    active_fol_ids = [str(rule.get("fol_id", "")) for rule in active_rules(fol_payload) if str(rule.get("fol_id", ""))]
    scored_fol_ids = sorted(set(active_fol_ids) | set(rule_session_sets))
    for fol_id in scored_fol_ids:
        session_ids = rule_session_sets.get(fol_id, set())
        hit_ids = set(session_ids)
        true_positive_ids = sorted(hit_ids & actual_anomalous_ids) if labeled_scoring_available else []
        false_positive_ids = sorted(hit_ids & actual_normal_ids) if labeled_scoring_available else sorted(hit_ids)
        false_negative_ids = sorted(actual_anomalous_ids - hit_ids) if labeled_scoring_available else []
        precision = len(true_positive_ids) / (len(true_positive_ids) + len(false_positive_ids)) if labeled_scoring_available and (true_positive_ids or false_positive_ids) else 0.0
        recall = len(true_positive_ids) / (len(true_positive_ids) + len(false_negative_ids)) if labeled_scoring_available and (true_positive_ids or false_negative_ids) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_rule[fol_id] = {
            "fol_id": fol_id,
            "hit_session_count": len(hit_ids),
            "true_positive_session_count": len(true_positive_ids),
            "false_positive_session_count": len(false_positive_ids),
            "false_negative_session_count": len(false_negative_ids),
            "false_positive_hit_count": int(rule_hit_counter.get(fol_id, 0)),
            "false_positive_rate": len(false_positive_ids) / normal_session_count if normal_session_count else 0.0,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "labeled_scoring_available": labeled_scoring_available,
            "sampled_false_negative_session_ids": false_negative_ids[:max_evidence_per_rule] if max_evidence_per_rule > 0 else [],
            "sampled_true_positive_session_ids": true_positive_ids[:max_evidence_per_rule] if max_evidence_per_rule > 0 else [],
            "sampled_false_positive_session_ids": false_positive_ids[:max_evidence_per_rule] if max_evidence_per_rule > 0 else [],
        }
    predicted_ids = set(hit_session_ids)
    true_positive_ids = sorted(predicted_ids & actual_anomalous_ids) if labeled_scoring_available else []
    false_positive_ids = sorted(predicted_ids & actual_normal_ids) if labeled_scoring_available else hit_session_ids
    false_negative_ids = sorted(actual_anomalous_ids - predicted_ids) if labeled_scoring_available else []
    true_negative_ids = sorted(actual_normal_ids - predicted_ids) if labeled_scoring_available else []
    precision = len(true_positive_ids) / (len(true_positive_ids) + len(false_positive_ids)) if labeled_scoring_available and (true_positive_ids or false_positive_ids) else 0.0
    recall = len(true_positive_ids) / (len(true_positive_ids) + len(false_negative_ids)) if labeled_scoring_available and (true_positive_ids or false_negative_ids) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "session_count": len(sessions),
        "normal_session_count": normal_session_count,
        "anomalous_session_count": len(actual_anomalous_ids) if labeled_scoring_available else 0,
        "labeled_scoring_available": labeled_scoring_available,
        "active_rule_count": len(active_rules(fol_payload)),
        "finding_count": len(findings),
        "hit_count": int(sum(rule_hit_counter.values())),
        "hit_session_count": len(hit_session_ids),
        "true_positive_session_count": len(true_positive_ids),
        "false_positive_session_count": len(false_positive_ids),
        "false_negative_session_count": len(false_negative_ids),
        "true_negative_session_count": len(true_negative_ids),
        "false_positive_rate": len(false_positive_ids) / normal_session_count if normal_session_count else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "hit_session_ids": hit_session_ids,
        "rule_hit_count": dict(rule_hit_counter),
        "rule_false_positive_session_count": {
            fol_id: int(per_rule.get(fol_id, {}).get("false_positive_session_count", len(ids)))
            for fol_id, ids in sorted(rule_session_sets.items())
        },
        "rule_false_positive_stats": per_rule,
        "rule_findings": rule_findings,
        "findings": findings,
    }


def replay_single_rule(payload: dict[str, Any], fol_id: str, sessions: list[dict[str, Any]], max_evidence: int) -> dict[str, Any]:
    single = copy.deepcopy(payload)
    target_fol_id = clean_fol_id(fol_id)
    single["expressions"] = [rule for rule in active_rules(single) if clean_fol_id(rule.get("fol_id", "")) == target_fol_id]
    return replay_rules(single, sessions, max_evidence)


def compact_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "fol_id": rule.get("fol_id", ""),
        "scenario_title": rule.get("scenario_title") or rule.get("source", {}).get("scenario_title", ""),
        "security_type": rule.get("scenario_summary", {}).get("security_type", rule.get("source", {}).get("security_type", "")),
        "risk_level": rule.get("scenario_summary", {}).get("risk_level", ""),
        "activity_abstraction": rule.get("activity_abstraction", {}),
        "logic_expressions": rule.get("logic_expressions", []),
    }


def compact_hit_session(hit_session: dict[str, Any]) -> dict[str, Any]:
    context = hit_session.get("session_context", {})
    api_sequence = context.get("api_sequence", [])
    raw_sequence = context.get("raw_sequence", [])
    return {
        "session_id": hit_session.get("session_id", ""),
        "session_label": hit_session.get("session_label", ""),
        "session_is_anomalous": bool(hit_session.get("session_is_anomalous")),
        "expression_hits": hit_session.get("expression_hits", []),
        "hit_context_summary": hit_session.get("hit_context_summary", {}),
        "api_sequence": api_sequence[:80],
        "raw_sequence": raw_sequence[:80],
    }


def compact_replay_session(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": session.get("session_id", ""),
        "label": session.get("label", ""),
        "is_anomalous": bool(session.get("is_anomalous")),
        "api_sequence": list(session.get("api_sequence", []))[:80],
        "raw_sequence": list(session.get("raw_sequence", []))[:80],
    }


def find_rule(payload: dict[str, Any], fol_id: str) -> dict[str, Any] | None:
    target_fol_id = clean_fol_id(fol_id)
    for rule in payload.get("expressions", []):
        if isinstance(rule, dict) and clean_fol_id(rule.get("fol_id", "")) == target_fol_id:
            return rule
    return None


def noisy_rules(replay: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    output = []
    target_fol_ids = {clean_fol_id(item) for item in getattr(args, "target_fol_id", []) or [] if clean_fol_id(item)}
    labeled_scoring_available = bool(replay.get("labeled_scoring_available"))
    for item in replay.get("rule_false_positive_stats", {}).values():
        fol_id = clean_fol_id(item.get("fol_id", ""))
        if target_fol_ids and fol_id not in target_fol_ids:
            continue
        fp_too_high = float(item.get("false_positive_rate", 0.0)) > args.target_rule_fp_rate
        f1_too_low = labeled_scoring_available and float(item.get("f1", 0.0)) < args.target_rule_min_f1
        if not target_fol_ids and not f1_too_low and int(item.get("false_positive_session_count", 0)) < args.min_rule_fp_sessions:
            continue
        if target_fol_ids or fp_too_high or f1_too_low:
            output.append(item)
    if labeled_scoring_available:
        return sorted(
            output,
            key=lambda item: (
                float(item.get("f1", 0.0)),
                -float(item.get("false_positive_rate", 0.0)),
                -int(item.get("false_positive_hit_count", 0)),
                item.get("fol_id", ""),
            ),
        )
    return sorted(output, key=lambda item: (-float(item.get("false_positive_rate", 0.0)), -int(item.get("false_positive_hit_count", 0)), item.get("fol_id", "")))


def selected_rules_for_update(payload: dict[str, Any], replay: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    target_fol_ids = [clean_fol_id(item) for item in getattr(args, "target_fol_id", []) or [] if clean_fol_id(item)]
    if not target_fol_ids:
        return noisy_rules(replay, args)
    stats = replay.get("rule_false_positive_stats", {}) if isinstance(replay.get("rule_false_positive_stats"), dict) else {}
    stats_by_id = {clean_fol_id(key): value for key, value in stats.items()}
    active_by_id = {clean_fol_id(rule.get("fol_id", "")): rule for rule in active_rules(payload)}
    selected = []
    for fol_id in target_fol_ids:
        if fol_id not in active_by_id:
            selected.append({"fol_id": fol_id, "selection_error": "target_rule_not_found_or_inactive"})
            continue
        selected.append(
            dict(
                stats_by_id.get(
                    fol_id,
                    {
                        "fol_id": fol_id,
                        "hit_session_count": 0,
                        "true_positive_session_count": 0,
                        "false_positive_session_count": 0,
                        "false_negative_session_count": 0,
                        "false_positive_hit_count": 0,
                        "false_positive_rate": 0.0,
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1": 0.0,
                        "labeled_scoring_available": bool(replay.get("labeled_scoring_available")),
                    },
                )
            )
        )
    return selected


def build_rule_evidence(
    payload: dict[str, Any],
    fol_id: str,
    rule_replay: dict[str, Any],
    sessions: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    rule = find_rule(payload, fol_id) or {}
    target_fol_id = clean_fol_id(fol_id)
    findings_by_id = {
        clean_fol_id(key): value
        for key, value in (rule_replay.get("rule_findings", {}) or {}).items()
    }
    stats_by_id = {
        clean_fol_id(key): value
        for key, value in (rule_replay.get("rule_false_positive_stats", {}) or {}).items()
    }
    finding = findings_by_id.get(target_fol_id, {})
    hit_sessions = finding.get("hit_sessions", [])[: args.max_evidence_sessions_per_rule]
    rule_stats = stats_by_id.get(target_fol_id, {})
    by_session_id = {str(session.get("session_id", "")): session for session in sessions if session.get("session_id")}
    false_negative_ids = [
        str(item)
        for item in rule_stats.get("sampled_false_negative_session_ids", [])
        if str(item) in by_session_id
    ]
    missed_anomalous_sessions = [compact_replay_session(by_session_id[item]) for item in false_negative_ids]
    return {
        "objective": "逐规则优化检测效果。有验证标签时以该规则 F1 提升为主，兼顾降低误报；无异常标签时才回退为仅降低正常样本误报。",
        "target_fol_id": target_fol_id,
        "optimization_threshold": {
            "target_rule_fp_rate": args.target_rule_fp_rate,
            "min_rule_fp_sessions": args.min_rule_fp_sessions,
            "target_rule_min_f1": args.target_rule_min_f1,
        },
        "current_rule_replay": {
            "session_count": rule_replay.get("session_count", 0),
            "normal_session_count": rule_replay.get("normal_session_count", 0),
            "anomalous_session_count": rule_replay.get("anomalous_session_count", 0),
            "labeled_scoring_available": rule_replay.get("labeled_scoring_available", False),
            "true_positive_session_count": rule_stats.get("true_positive_session_count", 0),
            "false_positive_session_count": rule_stats.get("false_positive_session_count", rule_replay.get("hit_session_count", 0)),
            "false_negative_session_count": rule_stats.get("false_negative_session_count", 0),
            "false_positive_hit_count": rule_replay.get("hit_count", 0),
            "false_positive_rate": rule_stats.get("false_positive_rate", rule_replay.get("false_positive_rate", 0.0)),
            "precision": rule_stats.get("precision", 0.0),
            "recall": rule_stats.get("recall", 0.0),
            "f1": rule_stats.get("f1", 0.0),
        },
        "rule": compact_rule(rule),
        "normal_hit_sessions": [compact_hit_session(item) for item in hit_sessions],
        "missed_anomalous_sessions": missed_anomalous_sessions,
    }


def build_prompt(evidence: dict[str, Any], accepted_history: list[dict[str, Any]]) -> str:
    payload = {
        "instructions": [
            "先根据 normal_hit_sessions 和 current_rule_replay 分析该规则为什么产生误报、漏报或 F1 偏低。",
            "false_positive_reason 必须具体到 API、参数、阈值、上下文缺失或正常业务行为。",
            "只针对 target_fol_id 给出 1 到 3 个候选修改。",
            "有 labeled_scoring_available 时，候选修改必须尽量提升该规则 F1，不能只减少误报却明显牺牲召回。",
            "优先选择保守修改：提高阈值、增加上下文排除、补充前置条件、收窄 API 范围，同时保持攻击覆盖。",
            "检测执行以 dimension/scope/detector 为准，formula 只作为一阶逻辑展示；如果修改公式语义，必须同步修改 modified_scope 或 modified_expression 对象中的 scope/detector。",
            "replace_expression 可以同时填写 modified_scope 和 modified_expression；modified_expression 可为完整 expression 对象，也可仅为新的 formula 字符串。",
            "不要新增规则，不要修改其他 fol_id，不要使用证据中不存在的 API 或参数。",
            "disable 只能在规则语义和正常证据完全冲突时提出。",
        ],
        "allowed_actions": sorted(SUPPORTED_ACTIONS),
        "candidate_schema": {
            "fol_id": "目标规则 ID",
            "action": "raise_threshold|add_context_requirement|add_precondition|narrow_api_scope|change_dimension|replace_expression|disable",
            "expression_index": "从 1 开始；disable 可为 null",
            "new_threshold": "raise_threshold 时填写整数，否则 null",
            "new_dimension": "change_dimension 时填写，否则空字符串",
            "modified_scope": "scope 增量或替换内容；可与 replace_expression 同时填写",
            "modified_expression": "replace_expression 时可填写完整 expression 对象，或仅填写新的 formula 字符串",
            "rationale": "为什么能降低误报",
        },
        "required_output": {
            "false_positive_reason": "误报原因分析",
            "candidates": [],
        },
        "accepted_history": accepted_history[-5:],
        "evidence": evidence,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def call_llm(prompt: str, args: argparse.Namespace) -> dict[str, Any]:
    base_url = normalize_openai_base_url(str(args.llm_url).strip())
    api_key = str(args.api_key or "").strip()
    if not base_url:
        raise ValueError("LLM requires --llm-url.")
    if not api_key:
        raise ValueError("LLM requires --api-key or AUTODL_API_KEY/LLM_API_KEY.")
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("LLM requires the OpenAI Python SDK: pip install openai") from exc

    client = OpenAI(base_url=base_url, api_key=api_key)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    last_error: Exception | None = None
    for attempt in range(args.retry + 1):
        try:
            stream = client.chat.completions.create(
                model=str(args.model).strip(),
                messages=messages,
                stream=True,
                timeout=args.request_timeout,
            )
            chunks: list[str] = []
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    chunks.append(chunk.choices[0].delta.content)
            return extract_json("".join(chunks))
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < args.retry:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"LLM rule update failed: {last_error}")


def candidate_list(response: dict[str, Any], fol_id: str, limit: int) -> list[dict[str, Any]]:
    candidates = response.get("candidates", [])
    if isinstance(candidates, dict):
        candidates = [candidates]
    output = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if str(candidate.get("fol_id", "")) != fol_id:
            continue
        action = str(candidate.get("action", ""))
        if action not in SUPPORTED_ACTIONS:
            continue
        output.append(candidate)
        if len(output) >= limit:
            break
    return output


def parse_object_maybe_json(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def parse_formula_maybe_string(value: Any) -> str:
    if isinstance(value, str):
        text = value.strip()
        if text and not text.startswith("{"):
            return text
    return ""


def merge_scope(existing: dict[str, Any], patch: Any) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    if not isinstance(patch, dict):
        return merged
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_scope(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def target_expression(rule: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any] | None:
    expressions = rule.get("logic_expressions", [])
    if not isinstance(expressions, list) or not expressions:
        return None
    index = candidate.get("expression_index")
    try:
        expression_index = int(index)
    except (TypeError, ValueError):
        expression_index = 1
    if expression_index < 1 or expression_index > len(expressions):
        return None
    expr = expressions[expression_index - 1]
    return expr if isinstance(expr, dict) else None


def as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [str(value)]
    return []


def replace_quoted_api_set(formula: str, old_values: list[str], new_values: list[str]) -> str:
    if not formula or not old_values or not new_values:
        return formula
    old_set = "{" + ",".join(json.dumps(value, ensure_ascii=False) for value in old_values) + "}"
    new_set = "{" + ",".join(json.dumps(value, ensure_ascii=False) for value in new_values) + "}"
    return formula.replace(old_set, new_set)


def sync_symbol_binding_values(expr: dict[str, Any], binding_key: str, values: list[str]) -> None:
    if not values:
        return
    symbol_bindings = expr.setdefault("symbol_bindings", {})
    if not isinstance(symbol_bindings, dict):
        return
    parameter_bindings = symbol_bindings.setdefault("parameter", {})
    if not isinstance(parameter_bindings, dict):
        return
    existing = parameter_bindings.get(binding_key, [])
    symbols = []
    if isinstance(existing, list):
        symbols = [str(item.get("symbol", "")) for item in existing if isinstance(item, dict) and item.get("symbol")]
    while len(symbols) < len(values):
        prefix = "C" if binding_key == "context_api_scope" else "T"
        symbols.append(f"{prefix}{len(symbols) + 1}")
    parameter_bindings[binding_key] = [
        {"symbol": symbols[index], "value": value}
        for index, value in enumerate(values)
    ]


def sync_expression_metadata(expr: dict[str, Any]) -> None:
    scope = expr.get("scope", {}) if isinstance(expr.get("scope"), dict) else {}
    target_apis = as_string_list(scope.get("target_api_scope"))
    context_apis = as_string_list(scope.get("context_api_scope"))
    if not target_apis and not context_apis:
        return

    detector = expr.get("detector")
    if isinstance(detector, dict):
        if target_apis:
            old_target_apis = as_string_list(detector.get("target_api_scope"))
            detector["target_api_scope"] = copy.deepcopy(target_apis)
        else:
            old_target_apis = []
        if context_apis:
            detector["context_api_scope"] = copy.deepcopy(context_apis)
        constraints = detector.get("status_code_constraints")
        if isinstance(constraints, dict) and target_apis:
            constraints["target_api_scope"] = copy.deepcopy(target_apis)
    else:
        old_target_apis = []

    if target_apis:
        sync_symbol_binding_values(expr, "target_api_scope", target_apis)
    if context_apis:
        sync_symbol_binding_values(expr, "context_api_scope", context_apis)

    formula = str(expr.get("formula", "") or "")
    if formula and target_apis:
        formula = replace_quoted_api_set(formula, old_target_apis, target_apis)
    expr["formula"] = formula


def apply_candidate(payload: dict[str, Any], fol_id: str, candidate: dict[str, Any], args: argparse.Namespace) -> dict[str, Any] | None:
    action = str(candidate.get("action", ""))
    if action == "disable" and not args.allow_disable:
        return None
    trial = copy.deepcopy(payload)
    rule = find_rule(trial, fol_id)
    if not rule:
        return None

    refinement = rule.setdefault("refinement", {})
    refinement.setdefault("accepted_updates", [])
    refinement["last_false_positive_reason"] = str(candidate.get("false_positive_reason") or "")
    refinement["last_update_rationale"] = str(candidate.get("rationale") or "")

    if action == "disable":
        refinement["disabled"] = True
        refinement["disabled_reason"] = str(candidate.get("rationale") or "LLM suggested disabling this noisy rule.")
    elif action == "replace_expression":
        expr = target_expression(rule, candidate)
        if expr is None:
            return None
        replacement = parse_object_maybe_json(candidate.get("modified_expression"))
        formula = parse_formula_maybe_string(candidate.get("modified_expression"))
        if replacement is None and not formula and not isinstance(candidate.get("modified_scope"), (dict, str)):
            return None
        try:
            expression_index = int(candidate.get("expression_index") or 1)
        except (TypeError, ValueError):
            expression_index = 1
        if replacement is not None:
            expr = copy.deepcopy(replacement)
            rule["logic_expressions"][expression_index - 1] = expr
        if formula:
            expr["formula"] = formula
        scope_patch = parse_object_maybe_json(candidate.get("modified_scope"))
        if scope_patch is not None:
            scope = expr.setdefault("scope", {})
            if not isinstance(scope, dict):
                return None
            expr["scope"] = merge_scope(scope, scope_patch)
        sync_expression_metadata(expr)
    else:
        expr = target_expression(rule, candidate)
        if expr is None:
            return None
        if action == "change_dimension":
            new_dimension = str(candidate.get("new_dimension", "")).strip()
            if not new_dimension:
                return None
            expr["dimension"] = new_dimension
        scope = expr.setdefault("scope", {})
        if not isinstance(scope, dict):
            return None
        if action == "raise_threshold":
            try:
                new_threshold = int(candidate.get("new_threshold"))
            except (TypeError, ValueError):
                return None
            if expr.get("dimension") == "parameter_consistency":
                scope["min_distinct_target_values"] = new_threshold
            else:
                scope["threshold"] = new_threshold
        elif action in {"add_context_requirement", "add_precondition", "narrow_api_scope", "change_dimension"}:
            scope_patch = parse_object_maybe_json(candidate.get("modified_scope"))
            if scope_patch is None:
                return None
            expr["scope"] = merge_scope(scope, scope_patch)
        sync_expression_metadata(expr)

    refinement["accepted_updates"].append(
        {
            "action": action,
            "expression_index": candidate.get("expression_index"),
            "rationale": candidate.get("rationale", ""),
        }
    )
    return trial


def candidate_applicability_reason(payload: dict[str, Any], fol_id: str, candidate: dict[str, Any], args: argparse.Namespace) -> str:
    action = str(candidate.get("action", ""))
    if action == "disable" and not args.allow_disable:
        return "disable_candidate_requires_--allow-disable"
    rule = find_rule(payload, fol_id)
    if not rule:
        return "target_rule_not_found"
    if action == "replace_expression":
        if target_expression(rule, candidate) is None:
            return "expression_index_not_found"
        if (
            parse_object_maybe_json(candidate.get("modified_expression")) is None
            and not parse_formula_maybe_string(candidate.get("modified_expression"))
            and parse_object_maybe_json(candidate.get("modified_scope")) is None
        ):
            return "modified_expression_or_modified_scope_required"
    if action in {"add_context_requirement", "add_precondition", "narrow_api_scope", "change_dimension"}:
        if target_expression(rule, candidate) is None:
            return "expression_index_not_found"
        if action != "change_dimension" and parse_object_maybe_json(candidate.get("modified_scope")) is None:
            return "modified_scope_must_be_json_object_or_object"
    if action == "raise_threshold":
        try:
            int(candidate.get("new_threshold"))
        except (TypeError, ValueError):
            return "new_threshold_must_be_integer"
    return "applicable"


def score(replay: dict[str, Any]) -> dict[str, Any]:
    return {
        "labeled_scoring_available": bool(replay.get("labeled_scoring_available")),
        "f1": float(replay.get("f1", 0.0) or 0.0),
        "precision": float(replay.get("precision", 0.0) or 0.0),
        "recall": float(replay.get("recall", 0.0) or 0.0),
        "false_positive_session_count": int(replay.get("false_positive_session_count", replay.get("hit_session_count", 0)) or 0),
        "false_positive_rate": float(replay.get("false_positive_rate", 0.0) or 0.0),
        "hit_session_count": int(replay.get("hit_session_count", 0) or 0),
        "hit_count": int(replay.get("hit_count", 0) or 0),
    }


def is_better(candidate_replay: dict[str, Any], baseline_replay: dict[str, Any]) -> bool:
    candidate = score(candidate_replay)
    baseline = score(baseline_replay)
    if candidate["labeled_scoring_available"] and baseline["labeled_scoring_available"]:
        if candidate["f1"] > baseline["f1"] + 1e-9:
            return True
        if abs(candidate["f1"] - baseline["f1"]) <= 1e-9:
            return (
                candidate["false_positive_session_count"],
                candidate["hit_count"],
            ) < (
                baseline["false_positive_session_count"],
                baseline["hit_count"],
            )
        return False
    return (
        candidate["false_positive_session_count"],
        candidate["hit_count"],
    ) < (
        baseline["false_positive_session_count"],
        baseline["hit_count"],
    )


def better_sort_key(replay: dict[str, Any]) -> tuple[float, int, int]:
    item = score(replay)
    if item["labeled_scoring_available"]:
        return (-item["f1"], item["false_positive_session_count"], item["hit_count"])
    return (0.0, item["false_positive_session_count"], item["hit_count"])


def evaluate_candidates(
    payload: dict[str, Any],
    fol_id: str,
    rule_replay: dict[str, Any],
    full_replay: dict[str, Any],
    candidates: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    args: argparse.Namespace,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    evaluated = []
    best: dict[str, Any] | None = None
    for candidate in candidates:
        trial_payload = apply_candidate(payload, fol_id, candidate, args)
        record = {"candidate": candidate, "accepted": False}
        if trial_payload is None:
            record["reason"] = candidate_applicability_reason(payload, fol_id, candidate, args)
            evaluated.append(record)
            continue
        trial_rule_replay = replay_single_rule(trial_payload, fol_id, sessions, args.max_evidence_sessions_per_rule)
        trial_full_replay = replay_rules(trial_payload, sessions, args.max_evidence_sessions_per_rule)
        record["before_rule_score"] = score(rule_replay)
        record["after_rule_score"] = score(trial_rule_replay)
        record["before_full_score"] = score(full_replay)
        record["after_full_score"] = score(trial_full_replay)
        if is_better(trial_rule_replay, rule_replay):
            record["accepted"] = True
            record["_trial_payload"] = trial_payload
            record["_trial_rule_replay"] = trial_rule_replay
            record["_trial_full_replay"] = trial_full_replay
            if best is None or better_sort_key(trial_rule_replay) < better_sort_key(best["_trial_rule_replay"]):
                best = record
        evaluated.append(record)
    return best, evaluated


def report_payload(
    args: argparse.Namespace,
    fol_file: Path,
    next_rules_file: Path,
    sessions: list[dict[str, Any]],
    initial_replay: dict[str, Any],
    final_replay: dict[str, Any],
    rule_runs: list[dict[str, Any]],
    stopped_reason: str,
) -> dict[str, Any]:
    return {
        "site_id": args.site_id,
        "fol_file": str(fol_file),
        "next_rules_file": str(next_rules_file),
        "session_count": len(sessions),
        "normal_data_assumption": (
            "使用 --validation-input-dir 时加载带标签验证集并按逐规则 F1 优化；否则默认仅加载正常会话，命中按误报计入。"
        ),
        "target_rule_fp_rate": args.target_rule_fp_rate,
        "target_rule_min_f1": args.target_rule_min_f1,
        "min_rule_fp_sessions": args.min_rule_fp_sessions,
        "validation_input_dir": str(getattr(args, "validation_input_dir", "") or ""),
        "initial_detection": {
            key: initial_replay.get(key)
            for key in (
                "session_count",
                "normal_session_count",
                "anomalous_session_count",
                "labeled_scoring_available",
                "active_rule_count",
                "hit_session_count",
                "hit_count",
                "true_positive_session_count",
                "false_positive_session_count",
                "false_negative_session_count",
                "false_positive_rate",
                "precision",
                "recall",
                "f1",
                "rule_false_positive_stats",
            )
        },
        "final_detection": {
            key: final_replay.get(key)
            for key in (
                "session_count",
                "normal_session_count",
                "anomalous_session_count",
                "labeled_scoring_available",
                "active_rule_count",
                "hit_session_count",
                "hit_count",
                "true_positive_session_count",
                "false_positive_session_count",
                "false_negative_session_count",
                "false_positive_rate",
                "precision",
                "recall",
                "f1",
                "rule_false_positive_stats",
            )
        },
        "accepted_change_count": sum(len(run.get("accepted_changes", [])) for run in rule_runs),
        "rule_runs": rule_runs,
        "stopped_reason": stopped_reason,
    }


def run_rule_update(args: argparse.Namespace) -> dict[str, Any]:
    base_dir = Path(args.base_dir)
    fol_file = Path(args.fol_file) if args.fol_file else default_fol_file(base_dir, args.site_id)
    next_rules_file = Path(args.next_rules_file) if args.next_rules_file else default_next_rules_file(base_dir, args.site_id)
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "fol_rule_updates"
    report_file = output_dir / f"site_{args.site_id}_rule_update_report.json"

    current_payload = read_json(fol_file)
    sessions = load_replay_sessions(args, base_dir)
    initial_replay = replay_rules(current_payload, sessions, args.max_evidence_sessions_per_rule)
    current_replay = initial_replay
    rule_runs: list[dict[str, Any]] = []
    selected_rules = selected_rules_for_update(current_payload, current_replay, args)

    if args.dry_run:
        for item in selected_rules:
            fol_id = str(item.get("fol_id", ""))
            if item.get("selection_error"):
                rule_runs.append(
                    {
                        "fol_id": fol_id,
                        "rounds": [],
                        "accepted_changes": [],
                        "stopped_reason": item.get("selection_error"),
                    }
                )
                continue
            rule_replay = replay_single_rule(current_payload, fol_id, sessions, args.max_evidence_sessions_per_rule)
            evidence = build_rule_evidence(current_payload, fol_id, rule_replay, sessions, args)
            prompt = build_prompt(evidence, [])
            prompt_file = output_dir / "prompts" / f"site_{args.site_id}_rule_{fol_id}_prompt.txt"
            prompt_file.parent.mkdir(parents=True, exist_ok=True)
            prompt_file.write_text(prompt, encoding="utf-8")
            rule_runs.append(
                {
                    "fol_id": fol_id,
                    "initial_rule_false_positive_score": score(rule_replay),
                    "final_rule_false_positive_score": score(rule_replay),
                    "rounds": [
                        {
                            "round": 0,
                            "before_rule_false_positive_score": score(rule_replay),
                            "prompt_file": str(prompt_file),
                            "evaluated_candidates": [],
                            "accepted": None,
                        }
                    ],
                    "accepted_changes": [],
                    "stopped_reason": "dry_run_prompt_generation_only",
                }
            )
        write_json(next_rules_file, current_payload)
        report = report_payload(args, fol_file, next_rules_file, sessions, initial_replay, current_replay, rule_runs, "dry_run_prompt_generation_only")
        write_json(report_file, report)
        return report

    for noisy in selected_rules:
        fol_id = str(noisy.get("fol_id", ""))
        if noisy.get("selection_error"):
            rule_runs.append(
                {
                    "fol_id": fol_id,
                    "rounds": [],
                    "accepted_changes": [],
                    "stopped_reason": noisy.get("selection_error"),
                }
            )
            continue
        target_fol_ids = {clean_fol_id(item) for item in getattr(args, "target_fol_id", []) or [] if clean_fol_id(item)}
        force_target_rule = fol_id in target_fol_ids
        accepted_history: list[dict[str, Any]] = []
        rule_run = {
            "fol_id": fol_id,
            "initial_rule_false_positive_score": None,
            "final_rule_false_positive_score": None,
            "rounds": [],
            "accepted_changes": [],
            "stopped_reason": "",
        }
        for round_index in range(1, args.max_iterations_per_rule + 1):
            rule_replay = replay_single_rule(current_payload, fol_id, sessions, args.max_evidence_sessions_per_rule)
            if rule_run["initial_rule_false_positive_score"] is None:
                rule_run["initial_rule_false_positive_score"] = score(rule_replay)
            rule_score = score(rule_replay)
            if not force_target_rule and rule_score["labeled_scoring_available"] and (
                rule_score["f1"] >= args.target_rule_min_f1
                and rule_score["false_positive_rate"] <= args.target_rule_fp_rate
            ):
                rule_run["stopped_reason"] = "rule_f1_and_false_positive_rate_within_threshold"
                break
            if not force_target_rule and not rule_score["labeled_scoring_available"] and (
                rule_score["false_positive_session_count"] < args.min_rule_fp_sessions
                or rule_score["false_positive_rate"] <= args.target_rule_fp_rate
            ):
                rule_run["stopped_reason"] = "rule_false_positive_rate_below_threshold"
                break

            evidence = build_rule_evidence(current_payload, fol_id, rule_replay, sessions, args)
            prompt = build_prompt(evidence, accepted_history)
            prompt_file = output_dir / "prompts" / f"site_{args.site_id}_rule_{fol_id}_round_{round_index}_prompt.txt"
            prompt_file.parent.mkdir(parents=True, exist_ok=True)
            prompt_file.write_text(prompt, encoding="utf-8")
            round_record: dict[str, Any] = {
                "round": round_index,
                "before_rule_false_positive_score": score(rule_replay),
                "false_positive_reason": "",
                "evaluated_candidates": [],
                "accepted": None,
            }
            try:
                llm_response = call_llm(prompt, args)
                false_positive_reason = str(llm_response.get("false_positive_reason", ""))
                candidates = candidate_list(llm_response, fol_id, args.max_candidates_per_rule)
                for candidate in candidates:
                    candidate["false_positive_reason"] = false_positive_reason
                best, evaluated = evaluate_candidates(current_payload, fol_id, rule_replay, current_replay, candidates, sessions, args)
                round_record["false_positive_reason"] = false_positive_reason
                round_record["evaluated_candidates"] = [
                    {key: value for key, value in item.items() if not key.startswith("_")}
                    for item in evaluated
                ]
                if best is None:
                    rule_run["rounds"].append(round_record)
                    continue
                current_payload = best.pop("_trial_payload")
                current_replay = best.pop("_trial_full_replay")
                best.pop("_trial_rule_replay")
                accepted_history.append(best)
                accepted_change = {
                    "round": round_index,
                    "false_positive_reason": false_positive_reason,
                    "candidate": best.get("candidate", {}),
                    "before_rule_score": best.get("before_rule_score"),
                    "after_rule_score": best.get("after_rule_score"),
                }
                rule_run["accepted_changes"].append(accepted_change)
                round_record["accepted"] = accepted_change
            except Exception as exc:  # noqa: BLE001
                round_record["error"] = f"llm_or_verifier_failed: {exc}"
            rule_run["rounds"].append(round_record)

        final_rule_replay = replay_single_rule(current_payload, fol_id, sessions, args.max_evidence_sessions_per_rule)
        rule_run["final_rule_false_positive_score"] = score(final_rule_replay)
        if not rule_run["stopped_reason"]:
            rule_run["stopped_reason"] = "max_iterations_reached"
        rule_runs.append(rule_run)
        write_json(next_rules_file, current_payload)
        report = report_payload(args, fol_file, next_rules_file, sessions, initial_replay, current_replay, rule_runs, "running")
        write_json(report_file, report)

    final_replay = replay_rules(current_payload, sessions, args.max_evidence_sessions_per_rule)
    write_json(next_rules_file, current_payload)
    report = report_payload(args, fol_file, next_rules_file, sessions, initial_replay, final_replay, rule_runs, "completed")
    write_json(report_file, report)
    return report


def run_rule_merge(args: argparse.Namespace) -> dict[str, Any]:
    base_dir = Path(args.base_dir)
    base_file = Path(args.base_fol_file) if args.base_fol_file else default_fol_file(base_dir, args.site_id)
    updated_file = Path(args.updated_fol_file) if args.updated_fol_file else default_next_rules_file(base_dir, args.site_id)
    output_file = Path(args.output_file) if args.output_file else base_dir / "fol_expressions" / f"site_{args.site_id}_fol_expressions_merged.json"
    base_payload = read_json(base_file)
    updated_payload = read_json(updated_file)
    updated_by_id = {
        str(rule.get("fol_id", "")): rule
        for rule in updated_payload.get("expressions", [])
        if isinstance(rule, dict) and rule.get("fol_id")
    }
    merged = copy.deepcopy(base_payload)
    replaced = []
    for index, rule in enumerate(merged.get("expressions", [])):
        fol_id = str(rule.get("fol_id", ""))
        if fol_id in updated_by_id:
            merged["expressions"][index] = copy.deepcopy(updated_by_id[fol_id])
            replaced.append(fol_id)
    write_json(output_file, merged)
    report = {
        "site_id": args.site_id,
        "base_fol_file": str(base_file),
        "updated_fol_file": str(updated_file),
        "merged_rules_file": str(output_file),
        "summary": {
            "base_rule_count": len(base_payload.get("expressions", [])),
            "updated_rule_count": len(updated_payload.get("expressions", [])),
            "merged_rule_count": len(merged.get("expressions", [])),
            "replaced_fol_ids": replaced,
            "appended_fol_ids": [],
        },
    }
    return report


def parse_merge_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge verified rule updates into a merged FOL rule file.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--base-fol-file", default="")
    parser.add_argument("--updated-fol-file", default="")
    parser.add_argument("--output-file", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_rule_update(args)
    initial = report.get("initial_detection", {})
    final = report.get("final_detection", {})
    print(
        f"site={args.site_id} sessions={report.get('session_count', 0)} "
        f"initial_fp_rate={float(initial.get('false_positive_rate') or 0.0):.4f} "
        f"final_fp_rate={float(final.get('false_positive_rate') or 0.0):.4f} "
        f"initial_f1={float(initial.get('f1') or 0.0):.4f} "
        f"final_f1={float(final.get('f1') or 0.0):.4f} "
        f"accepted_changes={report.get('accepted_change_count', 0)} "
        f"next_rules_file={report.get('next_rules_file', '')}"
    )


if __name__ == "__main__":
    main()
