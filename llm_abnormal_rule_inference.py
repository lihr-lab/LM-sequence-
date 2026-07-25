# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib import error, request


DEFAULT_BASE_DIR = str(Path(__file__).resolve().parent / "artifacts" / "train")
DEFAULT_AUTODL_BASE_URL = "https://www.autodl.art/api/v1"
DEFAULT_AUTODL_MODEL = "GLM-5"
DEFAULT_REVIEW_SYSTEM_PROMPT = (
    "你是面向 API 访问控制检测流水线的异常会话安全规则反推专家。"
    "你的任务很明确：输入已经是异常/攻击会话聚类，不再判断其是否代表正常业务，而是直接从异常行为证据反推出可检测的安全场景和规则生成要素。"
    "请从风险角度组织分析，而不是先做冗长的顺序分析和参数一致性分析。"
    "每个场景必须先给出风险类型和简短示例，再指出可能被攻击的点、攻击者如何攻击、需要检查的参数约束和状态码证据。"
    "候选风险只考虑五类：BOLA 对象级越权、BOPLA 属性级越权、BFLA 功能级越权、AUTH_BYPASS 认证授权绕过、RESOURCE_CONSUMPTION 资源消耗。"
    "所有顺序活动、正常链路、违规链路、related_apis、context_apis、target_apis 必须使用输入日志中真实出现的 METHOD /path API；"
    "禁止生成“用户应先登录并经过权限校验”“Admin Role Check”“在具备管理权限的前提下访问”等自然语言活动或虚拟 API。"
    "安全场景必须保持小而可检测：每个参数一致性场景最多保留 1 到 3 个核心 context_apis、1 到 2 个核心 target_apis；"
    "禁止把整条业务流程、整组管理接口或大量候选 API 塞进一个 ParameterFlowContext。"
    "参数相关场景必须严格保持单一攻击面：每个场景只围绕一个参数、一个同义映射参数对，或一组必须共同传递的关联参数；"
    "不要把多个无关联或互为或关系的参数揉进一个场景。"
    "响应码只能作为可信度、命中条件和风险等级证据，不能替代参数流动、角色权限或顺序约束分析。"
    "所有结论必须来自输入证据；证据不足时保守输出空场景或标记需要 OpenAPI/原始请求确认。"
    "只输出合法 JSON。"
)
HTTP_API_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+", re.I)
PARAM_TOKEN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Key|Name|Token|Role|Permission|Status|Type|Level|Number))\b")
NO_RISK_RE = re.compile(r"(无明显|无参数风险|无顺序风险|无法确定|无法推断|依据不足|none|not applicable|n/a)", re.I)
SEQUENCE_SIGNAL_RE = re.compile(r"(跳过|越序|提前|缺失|重复|先.*后|直接调用|绕过|order|sequence|repeat|missing|skip)", re.I)
PARAMETER_SIGNAL_RE = re.compile(r"(参数|对象|标识|id|key|token|上下文|来源|绑定|中途替换|不一致|跨对象|parameter|context|binding)", re.I)
BENIGN_POLLING_RE = re.compile(
    r"(/notification/count|/quickreload/|/status/|/heartbeat|/ping|/health|/keepalive|/poll|/longpoll|"
    r"/events|/activity|/presence|/unread|/badge|/counter|/count(?:$|[/?#]))",
    re.I,
)
RESOURCE_IMPACT_RE = re.compile(r"(耗尽|打满|过载|异常高频|短时间|大量|洪泛|拒绝服务|dos|ddos|burst|flood|exhaust|overload|rate.?limit)", re.I)
VIRTUAL_SEQUENCE_STEP_RE = re.compile(
    r"(Admin\s*Role\s*Check|用户应先登录|先登录|经过权限校验|具备管理权限|普通用户|未授权|低权限|"
    r"权限矩阵|角色检查|授权检查|认证检查|在具备.*权限.*前提|attacker|authorized user)",
    re.I,
)
MAX_CONTEXT_APIS_PER_PARAMETER_SCENARIO = 3
MAX_TARGET_APIS_PER_PARAMETER_SCENARIO = 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Use an LLM to infer security scenarios directly from abnormal API session clusters.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--cluster-file", default="", help="Default: <base-dir>/process_mining/site_<site_id>_business_session_clusters.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/process_mining/llm_abnormal_rule_inference")
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--openapi-file", default="", help="Default: <base-dir>/API_document/site_<site_id>_openapi.json")
    parser.add_argument("--parameter-profile-file", default="", help="Default: <base-dir>/parameter_profiles/site_<site_id>_parameter_profile.json")
    parser.add_argument("--max-openapi-context-paths", type=int, default=12, help="Maximum OpenAPI path summaries included in each review prompt.")
    parser.add_argument("--llm-url", default=os.getenv("AUTODL_BASE_URL", os.getenv("LLM_URL", DEFAULT_AUTODL_BASE_URL)), help="AutoDL OpenAI-compatible API base URL.")
    parser.add_argument("--model", default=os.getenv("AUTODL_MODEL", os.getenv("LLM_MODEL", DEFAULT_AUTODL_MODEL)), help="AutoDL model name.")
    parser.add_argument("--api-key", default=os.getenv("AUTODL_API_KEY", os.getenv("LLM_API_KEY", "")), help="AutoDL API key.")
    parser.add_argument("--max-clusters", type=int, default=0, help="0 means all clusters.")
    parser.add_argument("--members-per-cluster", type=int, default=3)
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--head-steps", type=int, default=18)
    parser.add_argument("--tail-steps", type=int, default=12)
    parser.add_argument("--max-prompt-chars", type=int, default=30000)
    parser.add_argument("--request-timeout", type=int, default=120)
    parser.add_argument("--retry", type=int, default=2)
    parser.add_argument("--min-confidence-sequence-length", type=int, default=1, help="Abnormal clusters shorter than this are skipped. Default keeps almost all abnormal sessions.")
    parser.add_argument("--rerun-all", action="store_true", help="Re-review clusters even if they already exist in the output file.")
    parser.add_argument("--dry-run", action="store_true", help="Only write prompts, do not call LLM.")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_openai_base_url(url: str) -> str:
    text = str(url or "").strip().rstrip("/")
    suffix = "/chat/completions"
    if text.lower().endswith(suffix):
        return text[: -len(suffix)]
    return text


def trim_trace(trace: list[Any], max_steps: int, head_steps: int, tail_steps: int) -> list[str]:
    items = [str(item) for item in trace]
    if len(items) <= max_steps:
        return items
    head_count = max(1, min(head_steps, max_steps))
    tail_count = max(0, min(tail_steps, max_steps - head_count))
    output = items[:head_count]
    omitted = len(items) - head_count - tail_count
    if omitted > 0:
        output.append(f"... omitted_steps={omitted}, total_steps={len(items)}")
    if tail_count > 0:
        output.extend(items[-tail_count:])
    return output


def trim_items(items: list[Any], max_steps: int, head_steps: int, tail_steps: int) -> list[Any]:
    if len(items) <= max_steps:
        return items
    head_count = max(1, min(head_steps, max_steps))
    tail_count = max(0, min(tail_steps, max_steps - head_count))
    output = list(items[:head_count])
    omitted = len(items) - head_count - tail_count
    if omitted > 0:
        output.append({"omitted_steps": omitted, "total_steps": len(items)})
    if tail_count > 0:
        output.extend(items[-tail_count:])
    return output


def parse_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def status_family(status: int) -> str:
    if status <= 0:
        return "unknown"
    return f"{status // 100}xx"


def api_without_status(token: str) -> str:
    return str(token or "").strip()


def api_method_path(token: Any) -> tuple[str, str]:
    text = str(token or "").strip()
    if " BODY " in text:
        text = text.split(" BODY ", 1)[0].strip()
    match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", text, re.I)
    if not match:
        return "", ""
    method = match.group(1).lower()
    path = match.group(2)
    if "?" in path:
        path = path.split("?", 1)[0]
    path = re.sub(r"^https?://[^/]+", "", path)
    return method, path or "/"


def openapi_path_regex(path_template: str) -> re.Pattern[str]:
    parts = [part for part in str(path_template or "/").strip("/").split("/") if part]
    regex_parts = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            regex_parts.append(r"[^/]+")
        else:
            regex_parts.append(re.escape(part))
    pattern = "^/" + "/".join(regex_parts) + "$"
    return re.compile(pattern)


def collect_cluster_api_tokens(cluster: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for key in ("representative_trace_sample",):
        values = cluster.get(key, [])
        if isinstance(values, list):
            tokens.extend(str(item) for item in values if isinstance(item, str))
    for key in ("representative_event_sample", "sampled_members"):
        values = cluster.get(key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, dict) and item.get("api"):
                tokens.append(str(item["api"]))
            elif isinstance(item, dict) and isinstance(item.get("event_sample"), list):
                tokens.extend(str(event.get("api")) for event in item["event_sample"] if isinstance(event, dict) and event.get("api"))
    return [token for token in tokens if HTTP_API_RE.match(token)]


def load_openapi_context(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"openapi_file": str(path), "available": False, "paths": []}
    doc = read_json(path)
    paths = doc.get("paths", {}) if isinstance(doc, dict) else {}
    summaries = []
    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_lower = str(method).lower()
            if method_lower not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            params = []
            for param in operation.get("parameters", []) or []:
                if isinstance(param, dict):
                    params.append(
                        {
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "required": bool(param.get("required", False)),
                        }
                    )
            body_keys: list[str] = []
            body = operation.get("requestBody", {})
            if isinstance(body, dict):
                body_text = json.dumps(body, ensure_ascii=False)
                body_keys = sorted(set(re.findall(r'"([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Key|Name|Token|Role|Status|Type|Level)?)"', body_text)))[:12]
            summaries.append(
                {
                    "method": method_lower.upper(),
                    "path": str(path_template),
                    "summary": operation.get("summary", ""),
                    "operationId": operation.get("operationId", ""),
                    "parameters": params[:12],
                    "request_body_keys": body_keys,
                    "_regex": openapi_path_regex(str(path_template)),
                }
            )
    return {"openapi_file": str(path), "available": True, "paths": summaries}


def compact_profile_params(params: Any, limit: int = 12) -> list[dict[str, Any]]:
    if not isinstance(params, dict):
        return []
    output = []
    for name, item in sorted(params.items(), key=lambda kv: float(kv[1].get("required_ratio", 0) if isinstance(kv[1], dict) else 0), reverse=True):
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "name": str(name),
                "required_ratio": item.get("required_ratio", 0),
                "types": item.get("types", [])[:4] if isinstance(item.get("types"), list) else [],
                "examples": item.get("examples", [])[:1] if isinstance(item.get("examples"), list) else [],
            }
        )
        if len(output) >= limit:
            break
    return output


def load_parameter_profile_context(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"parameter_profile_file": str(path), "available": False, "paths": []}
    doc = read_json(path)
    profile_paths = doc.get("paths", []) if isinstance(doc, dict) else []
    summaries = []
    for path_item in profile_paths:
        if not isinstance(path_item, dict):
            continue
        path_template = str(path_item.get("openapi_path") or path_item.get("path") or "")
        methods = path_item.get("methods", {})
        if not path_template or not isinstance(methods, dict):
            continue
        for method, method_item in methods.items():
            if not isinstance(method_item, dict):
                continue
            method_upper = str(method).upper()
            summaries.append(
                {
                    "method": method_upper,
                    "path": path_template,
                    "raw_profile_path": path_item.get("path", ""),
                    "request_count": method_item.get("request_count", 0),
                    "path_params": compact_profile_params(method_item.get("path", {}).get("params", {}) if isinstance(method_item.get("path"), dict) else {}),
                    "query_params": compact_profile_params(method_item.get("query", {}).get("params", {}) if isinstance(method_item.get("query"), dict) else {}),
                    "body_params": compact_profile_params(method_item.get("body", {}).get("params", {}) if isinstance(method_item.get("body"), dict) else {}),
                    "header_params": compact_profile_params(method_item.get("header", {}).get("params", {}) if isinstance(method_item.get("header"), dict) else {}, 8),
                    "query_param_sets": method_item.get("query", {}).get("param_sets", [])[:6] if isinstance(method_item.get("query"), dict) else [],
                    "body_param_sets": method_item.get("body", {}).get("param_sets", [])[:6] if isinstance(method_item.get("body"), dict) else [],
                    "_regex": openapi_path_regex(path_template),
                }
            )
    return {"parameter_profile_file": str(path), "available": True, "paths": summaries}


def relevant_openapi_context(cluster: dict[str, Any], openapi_context: dict[str, Any], max_paths: int) -> dict[str, Any]:
    if not openapi_context.get("available"):
        return openapi_context
    matched: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for token in collect_cluster_api_tokens(cluster):
        method, path = api_method_path(token)
        if not method or not path:
            continue
        for item in openapi_context.get("paths", []):
            if item.get("method", "").lower() != method:
                continue
            regex = item.get("_regex")
            if not isinstance(regex, re.Pattern) or not regex.match(path):
                continue
            key = (str(item.get("method")), str(item.get("path")))
            if key in seen:
                continue
            seen.add(key)
            public_item = {k: v for k, v in item.items() if k != "_regex"}
            public_item["matched_api"] = token
            matched.append(public_item)
            break
        if len(matched) >= max_paths:
            break
    return {
        "openapi_file": openapi_context.get("openapi_file", ""),
        "available": True,
        "matched_path_count": len(matched),
        "paths": matched,
    }


def relevant_parameter_profile_context(cluster: dict[str, Any], profile_context: dict[str, Any], max_paths: int) -> dict[str, Any]:
    if not profile_context.get("available"):
        return profile_context
    matched: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for token in collect_cluster_api_tokens(cluster):
        method, path = api_method_path(token)
        if not method or not path:
            continue
        for item in profile_context.get("paths", []):
            if item.get("method", "").lower() != method:
                continue
            regex = item.get("_regex")
            if not isinstance(regex, re.Pattern) or not regex.match(path):
                continue
            key = (str(item.get("method")), str(item.get("path")))
            if key in seen:
                continue
            seen.add(key)
            public_item = {k: v for k, v in item.items() if k != "_regex"}
            public_item["matched_api"] = token
            matched.append(public_item)
            break
        if len(matched) >= max_paths:
            break
    return {
        "parameter_profile_file": profile_context.get("parameter_profile_file", ""),
        "available": True,
        "matched_path_count": len(matched),
        "paths": matched,
    }


def build_api_document_context(
    cluster: dict[str, Any],
    openapi_context: dict[str, Any],
    profile_context: dict[str, Any],
    max_paths: int,
) -> dict[str, Any]:
    matched_profile = relevant_parameter_profile_context(cluster, profile_context, max_paths)
    matched_openapi = relevant_openapi_context(cluster, openapi_context, max_paths)
    if matched_profile.get("matched_path_count", 0) > 0:
        matched_openapi = {
            "openapi_file": matched_openapi.get("openapi_file", ""),
            "available": bool(matched_openapi.get("available")),
            "matched_path_count": matched_openapi.get("matched_path_count", 0),
            "paths": [],
            "omitted_reason": "parameter_profile_context 已提供真实日志参数画像，本 prompt 省略 OpenAPI 明细以避免重复和过长。",
        }
    return {
        "context_policy": (
            "参数画像来自真实请求日志，包含真实 query/body/header/path 参数、出现比例、类型和样例；"
            "推导参数一致性安全场景时优先使用 parameter_profile_context。"
            "OpenAPI 只作为补充说明；两者冲突时以参数画像和原始请求证据为准。"
        ),
        "openapi_context": matched_openapi,
        "parameter_profile_context": matched_profile,
    }


def status_summary(
    raw_trace: list[Any],
    api_trace: list[Any] | None = None,
    status_sequence: list[Any] | None = None,
    top_n: int = 10,
) -> dict[str, Any]:
    raw_items = [str(item) for item in raw_trace]
    api_items = [str(item) for item in (api_trace if api_trace is not None else raw_trace)]
    statuses = [parse_int(item) for item in status_sequence] if isinstance(status_sequence, list) else []
    if len(statuses) != len(raw_items):
        statuses = [0 for _ in raw_items]
    known_statuses = [status for status in statuses if status > 0]
    status_counter = Counter(str(status) for status in known_statuses)
    family_counter = Counter(status_family(status) for status in known_statuses)
    api_status_counter: Counter[tuple[str, str]] = Counter()
    for api, raw, status in zip(api_items, raw_items, statuses):
        if status > 0:
            api_status_counter[(api_without_status(api or raw), str(status))] += 1
    return {
        "known_status_count": len(known_statuses),
        "unknown_status_count": max(0, len(raw_items) - len(known_statuses)),
        "status_distribution": dict(sorted(status_counter.items())),
        "status_family_distribution": dict(sorted(family_counter.items())),
        "top_api_statuses": [
            {"api": api, "status": status, "count": count}
            for (api, status), count in api_status_counter.most_common(top_n)
        ],
    }


def compact_status_summary(summary: Any, top_n: int = 12) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    compact = {
        "known_status_count": summary.get("known_status_count", 0),
        "unknown_status_count": summary.get("unknown_status_count", 0),
        "status_distribution": summary.get("status_distribution", {}),
        "status_family_distribution": summary.get("status_family_distribution", {}),
    }
    top_api_statuses = summary.get("top_api_statuses", [])
    if isinstance(top_api_statuses, list):
        compact["top_api_statuses"] = top_api_statuses[:top_n]
    return compact


def trace_summary(trace: list[Any]) -> dict[str, Any]:
    items = [str(item) for item in trace]
    return {
        "length": len(items),
        "unique_api_count": len(set(items)),
        "start": items[0] if items else "",
        "end": items[-1] if items else "",
        "top_apis": [
            {"api": api, "count": count}
            for api, count in Counter(items).most_common(8)
        ],
    }


def event_trace_summary(events: list[Any]) -> dict[str, Any]:
    apis = [str(event.get("api", "")) for event in events if isinstance(event, dict) and event.get("api")]
    return trace_summary(apis)


def compact_cluster(cluster: dict[str, Any], cluster_index: int, args: argparse.Namespace) -> dict[str, Any]:
    members = cluster.get("member_sessions", [])
    compact_members = []
    for member in members[: args.members_per_cluster]:
        member_trace = member.get("trace", [])
        member_events = member.get("events", [])
        compact_members.append(
            {
                "session_id": member.get("session_id", ""),
                "distance_to_representative": member.get("distance_to_representative"),
                "length": member.get("length"),
                "summary": event_trace_summary(member_events) if member_events else trace_summary(member_trace),
                "status_summary": compact_status_summary(member.get("status_summary", {})),
                "trace_sample": trim_trace(member_trace, args.max_steps, args.head_steps, args.tail_steps),
                "event_sample": trim_items(member_events, args.max_steps, args.head_steps, args.tail_steps) if member_events else [],
            }
        )
    representative_trace = cluster.get("representative_trace", [])
    representative_events = cluster.get("representative_events", [])
    representative_status = cluster.get("representative_status_summary", {})
    cluster_status = cluster.get("cluster_status_summary") or representative_status
    return {
        "cluster_index": cluster_index,
        "cluster_size": cluster.get("cluster_size"),
        "representative_session_id": cluster.get("representative_session_id", ""),
        "representative_length": cluster.get("representative_length"),
        "representative_summary": event_trace_summary(representative_events) if representative_events else trace_summary(representative_trace),
        "representative_trace_sample": trim_trace(representative_trace, args.max_steps, args.head_steps, args.tail_steps),
        "representative_event_sample": trim_items(representative_events, args.max_steps, args.head_steps, args.tail_steps) if representative_events else [],
        "status_code_evidence": {
            "cluster_status_summary": compact_status_summary(cluster_status),
            "representative_status_summary": compact_status_summary(representative_status),
            "interpretation_hint": (
                "结合簇级状态码分布、代表序列状态码、关键 API/前置 API/目标 API 的状态码判断风险可信度；"
                "2xx/3xx 支持请求可能被处理，401/403 支持权限控制或探测，404 支持对象不存在或隐藏式权限控制，"
                "5xx 支持异常处理或资源消耗风险。"
            ),
        },
        "sampled_members": compact_members,
    }


def is_confidence_reviewable(cluster: dict[str, Any], min_sequence_length: int) -> bool:
    try:
        representative_length = int(cluster.get("representative_length", 0) or 0)
    except (TypeError, ValueError):
        representative_length = len(as_text_list(cluster.get("representative_trace_sample", [])))
    return representative_length >= max(1, min_sequence_length)


def short_sequence_filter_record(cluster: dict[str, Any], min_sequence_length: int) -> dict[str, Any]:
    return {
        "cluster_index": cluster.get("cluster_index"),
        "cluster_size": cluster.get("cluster_size"),
        "representative_session_id": cluster.get("representative_session_id", ""),
        "representative_length": cluster.get("representative_length"),
        "min_confidence_sequence_length": min_sequence_length,
        "reason": "代表序列长度低于聚类置信度判断阈值，已在代码层过滤，不调用 LLM 生成安全场景。",
    }


def build_prompt(
    site_id: str,
    cluster: dict[str, Any],
    algorithm: dict[str, Any],
    openapi_context: dict[str, Any] | None = None,
) -> str:
    compact = json.dumps(cluster, ensure_ascii=False, separators=(",", ":"))
    algo = json.dumps(algorithm, ensure_ascii=False, separators=(",", ":"))
    api_document_payload = json.dumps(openapi_context or {}, ensure_ascii=False, separators=(",", ":"))
    return f"""你正在为 API 访问控制异常检测流水线审核一个业务会话聚类簇。

任务：
1. 判断该聚类簇是否能代表一个稳定的正常业务流程；不稳定、混簇、低价值噪声或证据不足时，少生成或不生成安全场景。
2. 概括该正常业务流程中的核心 API 链路、上下文来源、目标动作、关键参数/对象。
3. 从五类安全风险角度反推攻击者可能破坏的约束，生成 0 到 2 个证据最强的安全场景。每个场景必须先说明风险示例，再指出攻击点、攻击方式、命中条件、参数约束和状态码证据。
4. 不生成攻击脚本、payload、检测规则、一阶逻辑表达式或成功利用结论；只输出结构化 JSON。

风险优先示例：
- BFLA/功能级越权：
  - 示例：普通用户 token 调用管理配置类接口，并提交配置 payload。
  - 规则逻辑：非管理员角色访问 admin/config/manage/delete/permission/role 等管理端写接口；角色与接口权限矩阵不匹配。
  - 攻击点：接口只检查登录态，不检查当前用户角色或功能权限。
  - 攻击方式：攻击者复用普通登录态直接调用管理端写接口，或提交 role/group/permission/admin 等权限相关参数。
  - 命中条件：普通用户或低权限上下文请求返回 2xx/3xx，或者授权前置 401/403 后目标管理写接口仍被处理。
  - 风险：配置被篡改、权限扩大、系统级破坏。
  - 分析维度：参数分析、状态码分析、顺序/权限前置分析。

五类安全场景与分析口径：
- BOLA/对象级越权：
  - 示例：攻击者替换对象 ID、空间 ID、项目 ID、运行实例 ID、步骤 ID、帖子 ID 等访问或修改不属于当前上下文的对象。
  - 攻击点：目标 API 使用客户端传入对象标识，但未校验对象是否属于当前用户、父对象、会话上下文或上游详情/列表。
  - 攻击方式：替换、枚举、跨父对象组合、跳过列表/详情/归属上下文后直接访问目标对象。
  - 分析维度：参数分析、状态码分析；有明确跳步时补充顺序分析。
- BOPLA/属性级越权：
  - 示例：攻击者提交 reporter、assignee、status、securityLevel、role、project、owner、visibility 等不应由客户端控制的属性。
  - 攻击点：服务端把敏感属性当作普通请求字段接受，未按角色、状态机或服务端上下文重算。
  - 攻击方式：篡改请求体/查询参数中的属性字段，跳过审批、状态流、权限校验或详情确认后直接更新属性。
  - 分析维度：参数分析、状态码分析；必要时补充状态流顺序分析。
- BFLA/功能级越权：
  - 示例：普通用户直接调用 admin/config/delete/permission/approve/manage 等高权限功能。
  - 攻击点：接口只检查登录或会话存在，不检查角色、功能权限、权限矩阵或管理上下文。
  - 攻击方式：低权限用户直接调用管理端读写接口，或提交 role、permission、group、admin 等权限参数影响功能授权。
  - 分析维度：参数分析、状态码分析、权限前置顺序分析。
- AUTH_BYPASS/认证授权绕过：
  - 示例：缺少 login/session/auth/checkPermission/token/xsrf/csrf 前置步骤，或前置失败后仍执行目标操作。
  - 攻击点：目标接口未强制校验认证、会话、授权、CSRF/XSRF 或授权前置结果。
  - 攻击方式：直接调用后置敏感接口，复用缺失/失效 token，或在授权前置 401/403 后继续触发目标动作。
  - 分析维度：状态码分析、顺序分析；token/session 参数只作为认证上下文证据。
- RESOURCE_CONSUMPTION/资源消耗：
  - 示例：上传、导出、搜索、报表、批处理、生成、重计算等高成本 API 被高频调用，或 size/limit/pageSize/range/depth 被放大。
  - 攻击点：接口缺少限流、配额、分页上限、成本参数约束或任务状态前置。
  - 攻击方式：重复调用高成本 API，扩大成本参数，枚举大量 contentId/objectId 触发批量处理。
  - 分析维度：参数分析、状态码分析、重复/洪泛顺序分析。普通 notification/count、quickreload、status、heartbeat、ping、poll、unread/count 等低成本读接口重复出现，不足以单独构成该风险。

异常证据要求：
- 参数一致性异常：说明关键参数或对象从哪个上下文 API 来，流向哪个目标 API，真实参数名、位置、source_parameter、target_parameter、绑定/归属/派生关系是什么，以及攻击者可能破坏的是替换、枚举、跨对象、跨父对象、来源不明还是客户端控制属性。
- 顺序异常：说明正常链路和可能被破坏的链路，例如 A->B->C 被攻击者变成 A->C、C 过早出现、关键前置缺失或敏感接口重复调用。
- 顺序活动必须是输入日志中真实出现的 API，格式必须接近 `GET /path`、`POST /path`、`PUT /path` 等。禁止把抽象概念写成活动，例如“用户应先登录并经过权限校验（Admin Role Check）”“在具备管理权限的前提下访问 GET /admin/space”“攻击者/普通用户在未授权状态下直接请求 GET /admin/space”。如果日志中没有真实登录、角色检查或权限检查 API，只能在 attack_point、hit_condition、later_check_hint 中说明需要角色/权限证据，不能把它编造成 sequence step。
- 响应码只作为证据：用于提高或降低场景可信度和风险等级，不能单独证明风险成立，也不能代替参数流动关系或顺序约束。2xx/3xx 表示请求可能被处理或跳转，401/403 表示控制可能生效或前置失败，404 表示对象不存在或隐藏式权限控制，5xx 表示异常处理或资源压力证据。

安全场景参数约束：
- 每个安全场景只针对一个参数、一个同义映射参数对，或一组确实有关联关系的参数进行推导。
- 每个 parameter_consistency_risk 必须保持最小上下文：context_apis 最多 3 个，target_apis 最多 2 个。优先选择和目标参数存在直接来源、同一对象、归属、派生或权限矩阵关系的 API。
- 禁止把整条代表序列、整组管理接口、所有同类接口或大量候选上下文 API 放进一个场景；不要生成 C1...C10/C15 这种长上下文公式。
- 如果同一个参数出现在多个不同目标动作中，例如 manage/security/member/module/default/permissions，必须按目标动作或接口组拆分；最多输出证据最强的 1 到 2 个场景，其余写入 later_check_hint。
- 允许放在同一个场景的情况只有两类：一堆参数必须一起出现在同一个 API 中并作为整体上下文传递，例如组合键或同一请求体字段组；或者上下文参数与目标参数虽然名字不同，但业务上代表同一个对象或同一个归属关系，例如 source_parameter=cycleId/runId，target_parameter=testRunStepId。
- 不允许把多个无关联参数混杂到一个场景中；不允许把多个互为“或”关系的参数写成一个“同时篡改 A/B/C 组合”的风险。
- 如果多个参数代表不同攻击面，必须拆成不同安全场景；如果最多 2 个场景不够覆盖，则只输出证据最强的 1 到 2 个，并在 later_check_hint 中说明其他参数需要单独复核。
- 对每个场景或 parameter_risk_cases 项都要回答：参数来自哪个上下文 API、流向哪个目标 API、参数位置是什么、source_parameter 与 target_parameter 是否同名或如何映射、正常绑定/归属/派生关系是什么、攻击者破坏的是替换、枚举、跨对象、跨父对象、来源不明还是客户端控制属性。
- 示例关系表达：GET /jira/secure/ShowTestCycleRunDetail.jspa 中的 cycleId/runId 是上下文来源，PUT /jira/rest/synapse/1.0/testRun/updateTestRunStepStatus 中的 testRunStepId 是目标参数；关系是“步骤ID必须属于当前会话加载的测试周期和运行实例”。这应写成围绕 testRunStepId 的独立场景，而不是把 runId、stepId、testRunStepId 合并成一个含糊的组合攻击。

输出约束：
- 每个场景只输出有证据支撑的异常维度：有顺序异常证据才输出 sequence_order_risk；有参数流动或绑定证据才输出 parameter_consistency_risk；两者真实耦合时才使用 risk_type=both。
- 每个场景必须先写 risk_example、attack_point、attack_method、hit_condition，再展开 sequence_order_risk 或 parameter_consistency_risk。
- analysis_dimensions 必须列出本场景实际使用的分析维度，例如 ["参数分析","状态码分析"]、["状态码分析","顺序分析"]、["参数分析","状态码分析","权限前置顺序分析"]。
- sequence_order_risk 要写清正常链路与可能违规链路，例如 A->B->C 被变成 A->C、C 过早出现、关键前置缺失或敏感接口重复调用。
- sequence_order_risk.normal_sequence_pattern、possible_violation_sequence_pattern、related_apis 只能包含真实 API 或带真实 API 的简短 step；不能出现“Admin Role Check”“用户应先登录”“具备管理权限”“普通用户未授权”等非 API 活动。权限/角色判断写入 attack_point、hit_condition 或 later_check_hint。
- parameter_consistency_risk 只能围绕本场景的一个参数、同义映射参数对或必要参数组，写清上下文 API、目标 API、参数来源、参数位置、绑定关系、parameter_risk_cases；参数名和参数位置必须优先来自参数画像或原始请求，OpenAPI 只作为补充，不能把路径片段或业务概念改写成参数名。
- parameter_consistency_risk.context_apis 和 target_apis 必须是最小可检测集合，不能超过上述数量限制；context_binding 中每条绑定都必须能解释具体 source_api 到 target_api 的关系，不能只因为 API 在同一簇中出现就加入上下文。
- 如果上下文 API 与目标 API 参数名不同，必须保留真实参数名，并用 source_parameter/target_parameter 表达映射；证据不足时设置 needs_openapi_or_raw_request_confirmation=true，并在 later_check_hint 中说明需要哪些原始字段。
- 如果输入事件携带 data_valid、seq_valid、data_type、user_type、source_file、session_key 等训练字段，可作为辅助证据：data_valid/seq_valid 为 False 或异常类型较多时，应降低该簇作为正常模式的可信度；不同 source_file 的同名 user_index 已由上游拆成不同 session_key，不要把它们误认为同一真实用户。
- 如果聚类不适合作为正常业务模式参考，或无法从输入证据推断可验证约束，possible_security_scenarios 返回空数组。
- risk_level 使用 low、medium、high。序列中出现修改/删除/确认/权限/配置/管理类后置动作且前置上下文不足时通常为 high；只有读接口且主要需要参数一致性确认时通常为 medium；仅为轻微重复或低影响读接口时为 low。
- 响应码必须写在具体场景的 response_code_evidence 中，说明它如何支撑或削弱该场景的参数一致性异常或顺序异常推断。

站点：{site_id}
聚类算法配置：
{algo}

匹配到的 API 文档/参数画像上下文：
{api_document_payload}

待审核聚类簇：
{compact}

请输出 JSON，不要输出 Markdown，不要解释 JSON 之外的文字。字段建议保持如下结构：
{{
  "cluster_index": <int>,
  "is_trustworthy": <true|false>,
  "trust_score": <0.0到1.0>,
  "business_pattern_name": "<用中文概括该簇业务模式>",
  "main_evidence": ["<为什么认为它们相似或不相似>"],
  "mixed_member_session_ids": ["<疑似不属于本簇的成员session_id>"],
  "representative_problem": "<代表会话是否合适，不合适则说明原因>",
  "possible_security_scenarios": [
    {{
      "scenario_id": "<cluster_index-scenario-序号，例如 C1-S1>",
      "scenario_title": "<围绕主风险轴的标题，例如 测试步骤ID脱离运行实例上下文导致的对象级访问风险>",
      "security_type": "<BOLA|BFLA|BOPLA|AUTH_BYPASS|RESOURCE_CONSUMPTION>",
      "risk_level": "<low|medium|high>",
      "risk_score": <0.0到1.0>,
      "risk_type": "<sequence_order|parameter_consistency|both>",
      "risk_example": "<一句话示例，例如 普通用户 token 调用管理配置接口并提交配置 payload>",
      "attack_point": "<可能被攻击的点，例如 接口只检查登录态，不检查角色权限>",
      "attack_method": "<攻击者如何攻击，例如 替换对象ID/直接调用管理接口/扩大分页参数/跳过授权前置>",
      "hit_condition": "<后续检测命中条件，例如 普通用户请求返回2xx、目标参数不来自上下文、授权前置403后目标写接口仍2xx>",
      "analysis_dimensions": ["参数分析", "状态码分析"],
      "//": "如果不是该风险维度，直接省略对应字段，不要输出空对象或不适用说明。",
      "sequence_order_risk": {{
        "risk_level": "<low|medium|high>",
        "sequence_subtype": "<authorization_precheck|business_order|repeated_call>",
        "normal_sequence_pattern": ["<正常链路第1步>", "<正常链路第2步>", "<正常链路第3步>"],
        "possible_violation_sequence_pattern": ["<攻击场景下的违规链路第1步>", "<违规链路第2步，尽量体现跳过/越序/重复>"],
        "violated_order_constraint": "<被破坏的顺序约束，例如 通常应先详情/校验再修改>",
        "missing_or_reordered_step": "<被跳过、缺失、提前或重复的关键步骤>",
        "why_this_order_is_risky": "<为什么这个违规顺序有风险，尽量说清楚 A->C 跳过了 B 或 C 出现过早/重复>",
        "authorization_precheck": {{
          "precheck_required": <true|false>,
          "precheck_api": "<必须是输入日志中真实存在的认证/授权/权限检查 API；没有则留空字符串>",
          "required_response_keywords": ["token", "session", "permission", "access", "allowed", "role"],
          "max_interval_seconds": 300,
          "browser_context_required": true
        }},
        "related_apis": ["<相关API>"]
      }},
      "parameter_consistency_risk": {{
        "risk_level": "<low|medium|high>",
        "key_parameters_or_objects": ["<需要检查是否中途替换或不一致的参数/对象，如 issueId/projectId/avatarId>"],
        "target_apis": ["<携带或使用关键参数的目标API，最多2个，只保留同一目标动作的最小集合>"],
        "context_apis": ["<提供直接业务上下文、对象来源或绑定关系的前置API，最多3个；没有直接关系则空数组>"],
        "normal_parameter_sequence": ["<参数在正常业务中应出现或传递的API链路>"],
        "parameter_dependency_relation": "<stable_within_target_api|derived_from_context_api|bound_to_upstream_context|same_actor_context|unknown>",
        "expected_parameter_source": "<upstream_context_api|same_request_or_business_context|authenticated_session|unknown>",
        "parameter_occurrences": [{{"parameter":"<参数名>","api":"<API>","location":"<path|query|body|header|response_or_business_context|unknown>","role":"<context_source|target_parameter>"}}],
        "context_binding": [{{"source_api":"<上游上下文API，必须在context_apis内>","target_api":"<目标API，必须在target_apis内>","parameter":"<同名参数名；不同名映射时可为空>","source_parameter":"<上游真实参数名或参数组>","target_parameter":"<目标真实参数名>","relation":"<归属依赖|派生依赖|同一对象|同一用户上下文|组合键|其他依赖或流动关系>","explanation":"<为什么该目标参数必须受该上游上下文约束；不能只说同簇出现>"}}],
        "parameter_risk_cases": [
          {{
            "case_id": "<P1>",
            "parameter_or_parameter_group": ["<本case只放同一攻击面的参数或组合键>"],
            "source_api": "<上下文来源API>",
            "target_api": "<目标API>",
            "source_parameter": "<来源参数名或参数组>",
            "target_parameter": "<目标参数名>",
            "relationship": "<正常参数流动/归属/派生关系>",
            "risky_form": "<该参数被替换、枚举、跨对象、跨父对象或客户端控制的具体形式>",
            "case_reason": "<为什么这是一个独立场景；如果与其他参数是或关系，在这里说明>"
          }}
        ],
        "risky_parameter_form": "<只概括本场景/本case的风险；多个独立参数用“或”关系分开，不写成必须同时篡改的组合>",
        "needs_openapi_or_raw_request_confirmation": <true|false>
      }},
      "response_code_evidence": {{
        "cluster_status_distribution": {{"<status>": <count>}},
        "sequence_status_observation": "<整个正常序列状态码分布对风险判断的影响>",
        "precheck_api_status_observation": "<登录/会话/权限/上下文/校验等前置 API 的状态码含义；没有则省略>",
        "target_api_status_observation": "<目标 API 或敏感 API 的状态码含义；没有则省略>",
        "parameter_api_status_observation": "<参数一致性相关 API 的状态码含义；没有则省略>",
        "risk_level_adjustment_reason": "<响应码如何支撑或降低风险等级>"
      }},
      "overall_reason": "<综合风险评级原因，控制在 1 到 3 句话>",
      "later_check_hint": "<后续检测应重点看序列顺序还是参数一致性，以及需要哪些原始字段>"
    }}
  ],
  "suggestion": {{
    "eps_action": "<keep|decrease|increase>",
    "min_samples_action": "<keep|decrease|increase>",
    "reason": "<调参原因>"
  }}
}}
"""


def build_prompt_status_legacy(site_id: str, cluster: dict[str, Any], algorithm: dict[str, Any]) -> str:
    compact = json.dumps(cluster, ensure_ascii=False, separators=(",", ":"))
    algo = json.dumps(algorithm, ensure_ascii=False, separators=(",", ":"))
    return f"""你是 API 日志业务流程聚类质检员和安全场景推演员。输入簇默认来自正常业务样本；你的任务是判断该簇能否作为正常业务模式参考，并从正常业务约束反推可能的 OWASP API 安全风险场景。

任务：
1. 判断 DBSCAN 聚类簇是否适合作为正常业务模式参考。可信表示代表会话和成员会话大体体现同一种业务模式或同一类用户操作流程；头像、配置、通知、轮询、静态资源等前端噪声可以接受；明显混入不同业务流程时需要指出。
2. 概括正常业务模式：主要 API 顺序、核心对象/API、关键上下文关系、状态码表现。
3. 当簇适合作为正常业务模式参考时，生成 0 到 2 个安全风险场景。推理方向是从正常约束反推攻击者破坏该约束后可能产生的风险。
4. 每个安全场景说明正常业务约束、可能攻击主体、目标对象/API、被破坏的约束、可能的越权/绕过/滥用形式、风险等级和依据。

安全风险评级要求：
- risk_type 必须围绕一个主风险轴：sequence_order 表示跳步、越序、缺失或重复关键步骤；parameter_consistency 表示对象 ID、用户 ID、订单 ID、项目 ID、角色/权限字段等参数上下文不一致；both 仅在顺序链和参数依赖真实耦合时使用。
- sequence_order_risk 和 parameter_consistency_risk 不是每个场景都必须同时输出。依据不足的风险字段必须完整省略。
- security_type 从 BOLA、BFLA、BOPLA、AUTH_BYPASS、RESOURCE_CONSUMPTION 中选择。
- BOLA：说明是否绕过列表/详情/项目上下文直接访问对象，或替换 issueId/projectId/userId/avatarId/orderId 等对象标识。
- BFLA：说明普通流程中是否涉及 admin/config/delete/permission/role/group/approve 等高权限接口或参数。
- BOPLA：说明创建/更新/转派/状态流中是否可能跳过校验，或提交 reporter/status/securityLevel/assignee/project/owner/price 等不应由客户端控制的字段。
- AUTH_BYPASS：从 sequence_order_risk 描述认证、会话、授权、token、xsrf、权限上下文是否可能被绕过。
- RESOURCE_CONSUMPTION：只在上传、导出、搜索、报表、批处理或明确高成本接口存在重复/洪泛/过载证据时生成；普通 notification/count、quickreload、status、heartbeat、ping、poll、unread/count 轮询不足以单独支持该风险。
- risk_level 使用 low、medium、high。修改、删除、确认、支付、审批、权限、配置、管理类后置动作且前置上下文不足通常为 high；读接口存在对象替换或上下文不一致通常为 medium；低影响读接口或轻微重复通常为 low。

sequence_order_risk 要求：
- 从正常顺序链反推攻击场景下可能被破坏的顺序形式。
- normal_sequence_pattern 写正常链路；possible_violation_sequence_pattern 写具体违规链路，例如直接修改/提交/确认，列表 -> 修改跳过详情/校验，先修改后校验，敏感接口重复调用。
- normal_sequence_pattern、possible_violation_sequence_pattern、related_apis 必须使用输入日志中真实出现的 API，禁止生成“Admin Role Check”“用户应先登录”“具备管理权限”“普通用户未授权”等非 API 活动；如果缺少真实登录/角色/权限检查 API，只能在 later_check_hint 中说明需要补充角色证据。
- 如果无法从正常业务模式推断具体可破坏顺序链，省略 sequence_order_risk。

parameter_consistency_risk 要求：
- 从正常参数上下文反推攻击场景下可能被破坏的参数一致性形式。
- 当前输入主要是 API 路径序列，不一定包含完整 query/body/header 参数；不要虚构具体值，可说明需要结合 OpenAPI 和原始请求确认。
- 参数名必须来自 OpenAPI/API 文档或逐事件原始请求中实际出现的参数名；禁止把 API 路径、接口动作名、页面名或业务概念当成参数名。
- 如果上下文 API 与目标 API 的真实参数名不同，例如 path 参数 int_2 与目标参数 issueId，必须保留真实参数名，并在 context_binding 中用 source_parameter/target_parameter 表达映射关系，不能把 int_2 改写成 issueId。
- 如果只能从业务语义猜测参数，但 OpenAPI 或原始请求中没有该参数名，不要放入 key_parameters_or_objects 或 parameter_occurrences，只能在 later_check_hint 中说明需要原始请求确认。
- 尽量明确 key_parameters_or_objects、target_apis、context_apis、normal_parameter_sequence、parameter_dependency_relation、expected_parameter_source、parameter_occurrences、context_binding。
- 如果无法明确关键参数、上下文 API 或目标 API，省略 parameter_consistency_risk。

响应码分析要求：
- 聚类输入包含 status_code_evidence 时，必须把状态码分布纳入风险判断：包括整个序列状态码分布、代表序列状态码、关键 API、前置 API、目标 API 或参数一致性相关 API 的响应状态。
- 聚类输入包含 representative_event_sample 或 sampled_members[*].event_sample 时，每个事件的 status_code 与同一步 api 对齐；分析安全场景时优先使用逐事件状态码，而不是只看汇总分布。
- 2xx 表示请求大概率被服务端处理；若目标 API 在对象替换、跳步、越权参数场景下仍为 2xx，风险可信度上升。
- 3xx 表示重定向或缓存相关行为，需要结合最终跳转或后续链路判断；304 通常偏低风险证据。
- 401/403 表示认证或权限控制可能生效；若前置认证/授权 API 为 401/403 后仍继续执行目标修改/支付/配置操作，顺序风险上升。
- 404 表示对象不存在、路径错误或隐藏式权限控制；用于 BOLA/枚举类场景时应提示结合对象归属和同类请求确认。
- 5xx 表示服务端异常、解析失败或资源压力；上传、导出、搜索、报表、批处理等场景出现 5xx 时，可增强 RESOURCE_CONSUMPTION 或异常处理风险依据。
- 响应码不能单独证明越权成功；它是安全场景可信度、风险等级和 later_check_hint 的证据层。

输出约束：
- 只输出 JSON，不输出 Markdown。
- 不输出 payload、攻击脚本、检测代码、命中条件、HTTP 成功判定或一阶逻辑表达式。
- 如果簇不适合作为正常业务模式参考，possible_security_scenarios 返回空数组。
- 每个可信簇最多输出 2 个安全场景。

站点：{site_id}
聚类算法配置：
{algo}

待审核聚类簇：
{compact}

请输出 JSON，不要解释 JSON 之外的文字。字段建议保持如下结构：
{{
  "cluster_index": <int>,
  "is_trustworthy": <true|false>,
  "trust_score": <0.0到1.0>,
  "business_pattern_name": "<用中文概括该簇业务模式>",
  "business_pattern_summary": "<主要 API 顺序、核心对象/API、关键上下文关系和状态码表现>",
  "main_evidence": ["<为什么认为它们相似或不相似>"],
  "mixed_member_session_ids": ["<疑似不属于本簇的成员session_id>"],
  "representative_problem": "<代表会话是否合适，不合适则说明原因>",
  "possible_security_scenarios": [
    {{
      "scenario_id": "<cluster_index-scenario-序号，例如 C1-S1>",
      "scenario_title": "<围绕主风险轴的标题>",
      "security_type": "<BOLA|BFLA|BOPLA|AUTH_BYPASS|RESOURCE_CONSUMPTION>",
      "risk_level": "<low|medium|high>",
      "risk_score": <0.0到1.0>,
      "risk_type": "<sequence_order|parameter_consistency|both>",
      "normal_business_constraint": "<正常业务约束>",
      "possible_attacker": "<可能攻击主体>",
      "target_objects_or_apis": ["<目标对象或 API>"],
      "broken_constraint": "<被破坏的约束>",
      "possible_unauthorized_form": "<可能的越权、绕过、滥用或资源消耗形式>",
      "sequence_order_risk": {{
        "risk_level": "<low|medium|high>",
        "sequence_subtype": "<authorization_precheck|business_order|repeated_call>",
        "normal_sequence_pattern": ["<正常链路第1步>", "<正常链路第2步>"],
        "possible_violation_sequence_pattern": ["<攻击场景下的违规链路第1步>", "<违规链路第2步>"],
        "violated_order_constraint": "<被破坏的顺序约束>",
        "missing_or_reordered_step": "<被跳过、缺失、提前或重复的关键步骤>",
        "why_this_order_is_risky": "<为什么这个违规顺序有风险>",
        "related_apis": ["<相关API>"]
      }},
      "parameter_consistency_risk": {{
        "risk_level": "<low|medium|high>",
        "key_parameters_or_objects": ["<参数或对象>"],
        "target_apis": ["<目标API>"],
        "context_apis": ["<上下文API>"],
        "normal_parameter_sequence": ["<参数正常流转链路>"],
        "parameter_dependency_relation": "<参数依赖关系>",
        "expected_parameter_source": "<参数预期来源>",
        "parameter_occurrences": [{{"parameter":"<参数名>","api":"<API>","location":"<path|query|body|header|response_or_business_context|unknown>","role":"<context_source|target_parameter>"}}],
        "context_binding": [{{"source_api":"<上游上下文API>","target_api":"<目标API>","parameter":"<参数名>","relation":"<依赖或流动关系>","explanation":"<为什么该参数应受上下文约束>"}}],
        "risky_parameter_form": "<可能的参数中途替换、跨对象切换、来源不明或组合不合理形式>",
        "needs_openapi_or_raw_request_confirmation": <true|false>
      }},
      "response_code_evidence": {{
        "cluster_status_distribution": {{"<status>": <count>}},
        "sequence_status_observation": "<整个正常序列状态码分布对风险判断的影响>",
        "event_status_observation": "<逐事件 status_code 与 api 对齐后的关键观察>",
        "precheck_api_status_observation": "<前置 API 状态码含义；没有则省略>",
        "target_api_status_observation": "<目标 API 状态码含义；没有则省略>",
        "parameter_api_status_observation": "<参数一致性相关 API 状态码含义；没有则省略>",
        "risk_level_adjustment_reason": "<响应码如何支撑或降低风险等级>"
      }},
      "overall_reason": "<综合风险评级原因，1 到 3 句话>",
      "later_check_hint": "<后续应重点检查的顺序、参数、OpenAPI、原始请求或状态码证据>"
    }}
  ],
  "suggestion": {{
    "eps_action": "<keep|decrease|increase>",
    "min_samples_action": "<keep|decrease|increase>",
    "reason": "<调参原因>"
  }}
}}
"""


def build_prompt_user_prompt_removed(site_id: str, cluster: dict[str, Any], algorithm: dict[str, Any]) -> str:
    compact = json.dumps(cluster, ensure_ascii=False, separators=(",", ":"))
    algo = json.dumps(algorithm, ensure_ascii=False, separators=(",", ":"))
    return f"""你是一个 API 业务流程安全分析助手。输入是 DBSCAN 聚类得到的正常业务 API 序列簇。请先概括该簇体现的业务流程，再从正常业务约束反推可能的 OWASP API 安全风险场景。

一、任务核心

1. 识别正常业务模式
   - 概括该簇对应的业务流程。
   - 提取主要 API 调用顺序、核心对象、关键上下文关系。
   - 说明这些 API 之间体现的正常业务约束，例如：先登录再访问、先列表再详情、先校验再提交、先创建再支付、先查询上下文再修改对象。

2. 反推安全风险场景
   - 基于正常业务约束，推演攻击者可能破坏哪些顺序约束或参数上下文约束。
   - 每个簇生成 0 到 2 个安全风险场景。
   - 场景应围绕 OWASP API 风险语义展开，例如 BOLA、BOPLA、BFLA、AUTH_BYPASS、RESOURCE_CONSUMPTION。
   - 如果该簇无法支持具体安全场景，只输出业务模式概括，并说明无法推断的原因。

二、分析要求

1. 顺序风险 sequence_order_risk
   - 从正常 API 顺序链反推攻击场景下可能出现的跳步、越序、缺失或重复调用。
   - 写清楚正常链路和可能违规链路。
   - 示例：
     - 正常：登录/建立上下文 -> 列表/详情/校验 -> 修改/提交/确认
     - 违规：直接修改/提交/确认
     - 违规：列表 -> 修改，跳过详情/校验
     - 违规：先修改后校验
     - 违规：敏感接口被重复调用
   - 如果无法推断具体顺序破坏形式，不输出 sequence_order_risk。

2. 参数一致性风险 parameter_consistency_risk
   - 从正常参数流转关系反推攻击场景下可能出现的对象 ID 替换、用户身份不一致、上下文不一致、客户端控制敏感属性等问题。
   - 不虚构具体参数值；如果输入只有 API 路径，可说明需结合 OpenAPI 和原始请求确认参数。
   - 尽量明确：
     - key_parameters_or_objects：关键对象或参数，如 userId、orderId、issueId、projectId、avatarId、tripId、role、status。
     - target_apis：可能被攻击的目标 API。
     - context_apis：提供列表、详情、校验、上下文或绑定关系的 API。
     - normal_parameter_sequence：参数在正常流程中的来源和流转。
     - parameter_dependency_relation：参数依赖关系，例如 orderId 来自当前用户订单列表，payment userId 应绑定 token.userId。
     - expected_parameter_source：参数预期来源，例如登录态、token 主体、前置列表接口、详情接口、服务端会话上下文。
     - parameter_occurrences：参数可能出现在哪些 API 中。
     - context_binding：对象与用户、租户、订单、项目、角色、会话之间的绑定关系。
   - 如果无法明确关键参数、上下文 API 或目标 API，不输出 parameter_consistency_risk。

3. 风险场景字段要求
   - 每个场景说明：
     - 正常业务约束；
     - 可能攻击主体；
     - 目标对象或 API；
     - 被破坏的约束；
     - 可能的越权、绕过、滥用或资源消耗形式；
     - 风险等级 low / medium / high；
     - 后续需要结合 OpenAPI 或原始请求确认的点。
   - 每个场景只围绕一个主要风险轴展开；只有顺序链和参数依赖都明确时，risk_type 才使用 both。

三、案例参考

案例 1：BOLA 对象级越权：遍历用户/订单 ID
- 正常业务约束：用户先通过列表、搜索、订单中心、项目上下文等接口获得自己有权访问的对象 ID，再访问对应详情。
- 风险场景：攻击者替换 userId、orderId、projectId、issueId 等对象 ID，访问不属于自己的资源。
- 攻击点：服务端只校验是否登录，没有校验对象 ID 是否属于当前用户、租户或项目上下文。
- 典型 API：/users/{{id}}、/order/detail/{{order_id}}、/projects/{{projectId}}/issues/{{issueId}}
- 重点风险轴：parameter_consistency。
- security_category：BOLA。

案例 2：BOPLA 对象属性级越权：让他人支付
- 正常业务约束：支付账户、订单所有者、请求者身份应由服务端根据登录态和订单上下文绑定。
- 风险场景：攻击者在支付请求中传入 userId、orderId、tripId、accountId 等对象属性，使服务端按客户端提交的用户或账户扣款。
- 攻击点：服务端信任客户端传入的 userId/accountId，没有绑定 token 中的真实用户。
- 典型表现：订单属于攻击者，但付款账户、用户 ID 或扣款主体被替换为其他用户。
- 重点风险轴：parameter_consistency。
- security_category：BOPLA，也可能涉及 BOLA。

案例 3：RESOURCE_CONSUMPTION 资源消耗：无限头像上传
- 正常业务约束：头像上传、图片解析、压缩、存储、转码应受到大小、频率、配额和成本控制。
- 风险场景：攻击者重复上传 base64 图片、超大图片或高频上传头像。
- 攻击点：上传接口缺少大小限制、次数限制、存储配额、压缩/解析成本控制。
- 典型影响：响应变慢、5xx 增加、磁盘增长、CPU/带宽消耗升高。
- 重点风险轴：sequence_order 或重复敏感接口调用。
- security_category：RESOURCE_CONSUMPTION。

案例 4：BFLA 功能级越权：访问高权限功能
- 正常业务约束：admin、config、role、permission、delete、approve 等接口应绑定高权限角色或管理流程。
- 风险场景：低权限用户直接调用管理、配置、删除、审批、角色权限类接口。
- 攻击点：服务端只校验登录态，没有校验功能权限或角色权限。
- 典型 API：/admin/config、/users/{{id}}/role、/permission/update、/order/approve
- 重点风险轴：sequence_order 或 parameter_consistency，取决于是否能看出权限上下文。
- security_category：BFLA。

案例 5：AUTH_BYPASS 认证/会话绕过
- 正常业务约束：敏感详情、修改、提交、支付、配置等接口应依赖 login、session、token、xsrf、context 等前置步骤。
- 风险场景：攻击者直接调用后置敏感接口，绕过认证、会话初始化、CSRF token 获取或上下文建立。
- 攻击点：服务端对认证态、会话态、token、xsrf 或上下文绑定校验不足。
- 重点风险轴：sequence_order。
- security_category：AUTH_BYPASS。

站点：{site_id}
聚类算法配置：
{algo}

待审核聚类簇：
{compact}

输出 JSON：

{{
  "business_pattern_analysis": {{
    "business_pattern_summary": "",
    "representative_sequence_summary": "",
    "key_objects_or_parameters": [],
    "context_relationships": [],
    "mixed_flow_notes": [],
    "no_scenario_reason": ""
  }},
  "possible_security_scenarios": [
    {{
      "scenario_title": "",
      "security_category": "BOLA | BFLA | BOPLA | AUTH_BYPASS | RESOURCE_CONSUMPTION",
      "risk_type": "sequence_order | parameter_consistency | both",
      "risk_level": "low | medium | high",
      "normal_business_constraint": "",
      "possible_attacker": "",
      "target_objects_or_apis": [],
      "broken_constraint": "",
      "possible_unauthorized_form": "",
      "reason": "",
      "sequence_order_risk": {{
        "normal_sequence_pattern": "",
        "possible_violation_sequence_pattern": "",
        "security_impact": ""
      }},
      "parameter_consistency_risk": {{
        "key_parameters_or_objects": [],
        "target_apis": [],
        "context_apis": [],
        "normal_parameter_sequence": "",
        "parameter_dependency_relation": "",
        "expected_parameter_source": "",
        "parameter_occurrences": "",
        "context_binding": ""
      }},
      "later_check_hint": ""
    }}
  ]
}}
"""


def build_prompt(
    site_id: str,
    cluster: dict[str, Any],
    algorithm: dict[str, Any],
    openapi_context: dict[str, Any] | None = None,
) -> str:
    compact = json.dumps(cluster, ensure_ascii=False, separators=(",", ":"))
    algo = json.dumps(algorithm, ensure_ascii=False, separators=(",", ":"))
    api_document_payload = json.dumps(openapi_context or {}, ensure_ascii=False, separators=(",", ":"))
    return f"""你正在为 API 访问控制异常检测流水线分析一个异常会话聚类簇。

重要前提：
- 输入簇来自 abnormal/攻击会话，不是正常业务样本。
- 不要再判断“是否能代表稳定正常业务流程”作为过滤依据；除非完全没有可解释 API，否则都应尝试反推 1 到 3 个可检测安全场景。
- 输出结构必须兼容后续 fol_expression_generation.py：顶层必须包含 possible_security_scenarios，每个场景尽量包含 sequence_order_risk 或 parameter_consistency_risk。
- 只输出规则生成所需的结构化 JSON，不输出攻击 payload、利用代码或 Markdown。

任务：
1. 从异常会话中识别攻击目标 API、可疑前置/缺失前置、重复/枚举/越序行为、关键参数和响应码证据。
2. 直接反推可检测规则：异常行为应该如何被表达为顺序约束、参数一致性约束、权限/认证前置约束或资源消耗约束。
3. 每个场景都要说明 attack_observation、attack_point、attack_method、hit_condition、response_code_evidence。
4. 如果参数关系来自参数画像/OpenAPI，要使用真实参数名；如果无法确认参数来源，不要虚构来源，设置 needs_openapi_or_raw_request_confirmation=true。

风险类型只允许：
- BOLA：对象级越权，对象 ID/空间 ID/内容 ID/用户 ID/项目 ID 等被替换、枚举或跨上下文使用。
- BOPLA：属性级越权，role/status/permission/visibility/owner 等敏感属性由客户端提交或越权修改。
- BFLA：功能级越权，低权限/非管理上下文调用 admin/manage/config/delete/permission/role 等接口。
- AUTH_BYPASS：认证、会话、CSRF/XSRF、授权前置缺失或失败后仍调用敏感目标。
- RESOURCE_CONSUMPTION：高成本接口被重复、高频、扩大分页/范围或批量触发。

异常规则反推要求：
- sequence_order_risk 用于描述异常链路：关键前置缺失、目标 API 过早出现、先执行后校验、敏感 API 重复调用。
- parameter_consistency_risk 用于描述异常参数：目标参数来源不明、上下文不一致、同一目标 API 内多值切换、跨对象/跨父对象组合。
- 对 abnormal 输入，possible_violation_sequence_pattern 应优先来自当前异常簇的真实 API 顺序。
- normal_sequence_pattern 如果无法从异常簇确定，只填写推测所需的最小正常约束 API，且必须来自输入、OpenAPI 或参数画像中的真实 API；不要编造“Admin Role Check”等虚拟步骤。
- context_apis 最多 3 个，target_apis 最多 2 个；每个参数场景只围绕一个参数或一组真实相关参数。
- 响应码只能作为证据，不单独证明越权成功；2xx/3xx 增强“请求被处理”可信度，401/403 支持授权拦截或前置失败，404 支持枚举/隐藏式权限控制，5xx 支持异常处理或资源压力。

站点：{site_id}
聚类算法配置：
{algo}

匹配到的 API 文档/参数画像上下文：
{api_document_payload}

待分析异常聚类簇：
{compact}

请输出 JSON，不要输出 Markdown，不要解释 JSON 之外的文字。字段建议保持如下结构：
{{
  "cluster_index": <int>,
  "is_trustworthy": true,
  "trust_score": <0.0到1.0，表示异常证据足以生成规则的置信度>,
  "business_pattern_name": "<用中文概括异常行为或攻击模式>",
  "attack_observation_summary": "<异常簇体现出的攻击行为摘要>",
  "main_evidence": ["<异常 API 顺序、参数、响应码或重复调用证据>"],
  "mixed_member_session_ids": ["<明显混入其他攻击模式的成员session_id；没有则空数组>"],
  "representative_problem": "<代表异常会话是否能代表该攻击模式>",
  "possible_security_scenarios": [
    {{
      "scenario_id": "<cluster_index-scenario-序号，例如 C1-S1>",
      "scenario_title": "<围绕主风险轴的标题>",
      "security_type": "<BOLA|BFLA|BOPLA|AUTH_BYPASS|RESOURCE_CONSUMPTION>",
      "risk_level": "<low|medium|high>",
      "risk_score": <0.0到1.0>,
      "risk_type": "<sequence_order|parameter_consistency|both>",
      "risk_example": "<一句话描述异常攻击例子>",
      "attack_observation": "<从当前异常簇看到的异常行为>",
      "attack_point": "<可能存在的服务端校验薄弱点>",
      "attack_method": "<攻击者如何破坏约束，例如 直接调用/越序/替换对象ID/枚举参数/重复高成本请求>",
      "hit_condition": "<后续检测命中条件，应能转换为规则>",
      "analysis_dimensions": ["参数分析", "状态码分析"],
      "sequence_order_risk": {{
        "risk_level": "<low|medium|high>",
        "sequence_subtype": "<authorization_precheck|business_order|repeated_call|missing_step>",
        "normal_sequence_pattern": ["<应存在的最小正常链路，必须是真实 API；不确定可少写>"],
        "possible_violation_sequence_pattern": ["<当前异常簇中的违规 API 链路>"],
        "violated_order_constraint": "<被破坏的顺序约束>",
        "missing_or_reordered_step": "<缺失、提前、越序或重复的关键真实 API>",
        "why_this_order_is_risky": "<为什么这个异常顺序有安全风险>",
        "authorization_precheck": {{
          "precheck_required": <true|false>,
          "precheck_api": "<真实 API；没有则空字符串>",
          "required_response_keywords": ["token", "session", "permission", "access", "allowed", "role"],
          "max_interval_seconds": 300,
          "browser_context_required": true
        }},
        "related_apis": ["<相关真实API>"]
      }},
      "parameter_consistency_risk": {{
        "risk_level": "<low|medium|high>",
        "key_parameters_or_objects": ["<关键参数或对象>"],
        "target_apis": ["<目标API，最多2个>"],
        "context_apis": ["<上下文API，最多3个；没有真实关系则空数组>"],
        "normal_parameter_sequence": ["<参数正常应如何绑定或保持稳定>"],
        "parameter_dependency_relation": "<stable_within_target_api|derived_from_context_api|bound_to_upstream_context|same_actor_context|unknown>",
        "expected_parameter_source": "<upstream_context_api|same_request_or_business_context|authenticated_session|target_api_observed_values|unknown>",
        "parameter_occurrences": [{{"parameter":"<参数名>","api":"<API>","location":"<path|query|body|header|response_or_business_context|unknown>","role":"<context_source|target_parameter>"}}],
        "context_binding": [{{"source_api":"<上下文API>","target_api":"<目标API>","parameter":"<同名参数；不同名可为空>","source_parameter":"<来源参数名>","target_parameter":"<目标参数名>","relation":"<归属依赖|派生依赖|同一对象|同一用户上下文|组合键|其他>","explanation":"<为什么该绑定可检测>"}}],
        "parameter_risk_cases": [
          {{
            "case_id": "<P1>",
            "parameter_or_parameter_group": ["<本case参数>"],
            "source_api": "<上下文来源API；没有则空字符串>",
            "target_api": "<目标API>",
            "source_parameter": "<来源参数名；没有则空字符串>",
            "target_parameter": "<目标参数名>",
            "relationship": "<正常绑定、稳定性或来源关系>",
            "risky_form": "<替换、枚举、跨对象、跨父对象、来源不明、客户端控制属性等>",
            "case_reason": "<为什么这是独立规则场景>"
          }}
        ],
        "risky_parameter_form": "<异常参数形式>",
        "needs_openapi_or_raw_request_confirmation": <true|false>
      }},
      "response_code_evidence": {{
        "cluster_status_distribution": {{"<status>": <count>}},
        "sequence_status_observation": "<异常序列状态码如何支撑或削弱该规则>",
        "precheck_api_status_observation": "<前置 API 状态码含义；没有则省略>",
        "target_api_status_observation": "<目标 API 状态码含义；没有则省略>",
        "parameter_api_status_observation": "<参数相关 API 状态码含义；没有则省略>",
        "risk_level_adjustment_reason": "<响应码如何影响风险等级>"
      }},
      "overall_reason": "<综合风险评级原因，1 到 3 句话>",
      "later_check_hint": "<后续规则生成/检测还需要关注的字段或限制>"
    }}
  ],
  "suggestion": {{
    "eps_action": "keep",
    "min_samples_action": "keep",
    "reason": "<异常簇用于规则反推，聚类参数建议>"
  }}
}}
"""


def compact_cluster_for_prompt(
    site_id: str,
    cluster: dict[str, Any],
    algorithm: dict[str, Any],
    args: argparse.Namespace,
    openapi_context: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    working = dict(cluster)
    prompt = build_prompt(site_id, working, algorithm, openapi_context)
    while len(prompt) > args.max_prompt_chars and working.get("sampled_members"):
        working["sampled_members"] = working["sampled_members"][:-1]
        prompt = build_prompt(site_id, working, algorithm, openapi_context)
    while len(prompt) > args.max_prompt_chars and len(working.get("representative_trace_sample", [])) > 12:
        sample = working["representative_trace_sample"]
        working["representative_trace_sample"] = sample[:8] + [sample[len(sample) // 2]] + sample[-3:]
        prompt = build_prompt(site_id, working, algorithm, openapi_context)
    return working, prompt


def extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def call_llm(prompt: str, args: argparse.Namespace) -> dict[str, Any]:
    base_url = normalize_openai_base_url(str(args.llm_url).strip())
    api_key = str(getattr(args, "api_key", "") or "").strip()
    if not base_url:
        raise ValueError("AutoDL LLM requires --llm-url/base_url.")
    if not api_key:
        raise ValueError("AutoDL LLM requires --api-key or AUTODL_API_KEY/LLM_API_KEY.")
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("AutoDL LLM requires the OpenAI Python SDK: pip install openai") from exc

    client = OpenAI(base_url=base_url, api_key=api_key)
    messages = [
        {"role": "system", "content": DEFAULT_REVIEW_SYSTEM_PROMPT},
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
            content = "".join(chunks)
            return extract_json(content)
        except error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                detail = ""
            last_error = RuntimeError(f"HTTP {exc.code} {exc.reason}: {detail[:1000]}")
            if attempt < args.retry:
                time.sleep(3 * (attempt + 1))
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < args.retry:
                time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"LLM review failed: {last_error}")


def as_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value:
        return [str(value).strip()]
    return []


def unique_keep_order(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def nearest_context_apis(all_apis: list[str], target_apis: list[str], limit: int = MAX_CONTEXT_APIS_PER_PARAMETER_SCENARIO) -> list[str]:
    if not all_apis or not target_apis:
        return []
    target_set = set(target_apis)
    first_target_index = next((index for index, api in enumerate(all_apis) if api in target_set), len(all_apis))
    candidates = [api for api in all_apis[:first_target_index] if api not in target_set]
    if not candidates:
        candidates = [api for api in all_apis if api not in target_set]
    return unique_keep_order(candidates)[-limit:]


def compact_parameter_api_scope(context_apis: list[str], target_apis: list[str], all_apis: list[str]) -> tuple[list[str], list[str]]:
    targets = unique_keep_order(target_apis)[:MAX_TARGET_APIS_PER_PARAMETER_SCENARIO]
    if not targets and all_apis:
        targets = [all_apis[-1]]
    contexts = unique_keep_order([api for api in context_apis if api not in set(targets)])
    if not contexts and all_apis:
        contexts = nearest_context_apis(all_apis, targets)
    contexts = contexts[:MAX_CONTEXT_APIS_PER_PARAMETER_SCENARIO]
    return contexts, targets


def api_like_values(values: list[str]) -> list[str]:
    return [value for value in values if HTTP_API_RE.match(value)]


def is_virtual_sequence_step(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and VIRTUAL_SEQUENCE_STEP_RE.search(text) and not HTTP_API_RE.match(text))


def strip_virtual_sequence_steps(block: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(block, dict):
        return {}
    cleaned = dict(block)
    for key in ("normal_sequence_pattern", "possible_violation_sequence_pattern", "risky_sequence_pattern", "related_apis"):
        if key not in cleaned:
            continue
        values = as_text_list(cleaned.get(key, []))
        cleaned[key] = [value for value in values if not is_virtual_sequence_step(value)]
    precheck = cleaned.get("authorization_precheck")
    if isinstance(precheck, dict):
        precheck = dict(precheck)
        precheck_api = str(precheck.get("precheck_api", "") or "").strip()
        if precheck_api and not HTTP_API_RE.match(precheck_api):
            precheck["precheck_api"] = ""
        cleaned["authorization_precheck"] = precheck
    return cleaned


def representative_apis(cluster: dict[str, Any] | None) -> list[str]:
    if not cluster:
        return []
    trace = cluster.get("representative_trace_sample", [])
    return api_like_values(as_text_list(trace))


def block_text(block: dict[str, Any]) -> str:
    parts = []
    for value in block.values():
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif value:
            parts.append(str(value))
    return "\n".join(parts)


def scenario_text(scenario: dict[str, Any]) -> str:
    parts = []
    for key in ("scenario_title", "security_type", "risk_type", "overall_reason", "later_check_hint"):
        if scenario.get(key):
            parts.append(str(scenario[key]))
    for key in ("sequence_order_risk", "parameter_consistency_risk"):
        block = scenario.get(key, {})
        if isinstance(block, dict):
            parts.append(block_text(block))
    return "\n".join(parts)


def resource_consumption_api_texts(scenario: dict[str, Any], cluster: dict[str, Any] | None) -> list[str]:
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    sequence_block = strip_virtual_sequence_steps(sequence_block)
    values: list[str] = []
    for key in ("normal_sequence_pattern", "possible_violation_sequence_pattern", "risky_sequence_pattern", "related_apis"):
        values.extend(as_text_list(sequence_block.get(key, [])))
    values.extend(representative_apis(cluster))
    return api_like_values(values)


def is_benign_polling_resource_scenario(scenario: dict[str, Any], cluster: dict[str, Any] | None) -> bool:
    text = scenario_text(scenario)
    api_texts = resource_consumption_api_texts(scenario, cluster)
    if not api_texts:
        return False
    if not all(BENIGN_POLLING_RE.search(api) for api in api_texts):
        return False
    return not RESOURCE_IMPACT_RE.search(text)


def has_actionable_sequence_risk(block: dict[str, Any]) -> bool:
    if not isinstance(block, dict):
        return False
    block = strip_virtual_sequence_steps(block)
    normal = as_text_list(block.get("normal_sequence_pattern", []))
    risky = as_text_list(block.get("possible_violation_sequence_pattern", block.get("risky_sequence_pattern", [])))
    text = block_text(block)
    if any(is_virtual_sequence_step(item) for item in normal + risky):
        return False
    if not risky or NO_RISK_RE.search(text):
        return False
    if len(api_like_values(normal)) < 2 and len(normal) < 2:
        return False
    return bool(SEQUENCE_SIGNAL_RE.search(text))


def has_actionable_parameter_risk(block: dict[str, Any]) -> bool:
    if not isinstance(block, dict):
        return False
    params = as_text_list(block.get("key_parameters_or_objects", []))
    risky_form = str(block.get("risky_parameter_form", "") or "").strip()
    text = block_text(block)
    if not params and not risky_form:
        return False
    if NO_RISK_RE.search(text) and not params:
        return False
    return bool(params or PARAMETER_SIGNAL_RE.search(risky_form))


def risk_blocks_are_coupled(scenario: dict[str, Any]) -> bool:
    text = scenario_text(scenario)
    return bool(
        re.search(
            r"(同时|共同|两者|both|组合|顺序.{0,30}参数|参数.{0,30}顺序|上下文.{0,30}跳过|跳过.{0,30}上下文)",
            text,
            re.I,
        )
    )


def choose_risk_type(scenario: dict[str, Any]) -> str:
    declared = str(scenario.get("risk_type", "") or "").strip().lower()
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    has_sequence = has_actionable_sequence_risk(sequence_block)
    has_parameter = has_actionable_parameter_risk(parameter_block)
    if declared == "both" and has_sequence and has_parameter and risk_blocks_are_coupled(scenario):
        return "both"
    if declared == "sequence_order" and has_sequence:
        return "sequence_order"
    if declared == "parameter_consistency" and has_parameter:
        return "parameter_consistency"
    if has_sequence and has_parameter:
        return "both" if risk_blocks_are_coupled(scenario) else "parameter_consistency"
    if has_parameter:
        return "parameter_consistency"
    if has_sequence:
        return "sequence_order"
    return "none"


def infer_security_type(scenario: dict[str, Any], risk_type: str) -> str:
    declared = str(scenario.get("security_type", "") or "").strip().upper()
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    primary_text = block_text(parameter_block if risk_type == "parameter_consistency" else sequence_block)
    text = "\n".join([str(scenario.get("scenario_title", "")), primary_text, str(scenario.get("overall_reason", ""))])
    if risk_type == "parameter_consistency" and re.search(r"(id|key|object|issue|project|user|avatar|trigger|content|page|space|对象|标识)", text, re.I):
        inferred = "BOLA"
    elif risk_type == "parameter_consistency" and re.search(r"(reporter|assignee|status|securityLevel|visibility|属性|字段|状态|负责人)", text, re.I):
        inferred = "BOPLA"
    elif risk_type == "parameter_consistency" and re.search(r"(login|auth|session|token|xsrf|csrf|认证|会话)", text, re.I):
        inferred = "AUTH_BYPASS"
    elif re.search(r"(频繁|批量|资源|枚举|遍历|frequency|resource|enumerat)", text, re.I) or (
        risk_type == "sequence_order" and re.search(r"(重复|repeat)", text, re.I)
    ):
        inferred = "RESOURCE_CONSUMPTION"
    elif re.search(r"(login|auth|session|token|xsrf|csrf|认证|会话)", text, re.I):
        inferred = "AUTH_BYPASS"
    elif re.search(r"(admin|permission|role|group|config|delete|manage|权限|角色|管理|删除)", text, re.I):
        inferred = "BFLA"
    elif re.search(r"(reporter|assignee|status|securityLevel|visibility|属性|字段|状态|负责人)", text, re.I):
        inferred = "BOPLA"
    elif re.search(r"(id|key|object|issue|project|user|avatar|trigger|content|page|space|对象|标识)", text, re.I):
        inferred = "BOLA"
    else:
        inferred = declared if declared in {"BOLA", "BFLA", "BOPLA", "AUTH_BYPASS", "RESOURCE_CONSUMPTION", "OTHER"} else "OTHER"
    if declared in {"BOLA", "BFLA", "BOPLA", "AUTH_BYPASS", "RESOURCE_CONSUMPTION", "OTHER"} and inferred == "OTHER":
        return declared
    return inferred


def infer_parameters(parameter_block: dict[str, Any], scenario: dict[str, Any]) -> list[str]:
    params = as_text_list(parameter_block.get("key_parameters_or_objects", []))
    text = scenario_text(scenario)
    params.extend(PARAM_TOKEN_RE.findall(text))
    if re.search(r"/trigger/[^/\s]+", text, re.I):
        params.append("triggerId")
    return unique_keep_order(params)


def enrich_parameter_block(
    parameter_block: dict[str, Any],
    scenario: dict[str, Any],
    cluster: dict[str, Any] | None,
) -> dict[str, Any]:
    block = dict(parameter_block)
    params = infer_parameters(block, scenario)
    block["key_parameters_or_objects"] = params

    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    normal_apis = api_like_values(as_text_list(sequence_block.get("normal_sequence_pattern", [])))
    related_apis = api_like_values(as_text_list(sequence_block.get("related_apis", [])))
    cluster_apis = representative_apis(cluster)
    all_apis = unique_keep_order(as_text_list(block.get("normal_parameter_sequence", [])) + normal_apis + related_apis + cluster_apis)
    target_apis = api_like_values(as_text_list(block.get("target_apis", [])))
    context_apis = api_like_values(as_text_list(block.get("context_apis", [])))
    context_apis, target_apis = compact_parameter_api_scope(context_apis, target_apis, all_apis)
    block["target_apis"] = target_apis
    block["context_apis"] = context_apis
    block["normal_parameter_sequence"] = all_apis
    context_set = set(context_apis)
    target_set = set(target_apis)

    risk_form = str(block.get("risky_parameter_form", "") or "").strip()
    if not risk_form and params:
        risk_form = "关键参数脱离上游上下文、跨对象替换或在同一业务链路中不一致。"
    block["risky_parameter_form"] = risk_form
    dependency = str(block.get("parameter_dependency_relation", "") or "").strip()
    if not dependency or dependency.lower() == "unknown":
        dependency = "bound_to_upstream_context" if context_apis else "stable_within_target_api"
    expected_source = str(block.get("expected_parameter_source", "") or "").strip()
    if not expected_source or expected_source.lower() == "unknown":
        expected_source = "upstream_context_api" if context_apis else "same_request_or_business_context"
    block["parameter_dependency_relation"] = dependency
    block["expected_parameter_source"] = expected_source

    if isinstance(block.get("parameter_occurrences"), list) and block.get("parameter_occurrences"):
        block["parameter_occurrences"] = [
            item
            for item in block.get("parameter_occurrences", [])
            if isinstance(item, dict)
            and (
                str(item.get("api", "")) in context_set
                or str(item.get("api", "")) in target_set
                or not HTTP_API_RE.match(str(item.get("api", "")))
            )
        ]
    if not isinstance(block.get("parameter_occurrences"), list) or not block.get("parameter_occurrences"):
        occurrences = []
        for param in params:
            for api in context_apis:
                occurrences.append(
                    {
                        "parameter": param,
                        "api": api,
                        "location": "response_or_business_context",
                        "role": "context_source",
                    }
                )
            for api in target_apis:
                occurrences.append(
                    {
                        "parameter": param,
                        "api": api,
                        "location": "path_query_body_or_header",
                        "role": "target_parameter",
                    }
                )
        block["parameter_occurrences"] = occurrences

    if isinstance(block.get("context_binding"), list) and block.get("context_binding"):
        block["context_binding"] = [
            item
            for item in block.get("context_binding", [])
            if isinstance(item, dict)
            and str(item.get("source_api", "")) in context_set
            and str(item.get("target_api", "")) in target_set
        ]
    if not isinstance(block.get("context_binding"), list) or not block.get("context_binding"):
        bindings = []
        for param in params:
            for source_api in context_apis:
                for target_api in target_apis:
                    bindings.append(
                        {
                            "source_api": source_api,
                            "target_api": target_api,
                            "parameter": param,
                            "relation": dependency,
                            "explanation": f"{param} 应由上下文 API 约束目标 API，不能在后续调用中脱离上下文或中途替换。",
                        }
                    )
        block["context_binding"] = bindings
    block["needs_openapi_or_raw_request_confirmation"] = True
    return block


def api_status_observations(status_summary: dict[str, Any], apis: list[str]) -> list[dict[str, Any]]:
    if not isinstance(status_summary, dict) or not apis:
        return []
    wanted = set(api_without_status(api) for api in apis)
    observations = []
    for item in status_summary.get("top_api_statuses", []) or []:
        if not isinstance(item, dict):
            continue
        api = api_without_status(str(item.get("api", "")))
        if api in wanted:
            observations.append(
                {
                    "api": api,
                    "status": str(item.get("status", "")),
                    "count": item.get("count", 0),
                }
            )
    return observations


def build_response_code_evidence(scenario: dict[str, Any], cluster: dict[str, Any] | None) -> dict[str, Any]:
    evidence = cluster.get("status_code_evidence", {}) if isinstance(cluster, dict) else {}
    cluster_summary = evidence.get("cluster_status_summary", {}) if isinstance(evidence, dict) else {}
    representative_summary = evidence.get("representative_status_summary", {}) if isinstance(evidence, dict) else {}
    status_distribution = (
        cluster_summary.get("status_distribution", {})
        if isinstance(cluster_summary, dict)
        else {}
    )
    family_distribution = (
        cluster_summary.get("status_family_distribution", {})
        if isinstance(cluster_summary, dict)
        else {}
    )
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    precheck_apis = api_like_values(as_text_list(sequence_block.get("normal_sequence_pattern", []))[:-1])
    target_apis = api_like_values(as_text_list(parameter_block.get("target_apis", [])))
    target_apis.extend(api_like_values(as_text_list(sequence_block.get("related_apis", []))))
    if not target_apis:
        target_apis = api_like_values(as_text_list(sequence_block.get("normal_sequence_pattern", []))[-1:])
    context_apis = api_like_values(as_text_list(parameter_block.get("context_apis", [])))
    api_status_source = cluster_summary if isinstance(cluster_summary, dict) and cluster_summary.get("top_api_statuses") else representative_summary
    output = {
        "cluster_status_distribution": status_distribution,
        "cluster_status_family_distribution": family_distribution,
        "sequence_status_observation": "结合簇级状态码分布判断该正常链路主要是成功处理、权限拒绝、对象不存在还是服务端异常。",
        "risk_level_adjustment_reason": "响应码作为风险可信度证据使用；2xx/3xx通常增强已处理请求的可信度，401/403降低越权成功判断但支持探测或前置失败，5xx增强资源消耗或异常处理风险。",
    }
    precheck_statuses = api_status_observations(api_status_source, precheck_apis or context_apis)
    if precheck_statuses:
        output["precheck_api_statuses"] = precheck_statuses
        output["precheck_api_status_observation"] = "前置、上下文或校验 API 的状态码用于判断上下文是否真正建立。"
    target_statuses = api_status_observations(api_status_source, unique_keep_order(target_apis))
    if target_statuses:
        output["target_api_statuses"] = target_statuses
        output["target_api_status_observation"] = "目标 API 的状态码用于判断敏感动作、详情访问或高成本请求是否被服务端处理。"
    parameter_statuses = api_status_observations(api_status_source, unique_keep_order(context_apis + target_apis))
    if parameter_statuses:
        output["parameter_api_statuses"] = parameter_statuses
        output["parameter_api_status_observation"] = "参数上下文相关 API 的状态码用于判断对象来源、目标对象和上下文绑定是否需要进一步确认。"
    return output


def build_aligned_title(scenario: dict[str, Any], risk_type: str, security_type: str) -> str:
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    params = as_text_list(parameter_block.get("key_parameters_or_objects", []))
    normal_apis = api_like_values(as_text_list(sequence_block.get("normal_sequence_pattern", [])))
    object_name = params[0] if params else "对象参数"
    api_name = normal_apis[-1].split(maxsplit=1)[-1].rsplit("/", 1)[-1] if normal_apis else "接口"
    if risk_type == "parameter_consistency":
        if security_type == "BOLA":
            return f"{object_name} 上下文不一致导致的对象级访问风险"
        if security_type == "BOPLA":
            return f"{object_name} 属性参数越权修改风险"
        if security_type == "AUTH_BYPASS":
            return f"{object_name} 认证上下文不一致风险"
        return f"{object_name} 参数上下文一致性风险"
    if risk_type == "sequence_order":
        if security_type == "RESOURCE_CONSUMPTION":
            return f"{api_name} 重复调用资源消耗风险"
        if security_type == "BFLA":
            return f"{api_name} 高权限操作顺序绕过风险"
        return f"{api_name} 业务顺序约束绕过风险"
    if risk_type == "both":
        return f"{object_name} 上下文参数与业务顺序共同绕过风险"
    return str(scenario.get("scenario_title") or "安全场景依据不足")


def title_matches_primary_axis(title: str, risk_type: str, security_type: str) -> bool:
    text = str(title or "")
    if not text:
        return False
    if risk_type == "parameter_consistency":
        return bool(PARAMETER_SIGNAL_RE.search(text)) and not re.search(r"(重复调用|资源消耗|顺序|跳过|越序)", text)
    if risk_type == "sequence_order":
        return bool(SEQUENCE_SIGNAL_RE.search(text) or re.search(r"(顺序|跳过|越序|重复调用|资源消耗)", text))
    if risk_type == "both":
        return bool(PARAMETER_SIGNAL_RE.search(text) and SEQUENCE_SIGNAL_RE.search(text))
    return False


def normalize_security_scenario(scenario: dict[str, Any], cluster: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(scenario, dict):
        return None
    scenario = dict(scenario)
    risk_type = choose_risk_type(scenario)
    if risk_type == "none":
        return None
    security_type = infer_security_type(scenario, risk_type)
    scenario["risk_type"] = risk_type
    scenario["security_type"] = security_type
    if security_type == "RESOURCE_CONSUMPTION" and is_benign_polling_resource_scenario(scenario, cluster):
        return None

    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    if risk_type == "parameter_consistency":
        scenario.pop("sequence_order_risk", None)
        scenario["parameter_consistency_risk"] = enrich_parameter_block(parameter_block, scenario, cluster)
    elif risk_type == "sequence_order":
        scenario["sequence_order_risk"] = sequence_block
        scenario.pop("parameter_consistency_risk", None)
    else:
        scenario["sequence_order_risk"] = sequence_block
        scenario["parameter_consistency_risk"] = enrich_parameter_block(parameter_block, scenario, cluster)

    current_title = str(scenario.get("scenario_title", "") or "")
    if not title_matches_primary_axis(current_title, risk_type, security_type):
        scenario["scenario_title"] = build_aligned_title(scenario, risk_type, security_type)

    if risk_type == "parameter_consistency":
        scenario["overall_reason"] = str(scenario.get("overall_reason") or "该场景主风险来自关键参数与业务上下文不一致，需要检查参数来源、目标 API 和上下文绑定关系。")
        scenario["later_check_hint"] = "重点检查 parameter_consistency_risk 中的 target_apis、context_apis、parameter_occurrences 和 context_binding，不把重复调用或顺序异常作为本场景主证据。"
    elif risk_type == "sequence_order":
        scenario["overall_reason"] = str(scenario.get("overall_reason") or "该场景主风险来自业务顺序约束被跳过、越序或重复触发。")
        scenario["later_check_hint"] = "重点检查 sequence_order_risk 中的正常链路与违规链路，不把参数替换作为本场景主证据。"
    if not isinstance(scenario.get("response_code_evidence"), dict):
        scenario["response_code_evidence"] = build_response_code_evidence(scenario, cluster)
    return scenario


def summarize_reviews(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    if not reviews:
        return {
            "reviewed_clusters": 0,
            "trustworthy_clusters": 0,
            "untrustworthy_clusters": 0,
            "avg_trust_score": 0.0,
            "possible_security_scenario_count": 0,
        }
    scores = [float(item.get("trust_score", 0.0) or 0.0) for item in reviews]
    trustworthy = [item for item in reviews if bool(item.get("is_trustworthy"))]
    scenario_count = sum(len(item.get("possible_security_scenarios", []) or []) for item in trustworthy)
    return {
        "reviewed_clusters": len(reviews),
        "trustworthy_clusters": len(trustworthy),
        "untrustworthy_clusters": len(reviews) - len(trustworthy),
        "avg_trust_score": round(sum(scores) / len(scores), 4),
        "possible_security_scenario_count": scenario_count,
        "low_trust_cluster_indexes": [
            item.get("cluster_index") for item in reviews if float(item.get("trust_score", 0.0) or 0.0) < 0.6
        ],
    }


def reviews_with_security_scenarios(reviews: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        review
        for review in reviews
        if isinstance(review.get("possible_security_scenarios"), list)
        and review.get("possible_security_scenarios")
    ]


def normalize_review(review: dict[str, Any], cluster: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(review, dict):
        return {}
    try:
        trust_score = float(review.get("trust_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        trust_score = 0.0
        review["trust_score"] = 0.0
    mixed = review.get("mixed_member_session_ids", [])
    has_mixed = bool(mixed) if isinstance(mixed, list) else bool(mixed)
    scenarios = []
    for scenario in review.get("possible_security_scenarios", []) or []:
        normalized = normalize_security_scenario(scenario, cluster)
        if normalized:
            scenarios.append(normalized)
    review["possible_security_scenarios"] = scenarios
    warnings = []
    if not review.get("is_trustworthy"):
        warnings.append("LLM 认为该簇不太适合作为稳定正常业务模式参考。")
    if trust_score < 0.7:
        warnings.append("trust_score 低于 0.7，后续使用安全场景时建议人工复核。")
    if has_mixed:
        warnings.append("mixed_member_session_ids 非空，可能存在混簇。")
    if warnings:
        review["scenario_generation_warning"] = " ".join(warnings)
        review.setdefault("possible_security_scenarios", [])
    return review


def load_existing_reviews(output_path: Path) -> list[dict[str, Any]]:
    if not output_path.exists():
        return []
    try:
        payload = read_json(output_path)
    except Exception:  # noqa: BLE001
        return []
    reviews = payload.get("reviews", [])
    return [normalize_review(item) for item in reviews] if isinstance(reviews, list) else []


def review_key(review: dict[str, Any]) -> tuple[Any, str]:
    return review.get("cluster_index"), str(review.get("business_pattern_name", "")).strip()


def build_review_output(
    args: argparse.Namespace,
    cluster_file: Path,
    short_sequence_clusters: list[dict[str, Any]],
    existing_reviews: list[dict[str, Any]],
    prompts: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    failed_reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    scenario_reviews = reviews_with_security_scenarios(reviews)
    return {
        "site_id": args.site_id,
        "cluster_file": str(cluster_file),
        "review_policy": {
            "max_clusters": args.max_clusters,
            "members_per_cluster": args.members_per_cluster,
            "max_steps": args.max_steps,
            "min_confidence_sequence_length": args.min_confidence_sequence_length,
            "short_sequence_filtered_count": len(short_sequence_clusters),
            "skip_existing_reviews": not args.rerun_all,
            "reused_review_count": len(existing_reviews),
            "new_review_count": len(prompts),
            "completed_new_review_count": max(0, len(reviews) - len(existing_reviews)),
            "failed_review_count": len(failed_reviews),
            "security_scenario_cluster_count": len(scenario_reviews),
        },
        "summary": summarize_reviews(scenario_reviews),
        "reviews": scenario_reviews,
        "failed_reviews": failed_reviews,
    }


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    cluster_file = Path(args.cluster_file) if args.cluster_file else base_dir / "process_mining" / f"site_{args.site_id}_business_session_clusters.json"
    openapi_file = Path(args.openapi_file) if args.openapi_file else base_dir / "API_document" / f"site_{args.site_id}_openapi.json"
    parameter_profile_file = (
        Path(args.parameter_profile_file)
        if args.parameter_profile_file
        else base_dir / "parameter_profiles" / f"site_{args.site_id}_parameter_profile.json"
    )
    openapi_context = load_openapi_context(openapi_file)
    parameter_profile_context = load_parameter_profile_context(parameter_profile_file)
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "process_mining" / "llm_abnormal_rule_inference"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"site_{args.site_id}_abnormal_rule_inference.json"

    cluster_payload = read_json(cluster_file)
    clusters = list(cluster_payload.get("clusters", []))
    if args.max_clusters > 0:
        clusters = clusters[: args.max_clusters]

    algorithm = cluster_payload.get("algorithm", {})
    compact_clusters = [
        compact_cluster(cluster, index, args)
        for index, cluster in enumerate(clusters, start=1)
    ]
    short_sequence_clusters = [
        short_sequence_filter_record(cluster, args.min_confidence_sequence_length)
        for cluster in compact_clusters
        if not is_confidence_reviewable(cluster, args.min_confidence_sequence_length)
    ]
    reviewable_clusters = [
        cluster
        for cluster in compact_clusters
        if is_confidence_reviewable(cluster, args.min_confidence_sequence_length)
    ]
    existing_reviews = [] if args.rerun_all else load_existing_reviews(output_path)
    existing_by_cluster = {
        item.get("cluster_index"): item
        for item in existing_reviews
        if item.get("cluster_index") is not None
    }
    existing_names = {
        str(item.get("business_pattern_name", "")).strip()
        for item in existing_reviews
        if str(item.get("business_pattern_name", "")).strip()
    }
    prompts = []
    for cluster in reviewable_clusters:
        if cluster["cluster_index"] in existing_by_cluster:
            continue
        cluster_api_document_context = build_api_document_context(
            cluster,
            openapi_context,
            parameter_profile_context,
            args.max_openapi_context_paths,
        )
        prompt_cluster, prompt = compact_cluster_for_prompt(args.site_id, cluster, algorithm, args, cluster_api_document_context)
        prompts.append(
            {
                "cluster_index": cluster["cluster_index"],
                "prompt_chars": len(prompt),
                "openapi_file": str(openapi_file),
                "parameter_profile_file": str(parameter_profile_file),
                "openapi_matched_path_count": cluster_api_document_context.get("openapi_context", {}).get("matched_path_count", 0),
                "parameter_profile_matched_path_count": cluster_api_document_context.get("parameter_profile_context", {}).get("matched_path_count", 0),
                "prompt_cluster": prompt_cluster,
                "prompt": prompt,
            }
        )

    prompt_path = output_dir / f"site_{args.site_id}_abnormal_rule_inference_prompts.json"
    write_json(prompt_path, prompts)
    if args.dry_run:
        print(f"site={args.site_id} dry_run=true prompts={prompt_path}")
        return

    reviews = list(existing_reviews)
    failed_reviews: list[dict[str, Any]] = []
    write_json(
        output_path,
        build_review_output(args, cluster_file, short_sequence_clusters, existing_reviews, prompts, reviews, failed_reviews),
    )
    for item_index, item in enumerate(prompts, start=1):
        print(
            f"site={args.site_id} review_item={item_index}/{len(prompts)} "
            f"cluster_index={item['cluster_index']} prompt_chars={item['prompt_chars']}"
        )
        try:
            review = normalize_review(call_llm(item["prompt"], args), item.get("prompt_cluster"))
        except Exception as exc:  # noqa: BLE001
            failed_reviews.append(
                {
                    "cluster_index": item["cluster_index"],
                    "prompt_chars": item["prompt_chars"],
                    "error": str(exc),
                }
            )
            write_json(
                output_path,
                build_review_output(args, cluster_file, short_sequence_clusters, existing_reviews, prompts, reviews, failed_reviews),
            )
            print(f"site={args.site_id} review_failed cluster_index={item['cluster_index']} error={str(exc)[:300]}")
            continue
        business_name = str(review.get("business_pattern_name", "")).strip()
        if business_name and business_name in existing_names:
            review["duplicate_business_pattern_name"] = True
            review["duplicate_note"] = "该业务模式名称已在历史审核结果中出现，本次保留质检结论但可在后续案例汇总时去重。"
        elif business_name:
            existing_names.add(business_name)
        reviews.append(review)
        write_json(
            output_path,
            build_review_output(args, cluster_file, short_sequence_clusters, existing_reviews, prompts, reviews, failed_reviews),
        )

    print(
        f"site={args.site_id} reused_reviews={len(existing_reviews)} new_reviews={len(prompts)} "
        f"completed_new_reviews={max(0, len(reviews) - len(existing_reviews))} failed_reviews={len(failed_reviews)} "
        f"total_reviews={len(reviews)} output={output_path}"
    )


if __name__ == "__main__":
    main()
