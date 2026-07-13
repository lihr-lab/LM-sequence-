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


DEFAULT_BASE_DIR = r"D:\browser\Innovation\sequence\log_process"
DEFAULT_LOCAL_LLM_URL = "http://localhost:11434/api/generate"
DEFAULT_LOCAL_MODEL = "deepseek-r1:14b"
HTTP_API_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+", re.I)
PARAM_TOKEN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Key|Name|Token|Role|Permission|Status|Type|Level|Number))\b")
NO_RISK_RE = re.compile(r"(无明显|无参数风险|无顺序风险|无法确定|无法推断|依据不足|none|not applicable|n/a)", re.I)
SEQUENCE_SIGNAL_RE = re.compile(r"(跳过|越序|提前|缺失|重复|先.*后|直接调用|绕过|order|sequence|repeat|missing|skip)", re.I)
PARAMETER_SIGNAL_RE = re.compile(r"(参数|对象|标识|id|key|token|上下文|来源|绑定|中途替换|不一致|跨对象|parameter|context|binding)", re.I)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Use an LLM to review whether API session clusters are semantically coherent.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--cluster-file", default="", help="Default: <base-dir>/process_mining/site_<site_id>_business_session_clusters.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/process_mining/llm_cluster_reviews")
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--llm-url", default=os.getenv("LOCAL_LLM_URL", DEFAULT_LOCAL_LLM_URL), help="Local Ollama generate API URL.")
    parser.add_argument("--model", default=os.getenv("LOCAL_LLM_MODEL", DEFAULT_LOCAL_MODEL), help="Local Ollama model name.")
    parser.add_argument("--max-clusters", type=int, default=0, help="0 means all clusters.")
    parser.add_argument("--members-per-cluster", type=int, default=3)
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--head-steps", type=int, default=18)
    parser.add_argument("--tail-steps", type=int, default=12)
    parser.add_argument("--max-prompt-chars", type=int, default=30000)
    parser.add_argument("--request-timeout", type=int, default=120)
    parser.add_argument("--retry", type=int, default=2)
    parser.add_argument("--min-confidence-sequence-length", type=int, default=5, help="Clusters whose representative sequence is shorter than this are not sent to LLM confidence review.")
    parser.add_argument("--rerun-all", action="store_true", help="Re-review clusters even if they already exist in the output file.")
    parser.add_argument("--dry-run", action="store_true", help="Only write prompts, do not call LLM.")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


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


def compact_cluster(cluster: dict[str, Any], cluster_index: int, args: argparse.Namespace) -> dict[str, Any]:
    members = cluster.get("member_sessions", [])
    compact_members = []
    for member in members[: args.members_per_cluster]:
        compact_members.append(
            {
                "session_id": member.get("session_id", ""),
                "distance_to_representative": member.get("distance_to_representative"),
                "length": member.get("length"),
                "summary": trace_summary(member.get("trace", [])),
                "trace_sample": trim_trace(member.get("trace", []), args.max_steps, args.head_steps, args.tail_steps),
            }
        )
    return {
        "cluster_index": cluster_index,
        "cluster_size": cluster.get("cluster_size"),
        "representative_session_id": cluster.get("representative_session_id", ""),
        "representative_length": cluster.get("representative_length"),
        "representative_summary": trace_summary(cluster.get("representative_trace", [])),
        "representative_trace_sample": trim_trace(cluster.get("representative_trace", []), args.max_steps, args.head_steps, args.tail_steps),
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


def build_prompt(site_id: str, cluster: dict[str, Any], algorithm: dict[str, Any]) -> str:
    compact = json.dumps(cluster, ensure_ascii=False, separators=(",", ":"))
    algo = json.dumps(algorithm, ensure_ascii=False, separators=(",", ":"))
    return f"""你是 API 日志业务流程聚类质检员和安全场景推演员。

任务：
1. 判断一个 DBSCAN 聚类簇是否适合作为正常业务模式参考。可信的意思是：代表会话和成员会话大体体现同一种业务模式或同一类用户操作流程；头像、配置、通知、轮询、静态资源等噪声可以接受，但需要指出明显混入的不同业务流程。
2. 当该簇可以作为正常业务模式参考时，基于这个正常业务模式推演可能的安全攻击场景。如果该簇混杂严重、代表序列不稳定或业务含义不清晰，可以不生成安全场景，并说明原因。
3. 输入簇默认只是正常业务模式样本，你要做的是：从正常业务模式反推“如果攻击者破坏这个模式，可能出现什么安全风险场景”。
4. 安全攻击场景要尽量具体：说明正常业务约束、可能的攻击主体、目标对象/API、被破坏的约束、可能的越权形式。这里只写场景说明，不设计具体检测规则，不生成攻击脚本，不生成 payload，不生成一阶逻辑表达式。

安全风险评级要求：
- 风险类型必须围绕一个主风险轴展开。risk_type=parameter_consistency 时，标题、原因和 later_check_hint 都应围绕参数上下文、参数依赖或参数流动；不要再把重复请求、资源消耗、顺序跳步作为主证据。risk_type=sequence_order 时，标题和原因应围绕跳步、越序、缺失或重复；不要硬凑参数替换。
- sequence_order_risk 和 parameter_consistency_risk 不是每个场景都必须同时成立。只有实际正常链路能支持时才输出 sequence_order_risk 字段；只有能明确关键参数、上下文 API、目标 API 或参数依赖时才输出 parameter_consistency_risk 字段；两者存在真实耦合时才使用 risk_type=both。
- BOLA、BFLA、BOPLA、AUTH_BYPASS、RESOURCE_CONSUMPTION 这些安全类型表示“可能属于哪类攻击语义”。如果无法明确归类，可以使用 OTHER。
- 每个场景只选择实际依据最充分的分析层面；如果另一个层面依据不足，必须完整删除对应风险字段，不要输出空对象、low、不适用、无法确定或解释性占位文本：
  1. sequence_order_risk：从正常顺序链反推“可能被破坏的顺序形式”。不要评价当前聚类序列本身，只说明攻击场景下可能如何跳过、越序或重复关键步骤，例如：
     - 正常：登录/建立上下文 -> 列表/详情/校验 -> 修改/提交/确认
     - 可能违规：直接修改/提交/确认；或 列表 -> 修改，跳过详情/校验；或 先修改后校验；或 敏感接口重复调用
  2. parameter_consistency_risk：从正常参数上下文反推“可能被破坏的参数一致性形式”。必须尽量明确：key_parameters_or_objects、target_apis、context_apis、normal_parameter_sequence、parameter_dependency_relation、expected_parameter_source、parameter_occurrences、context_binding。例如同一会话中 issueId/projectId/userId/avatarId/orderId 等对象标识中途切换；后续接口参数没有来自前置上下文；参数集合、参数类型、参数依赖需要结合 OpenAPI 和原始请求确认。
- 例如 BOLA/横向越权不要细化到具体权限库，而是说明：序列上是否绕过列表/详情/项目上下文直接访问对象；参数上是否替换 issueId/projectId/userId/avatarId 等对象标识。
- 例如 BFLA/纵向越权说明：序列上普通流程中是否出现 admin/config/delete/permission 等高权限接口；参数上是否出现 role/permission/group/admin 等高权限参数。
- 例如 BOPLA/属性越权说明：序列上是否在创建/更新/转派/状态流中跳过校验步骤；参数上是否提交 reporter/status/securityLevel/assignee/project 等不应由客户端控制的字段。
- 例如 AUTH_BYPASS 说明：序列上是否缺少 login/session/auth 前置步骤；参数上是否缺少 token/xsrf/session 或认证参数不一致。
- sequence_order_risk.possible_violation_sequence_pattern 尽量写成具体链路，避免只写“缺少上下文验证”。如果能看出 A->B->C 的正常链路，就说明攻击场景下可能如何 A->C 跳过 B，或者 C 出现过早/重复。
- 如果无法从正常业务模式推断具体可破坏的顺序链，直接不要输出 sequence_order_risk 字段。
- 当前聚类输入主要是 API 路径序列，不一定包含完整 query/body/header 参数。因此参数风险不要虚构具体值，可以说明“建议检查哪些参数是否中途替换或不一致”。
- 目标是给出风险等级和大概原因，不输出具体 payload、命中条件、HTTP 成功判定、代码规则或正式规则表达式。
- 如果聚类不适合作为正常业务模式参考，possible_security_scenarios 可以返回空数组。
- 如果 trust_score 较低，或者 mixed_member_session_ids 非空且不像前端噪声，建议减少或不生成安全场景。
- 每个可信簇建议输出 0 到 2 个风险场景：只输出实际场景能支持的风险；不要为了覆盖序列顺序角度和参数一致性角度而强行生成。
- risk_level 使用 low、medium、high。序列中出现修改/删除/确认/权限/配置/管理类后置动作且前置上下文不足时通常为 high；只有读接口且主要需要参数一致性确认时通常为 medium；仅为轻微重复或低影响读接口时为 low。

站点：{site_id}
聚类算法配置：
{algo}

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
      "scenario_title": "<序列风险标题，例如 工单详情流程中对象参数中途替换风险>",
      "security_type": "<BOLA|BFLA|BOPLA|AUTH_BYPASS|RESOURCE_CONSUMPTION|OTHER>",
      "risk_level": "<low|medium|high>",
      "risk_score": <0.0到1.0>,
      "risk_type": "<sequence_order|parameter_consistency|both>",
      "//": "如果不是该风险维度，直接省略对应字段，不要输出空对象或不适用说明。",
      "sequence_order_risk": {{
        "risk_level": "<low|medium|high>",
        "normal_sequence_pattern": ["<正常链路第1步>", "<正常链路第2步>", "<正常链路第3步>"],
        "possible_violation_sequence_pattern": ["<攻击场景下的违规链路第1步>", "<违规链路第2步，尽量体现跳过/越序/重复>"],
        "violated_order_constraint": "<被破坏的顺序约束，例如 通常应先详情/校验再修改>",
        "missing_or_reordered_step": "<被跳过、缺失、提前或重复的关键步骤>",
        "why_this_order_is_risky": "<为什么这个违规顺序有风险，尽量说清楚 A->C 跳过了 B 或 C 出现过早/重复>",
        "related_apis": ["<相关API>"]
      }},
      "parameter_consistency_risk": {{
        "risk_level": "<low|medium|high>",
        "key_parameters_or_objects": ["<需要检查是否中途替换或不一致的参数/对象，如 issueId/projectId/avatarId>"],
        "target_apis": ["<携带或使用关键参数的目标API>"],
        "context_apis": ["<提供业务上下文、对象来源或绑定关系的前置API；没有则空数组>"],
        "normal_parameter_sequence": ["<参数在正常业务中应出现或传递的API链路>"],
        "parameter_dependency_relation": "<stable_within_target_api|derived_from_context_api|bound_to_upstream_context|same_actor_context|unknown>",
        "expected_parameter_source": "<upstream_context_api|same_request_or_business_context|authenticated_session|unknown>",
        "parameter_occurrences": [{{"parameter":"<参数名>","api":"<API>","location":"<path|query|body|header|response_or_business_context|unknown>","role":"<context_source|target_parameter>"}}],
        "context_binding": [{{"source_api":"<上游上下文API>","target_api":"<目标API>","parameter":"<参数名>","relation":"<依赖或流动关系>","explanation":"<为什么该参数应受该上下文约束>"}}],
        "risky_parameter_form": "<可能的参数中途替换、跨对象切换、参数来源不明、参数组合不合理形式>",
        "needs_openapi_or_raw_request_confirmation": <true|false>
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


def compact_cluster_for_prompt(
    site_id: str,
    cluster: dict[str, Any],
    algorithm: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[dict[str, Any], str]:
    working = dict(cluster)
    prompt = build_prompt(site_id, working, algorithm)
    while len(prompt) > args.max_prompt_chars and working.get("sampled_members"):
        working["sampled_members"] = working["sampled_members"][:-1]
        prompt = build_prompt(site_id, working, algorithm)
    while len(prompt) > args.max_prompt_chars and len(working.get("representative_trace_sample", [])) > 12:
        sample = working["representative_trace_sample"]
        working["representative_trace_sample"] = sample[:8] + [sample[len(sample) // 2]] + sample[-3:]
        prompt = build_prompt(site_id, working, algorithm)
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
    url = str(args.llm_url).strip()
    body = {
        "model": str(args.model).strip(),
        "prompt": "你只输出合法 JSON。\n\n" + prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1},
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    http_request = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(args.retry + 1):
        try:
            with request.urlopen(http_request, timeout=args.request_timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = str(payload.get("response", ""))
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


def api_like_values(values: list[str]) -> list[str]:
    return [value for value in values if HTTP_API_RE.match(value)]


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


def has_actionable_sequence_risk(block: dict[str, Any]) -> bool:
    if not isinstance(block, dict):
        return False
    normal = as_text_list(block.get("normal_sequence_pattern", []))
    risky = as_text_list(block.get("possible_violation_sequence_pattern", block.get("risky_sequence_pattern", [])))
    text = block_text(block)
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
    if not target_apis and all_apis:
        target_apis = [all_apis[-1]]
    if not context_apis and all_apis:
        context_apis = [api for api in all_apis if api not in target_apis]
    block["target_apis"] = target_apis
    block["context_apis"] = context_apis
    block["normal_parameter_sequence"] = all_apis

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


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    cluster_file = Path(args.cluster_file) if args.cluster_file else base_dir / "process_mining" / f"site_{args.site_id}_business_session_clusters.json"
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "process_mining" / "llm_cluster_reviews"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"site_{args.site_id}_cluster_review.json"

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
        prompt_cluster, prompt = compact_cluster_for_prompt(args.site_id, cluster, algorithm, args)
        prompts.append(
            {
                "cluster_index": cluster["cluster_index"],
                "prompt_chars": len(prompt),
                "prompt_cluster": prompt_cluster,
                "prompt": prompt,
            }
        )

    prompt_path = output_dir / f"site_{args.site_id}_cluster_review_prompts.json"
    write_json(prompt_path, prompts)
    if args.dry_run:
        print(f"site={args.site_id} dry_run=true prompts={prompt_path}")
        return

    reviews = list(existing_reviews)
    for item in prompts:
        print(f"site={args.site_id} review_cluster={item['cluster_index']}/{len(prompts)} prompt_chars={item['prompt_chars']}")
        review = normalize_review(call_llm(item["prompt"], args), item.get("prompt_cluster"))
        business_name = str(review.get("business_pattern_name", "")).strip()
        if business_name and business_name in existing_names:
            review["duplicate_business_pattern_name"] = True
            review["duplicate_note"] = "该业务模式名称已在历史审核结果中出现，本次保留质检结论但可在后续案例汇总时去重。"
        elif business_name:
            existing_names.add(business_name)
        reviews.append(review)

    scenario_reviews = reviews_with_security_scenarios(reviews)
    output = {
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
            "security_scenario_cluster_count": len(scenario_reviews),
        },
        "summary": summarize_reviews(scenario_reviews),
        "reviews": scenario_reviews,
    }
    write_json(output_path, output)
    print(f"site={args.site_id} reused_reviews={len(existing_reviews)} new_reviews={len(prompts)} total_reviews={len(reviews)} output={output_path}")


if __name__ == "__main__":
    main()
