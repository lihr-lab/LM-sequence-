# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib import error, request


DEFAULT_BASE_DIR = r"D:\browser\Innovation\sequence\log_process"
DEFAULT_LOCAL_LLM_URL = "http://localhost:11434/api/generate"
DEFAULT_LOCAL_MODEL = "deepseek-r1:14b"


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
- 现在主要做“序列风险评级”，不要深入拆成复杂业务权限规则。
- BOLA、BFLA、BOPLA、AUTH_BYPASS、RESOURCE_CONSUMPTION 这些安全类型表示“可能属于哪类攻击语义”。如果无法明确归类，可以使用 OTHER。
- 每个安全类型尽量从两个分析层面说明风险；如果其中一个层面依据不足，可以写低风险或说明需要更多证据：
  1. sequence_order_risk：从正常顺序链反推“可能被破坏的顺序形式”。不要评价当前聚类序列本身，只说明攻击场景下可能如何跳过、越序或重复关键步骤，例如：
     - 正常：登录/建立上下文 -> 列表/详情/校验 -> 修改/提交/确认
     - 可能违规：直接修改/提交/确认；或 列表 -> 修改，跳过详情/校验；或 先修改后校验；或 敏感接口重复调用
  2. parameter_consistency_risk：从正常参数上下文反推“可能被破坏的参数一致性形式”。例如同一会话中 issueId/projectId/userId/avatarId/orderId 等对象标识中途切换；后续接口参数没有来自前置上下文；参数集合、参数类型、参数依赖需要结合 OpenAPI 和原始请求确认。
- 例如 BOLA/横向越权不要细化到具体权限库，而是说明：序列上是否绕过列表/详情/项目上下文直接访问对象；参数上是否替换 issueId/projectId/userId/avatarId 等对象标识。
- 例如 BFLA/纵向越权说明：序列上普通流程中是否出现 admin/config/delete/permission 等高权限接口；参数上是否出现 role/permission/group/admin 等高权限参数。
- 例如 BOPLA/属性越权说明：序列上是否在创建/更新/转派/状态流中跳过校验步骤；参数上是否提交 reporter/status/securityLevel/assignee/project 等不应由客户端控制的字段。
- 例如 AUTH_BYPASS 说明：序列上是否缺少 login/session/auth 前置步骤；参数上是否缺少 token/xsrf/session 或认证参数不一致。
- sequence_order_risk.possible_violation_sequence_pattern 尽量写成具体链路，避免只写“缺少上下文验证”。如果能看出 A->B->C 的正常链路，就说明攻击场景下可能如何 A->C 跳过 B，或者 C 出现过早/重复。
- 如果无法从正常业务模式推断具体可破坏的顺序链，可以将 sequence_order_risk.risk_level 设为 low，并在 possible_violation_sequence_pattern 写“当前正常模式主要提示该接口可能需要前置上下文，无法推断具体违规链路”。
- 当前聚类输入主要是 API 路径序列，不一定包含完整 query/body/header 参数。因此参数风险不要虚构具体值，可以说明“建议检查哪些参数是否中途替换或不一致”。
- 目标是给出风险等级和大概原因，不输出具体 payload、命中条件、HTTP 成功判定、代码规则或正式规则表达式。
- 如果聚类不适合作为正常业务模式参考，possible_security_scenarios 可以返回空数组。
- 如果 trust_score 较低，或者 mixed_member_session_ids 非空且不像前端噪声，建议减少或不生成安全场景。
- 每个可信簇建议输出 1 到 2 个风险场景：优先覆盖一个序列顺序角度和一个参数一致性角度；如果依据不足，可以只输出 0 到 1 个。
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
      "sequence_order_risk": {{
        "risk_level": "<low|medium|high>",
        "normal_sequence_pattern": ["<正常链路第1步>", "<正常链路第2步>", "<正常链路第3步>"],
        "possible_violation_sequence_pattern": ["<攻击场景下的违规链路第1步>", "<违规链路第2步，尽量体现跳过/越序/重复>"],
        "violated_order_constraint": "<被破坏的顺序约束，例如 通常应先详情/校验再修改；如果无法判断写 无法确定>",
        "missing_or_reordered_step": "<被跳过、缺失、提前或重复的关键步骤；如果无法判断写 无法确定>",
        "why_this_order_is_risky": "<为什么这个违规顺序有风险，尽量说清楚 A->C 跳过了 B 或 C 出现过早/重复>",
        "related_apis": ["<相关API>"]
      }},
      "parameter_consistency_risk": {{
        "risk_level": "<low|medium|high>",
        "key_parameters_or_objects": ["<需要检查是否中途替换或不一致的参数/对象，如 issueId/projectId/avatarId>"],
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


def normalize_review(review: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(review, dict):
        return {}
    try:
        trust_score = float(review.get("trust_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        trust_score = 0.0
        review["trust_score"] = 0.0
    mixed = review.get("mixed_member_session_ids", [])
    has_mixed = bool(mixed) if isinstance(mixed, list) else bool(mixed)
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
    for cluster in compact_clusters:
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
        review = normalize_review(call_llm(item["prompt"], args))
        business_name = str(review.get("business_pattern_name", "")).strip()
        if business_name and business_name in existing_names:
            review["duplicate_business_pattern_name"] = True
            review["duplicate_note"] = "该业务模式名称已在历史审核结果中出现，本次保留质检结论但可在后续案例汇总时去重。"
        elif business_name:
            existing_names.add(business_name)
        reviews.append(review)

    output = {
        "site_id": args.site_id,
        "cluster_file": str(cluster_file),
        "review_policy": {
            "max_clusters": args.max_clusters,
            "members_per_cluster": args.members_per_cluster,
            "max_steps": args.max_steps,
            "skip_existing_reviews": not args.rerun_all,
            "reused_review_count": len(existing_reviews),
            "new_review_count": len(prompts),
        },
        "summary": summarize_reviews(reviews),
        "reviews": reviews,
    }
    write_json(output_path, output)
    print(f"site={args.site_id} reused_reviews={len(existing_reviews)} new_reviews={len(prompts)} total_reviews={len(reviews)} output={output_path}")


if __name__ == "__main__":
    main()
