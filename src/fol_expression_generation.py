# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_BASE_DIR = r"D:\browser\Innovation\sequence\log_process"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

OBJECT_RE = re.compile(r"(issue|project|space|content|page|comment|worklog|attachment|board|sprint|filter|dashboard|avatar|user|group|id|key)", re.I)
FIELD_RE = re.compile(r"(reporter|creator|author|assignee|owner|status|resolution|security|visibility|role|permission|sprint|version|duedate|project|issuetype|transition)", re.I)
AUTH_RE = re.compile(r"(login|auth|session|cookie|token|xsrf|csrf|secure)", re.I)
ADMIN_RE = re.compile(r"(admin|permission|role|config|workflow|scheme|manage|delete|project.?role)", re.I)
FREQ_RE = re.compile(r"(search|upload|download|export|avatar|attachment|jql|cql|poll|notification|gadget|autocomplete)", re.I)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate scenario-bound first-order logic drafts.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--review-file", default="", help="Default: <base-dir>/process_mining/llm_cluster_reviews/site_<site_id>_cluster_review.json")
    parser.add_argument("--openapi-file", default="", help="Default: <base-dir>/API document/site_<site_id>_openapi.json")
    parser.add_argument("--boundary-file", default="", help="Default: <base-dir>/object_boundary_mining/site_<site_id>_project_issue_access.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/fol_expressions")
    parser.add_argument("--include-low-trust", action="store_true")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_project_boundary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"available": False, "project_contains_issues": [], "actor_accessible_projects": []}
    payload = read_json(path)
    return {
        "available": True,
        "project_contains_issues": payload.get("project_contains_issues", []) if isinstance(payload, dict) else [],
        "actor_accessible_projects": payload.get("actor_accessible_projects", []) if isinstance(payload, dict) else [],
    }


def normalize_security_type(value: str) -> str:
    mapping = {
        "BOLA": "BOLA",
        "对象级越权": "BOLA",
        "横向越权": "BOLA",
        "BFLA": "BFLA",
        "功能级越权": "BFLA",
        "纵向越权": "BFLA",
        "BOPLA": "BOPLA",
        "对象属性级越权": "BOPLA",
        "属性越权": "BOPLA",
        "AUTH_BYPASS": "AUTH_BYPASS",
        "认证绕过": "AUTH_BYPASS",
        "RESOURCE_CONSUMPTION": "RESOURCE_CONSUMPTION",
        "资源消耗": "RESOURCE_CONSUMPTION",
        "OTHER": "OTHER",
        "其他": "OTHER",
    }
    text = str(value or "").strip()
    return mapping.get(text, text or "OTHER")


def normalize_api(api: str) -> str:
    text = str(api or "").strip()
    parts = text.split(maxsplit=1)
    if len(parts) == 2 and parts[0].lower() in HTTP_METHODS:
        return f"{parts[0].upper()} {parts[1]}"
    return text


def flatten_body_schema(schema: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
    if not isinstance(schema, dict):
        return []
    output = []
    required = set(schema.get("required", []) if isinstance(schema.get("required"), list) else [])
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return output
    for name, child in properties.items():
        full_name = f"{prefix}.{name}" if prefix else str(name)
        child_schema = child if isinstance(child, dict) else {}
        output.append(
            {
                "name": full_name,
                "in": "body",
                "required": str(name) in required,
                "type": child_schema.get("type", "unknown"),
            }
        )
        output.extend(flatten_body_schema(child_schema, full_name))
    return output


def operation_parameters(operation: dict[str, Any]) -> list[dict[str, Any]]:
    params = []
    raw_params = operation.get("parameters", [])
    if isinstance(raw_params, list):
        for item in raw_params:
            if not isinstance(item, dict):
                continue
            schema = item.get("schema") if isinstance(item.get("schema"), dict) else {}
            params.append(
                {
                    "name": str(item.get("name", "")),
                    "in": str(item.get("in", "")),
                    "required": bool(item.get("required", False)),
                    "type": schema.get("type", "unknown"),
                }
            )
    body = operation.get("requestBody", {})
    content = body.get("content", {}) if isinstance(body, dict) else {}
    if isinstance(content, dict):
        for media in content.values():
            if isinstance(media, dict):
                params.extend(flatten_body_schema(media.get("schema", {})))
    return [item for item in params if item.get("name")]


def build_openapi_index(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index = {}
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        return index
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            api = f"{method.upper()} {path}"
            params = operation_parameters(operation)
            index[api] = {
                "api": api,
                "summary": operation.get("summary", ""),
                "operation_id": operation.get("operationId", ""),
                "parameters": params,
                "object_parameters": [p for p in params if OBJECT_RE.search(p["name"])],
                "sensitive_fields": [p for p in params if FIELD_RE.search(p["name"])],
                "auth_fields": [p for p in params if AUTH_RE.search(p["name"])],
            }
    return index


def api_matches(candidate: str, api: str) -> bool:
    candidate = normalize_api(candidate)
    api = normalize_api(api)
    if not candidate or not api:
        return False
    c_parts = candidate.split(maxsplit=1)
    a_parts = api.split(maxsplit=1)
    if len(c_parts) == 2 and len(a_parts) == 2 and c_parts[0] != a_parts[0]:
        return False
    c_path = c_parts[-1].rstrip("/")
    a_path = a_parts[-1].rstrip("/")
    generalized = re.sub(r"\{[^/]+\}", "{}", a_path)
    candidate_generalized = re.sub(r"/\d+|/[A-Fa-f0-9-]{8,}", "/{}", c_path)
    return c_path == a_path or candidate_generalized == generalized or c_path.endswith(a_path) or a_path.endswith(c_path)


def related_apis(scenario: dict[str, Any]) -> list[str]:
    apis = []
    for angle in scenario.get("scenario_angles", []) or []:
        if not isinstance(angle, dict):
            continue
        for api in angle.get("related_apis", []) or []:
            api = normalize_api(str(api))
            if api:
                apis.append(api)
    sequence_risk = scenario.get("sequence_order_risk", {})
    if isinstance(sequence_risk, dict):
        for api in sequence_risk.get("related_apis", []) or []:
            api = normalize_api(str(api))
            if api:
                apis.append(api)
    return sorted(set(apis))


def scenario_text(scenario: dict[str, Any]) -> str:
    parts = []
    for key in (
        "scenario_title",
        "risk_level",
        "risk_type",
        "overall_reason",
        "security_type",
        "target_asset",
        "business_security_boundary",
        "risk_direction",
        "why_reasonable_in_this_cluster",
        "possible_attack_path",
        "later_check_hint",
        "later_rule_generation_hint",
    ):
        if scenario.get(key):
            parts.append(str(scenario[key]))
    for block_name in ("sequence_order_risk", "parameter_consistency_risk"):
        block = scenario.get(block_name, {})
        if isinstance(block, dict):
            for value in block.values():
                if isinstance(value, list):
                    parts.extend(str(item) for item in value)
                elif value:
                    parts.append(str(value))
    for angle in scenario.get("scenario_angles", []) or []:
        if not isinstance(angle, dict):
            continue
        for value in angle.values():
            if isinstance(value, list):
                parts.extend(str(item) for item in value)
            elif value:
                parts.append(str(value))
    return "\n".join(parts)


def openapi_context_for(apis: list[str], index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for api in apis:
        matches = [item for key, item in index.items() if api_matches(api, key)]
        output.extend(matches[:2] or [{"api": api, "parameters": [], "object_parameters": [], "sensitive_fields": [], "auth_fields": []}])
    unique = {}
    for item in output:
        unique[item["api"]] = {
            "api": item["api"],
            "summary": item.get("summary", ""),
            "parameters": item.get("parameters", [])[:20],
            "object_parameters": item.get("object_parameters", []),
            "sensitive_fields": item.get("sensitive_fields", []),
            "auth_fields": item.get("auth_fields", []),
        }
    return list(unique.values())


def infer_entities(scenario: dict[str, Any], security_type: str, context: list[dict[str, Any]]) -> list[dict[str, str]]:
    text = scenario_text(scenario)
    entities = [
        {"symbol": "s", "type": "Session", "description": "当前业务会话"},
        {"symbol": "r", "type": "Request", "description": "触发安全场景的请求"},
        {"symbol": "u", "type": "User", "description": "当前登录用户或匿名主体"},
        {"symbol": "api", "type": "Api", "description": "被调用接口"},
    ]
    target = str(scenario.get("target_asset", "")).strip()
    object_params = sorted({p["name"] for item in context for p in item.get("object_parameters", [])})
    sensitive_fields = sorted({p["name"] for item in context for p in item.get("sensitive_fields", [])})
    if security_type == "BOLA":
        if re.search(r"(search|list|搜索|列表|返回)", text, re.I):
            entities.append({"symbol": "o", "type": "ResultObject", "description": f"搜索/列表响应返回的对象；目标资产={target or '未明确'}"})
        else:
            entities.append({"symbol": "o", "type": "BusinessObject", "description": f"被访问的业务对象；候选参数={', '.join(object_params) or target or '未明确'}"})
    elif security_type == "BFLA":
        entities.append({"symbol": "op", "type": "PrivilegedOperation", "description": f"高权限功能或动作；目标={target or '未明确'}"})
    elif security_type == "BOPLA":
        entities.append({"symbol": "f", "type": "SensitiveField", "description": f"敏感字段；候选字段={', '.join(sensitive_fields) or target or '未明确'}"})
    elif security_type == "AUTH_BYPASS":
        entities.append({"symbol": "a", "type": "AuthState", "description": "认证或会话状态"})
    elif security_type == "RESOURCE_CONSUMPTION":
        entities.extend(
            [
                {"symbol": "w", "type": "TimeWindow", "description": "统计时间窗口"},
                {"symbol": "n", "type": "Count", "description": "窗口内调用次数"},
            ]
        )
    return entities


def missing_requirements(scenario: dict[str, Any], security_type: str, apis: list[str], context: list[dict[str, Any]]) -> list[str]:
    missing = []
    if not apis:
        missing.append("related_apis")
    if not str(scenario.get("scenario_title", "")).strip():
        missing.append("scenario_title")
    if not str(scenario.get("overall_reason", "")).strip():
        missing.append("overall_reason")
    return missing


def fol_string(value: str) -> str:
    text = str(value or "").strip()
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def scenario_related_objects(scenario: dict[str, Any]) -> list[str]:
    values = []
    for angle in scenario.get("scenario_angles", []) or []:
        if not isinstance(angle, dict):
            continue
        for item in angle.get("related_parameters_or_objects", []) or []:
            text = str(item or "").strip()
            if text:
                values.append(text)
    return sorted(set(values))


def api_score_tokens(text: str) -> set[str]:
    tokens = set()
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_/-]{2,}", text):
        cleaned = token.strip("/").lower()
        if cleaned and cleaned not in {"get", "post", "put", "patch", "delete", "api", "jira", "rest"}:
            tokens.add(cleaned)
            for part in re.split(r"[/_-]+", cleaned):
                if len(part) >= 3:
                    tokens.add(part)
    for token in re.findall(r"[\u4e00-\u9fff]{2,}", text):
        tokens.add(token)
    return tokens


def select_risk_api_context(scenario: dict[str, Any], security_type: str, context: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not context:
        return None
    text = scenario_text(scenario)
    tokens = api_score_tokens(text)
    best: tuple[int, int, dict[str, Any] | None] = (-1, -1, None)
    for index, item in enumerate(context):
        api = str(item.get("api", ""))
        api_text = " ".join(
            [
                api,
                str(item.get("summary", "")),
                str(item.get("operation_id", "")),
                " ".join(str(p.get("name", "")) for p in item.get("parameters", [])),
            ]
        )
        api_lower = api_text.lower()
        score = 0
        for token in tokens:
            token_lower = token.lower()
            if token_lower in api_lower:
                score += 3 if "/" in token_lower else 1
        if security_type == "BOLA" and item.get("object_parameters"):
            score += 4
        if security_type == "BFLA" and ADMIN_RE.search(api_text):
            score += 5
        if security_type == "BOPLA" and item.get("sensitive_fields"):
            score += 5
        if security_type == "AUTH_BYPASS" and AUTH_RE.search(api_text):
            score += 5
        if security_type == "RESOURCE_CONSUMPTION" and FREQ_RE.search(api_text):
            score += 4
        if re.search(r"(attack|攻击|漏洞|枚举|篡改|绕过|越权|高危|直接调用)", text, re.I) and any(
            part in api_lower for part in ("leader", "admin", "delete", "permission", "config", "token", "search", "export")
        ):
            score += 2
        tie_breaker = len(item.get("parameters", []))
        if score > best[0] or (score == best[0] and tie_breaker > best[1]):
            best = (score, tie_breaker, item)
    return best[2]


def first_matching_name(names: list[str], pattern: re.Pattern[str]) -> str:
    for name in names:
        if pattern.search(name):
            return name
    return names[0] if names else ""


def api_path_parameters(api: str) -> list[str]:
    return [name.strip() for name in re.findall(r"\{([^}/]+)\}", str(api or "")) if name.strip()]


def formula_constants(scenario: dict[str, Any], security_type: str, context: list[dict[str, Any]]) -> dict[str, str]:
    selected = select_risk_api_context(scenario, security_type, context) or {}
    target_asset = str(scenario.get("target_asset") or scenario.get("scenario_title") or "").strip()
    boundary = str(scenario.get("business_security_boundary") or scenario.get("risk_type") or "sequence_or_parameter_risk").strip()
    attack_path = str(scenario.get("possible_attack_path") or scenario.get("overall_reason") or scenario.get("later_check_hint") or "").strip()
    selected_api = str(selected.get("api", "")).strip()
    selected_object_params = api_path_parameters(selected_api) + [str(p["name"]) for p in selected.get("object_parameters", []) if p.get("name")]
    selected_fields = [str(p["name"]) for p in selected.get("sensitive_fields", []) if p.get("name")]
    selected_auth_fields = [str(p["name"]) for p in selected.get("auth_fields", []) if p.get("name")]
    related_objects = scenario_related_objects(scenario)
    related_object_ids = [item for item in related_objects if OBJECT_RE.search(item)]
    related_fields = [item for item in related_objects if FIELD_RE.search(item)]
    return {
        "api": selected_api,
        "target_asset": target_asset,
        "boundary": boundary,
        "attack_path": attack_path,
        "risk_level": str(scenario.get("risk_level") or "medium").strip(),
        "risk_type": str(scenario.get("risk_type") or "both").strip(),
        "object_field": first_matching_name(selected_object_params, OBJECT_RE) or first_matching_name(related_object_ids, OBJECT_RE),
        "sensitive_field": first_matching_name(selected_fields, FIELD_RE) or first_matching_name(related_fields, FIELD_RE),
        "auth_field": first_matching_name(selected_auth_fields, AUTH_RE) or ("authenticated_session" if AUTH_RE.search(scenario_text(scenario)) else ""),
    }


def binding_missing_requirements(
    security_type: str,
    bindings: dict[str, str],
    entities: list[dict[str, str]],
    activity_model: dict[str, Any],
    scenario: dict[str, Any],
) -> list[str]:
    missing = []
    for key in ("risk_level", "risk_type"):
        if not bindings.get(key):
            missing.append(key)
    risk_type = str(bindings.get("risk_type") or scenario.get("risk_type") or "both").lower()
    if risk_type in {"sequence_order", "both"} and not activity_model.get("activities"):
        missing.append("activity_abstraction")
    return missing


def formula_binding_view(security_type: str, bindings: dict[str, str]) -> dict[str, str]:
    keys = ["api", "target_asset", "risk_level", "risk_type", "attack_path", "object_field", "sensitive_field", "auth_field"]
    return {key: bindings[key] for key in keys if bindings.get(key)}


def has_project_boundary_model(boundary_model: dict[str, Any]) -> bool:
    return bool(boundary_model.get("available") and boundary_model.get("project_contains_issues") and boundary_model.get("actor_accessible_projects"))


def activity_label(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    return text if text else fallback


def label_mentions_api(text: str, label: str) -> bool:
    text = str(text or "")
    label = str(label or "")
    if not text or not label:
        return False
    if label in text:
        return True
    parts = label.split(maxsplit=1)
    if len(parts) == 2 and parts[1] in text:
        return True
    return False


def build_activity_abstraction(scenario: dict[str, Any]) -> dict[str, Any]:
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    normal_labels = sequence_block.get("normal_sequence_pattern", [])
    risky_labels = sequence_block.get("possible_violation_sequence_pattern", sequence_block.get("risky_sequence_pattern", []))
    if not isinstance(normal_labels, list):
        normal_labels = []
    if not isinstance(risky_labels, list):
        risky_labels = []
    normal_labels = [activity_label(item, f"normal_step_{index}") for index, item in enumerate(normal_labels, start=1)]
    risky_labels = [activity_label(item, f"violation_step_{index}") for index, item in enumerate(risky_labels, start=1)]
    missing_label = activity_label(sequence_block.get("missing_or_reordered_step", ""), "")

    labels: list[str] = []
    for label in normal_labels + risky_labels:
        if label and label not in labels:
            labels.append(label)
    symbols = {label: f"A{index}" for index, label in enumerate(labels, start=1)}
    normal_chain = [symbols[label] for label in normal_labels if label in symbols]
    risky_chain = [symbols[label] for label in risky_labels if label in symbols]
    missing_symbol = ""
    if missing_label and missing_label != "无法确定":
        for label in normal_labels:
            if label_mentions_api(missing_label, label):
                missing_symbol = symbols.get(label, "")
                break
    if not missing_symbol:
        for label in normal_labels:
            if label not in risky_labels:
                missing_symbol = symbols.get(label, "")
                missing_label = label
                break
    risk_target = risky_chain[0] if missing_symbol and risky_chain else (risky_chain[-1] if risky_chain else (normal_chain[-1] if normal_chain else "A_risk"))
    return {
        "activities": [{"symbol": symbol, "label": label} for label, symbol in symbols.items()],
        "normal_chain": normal_chain,
        "risky_chain": risky_chain,
        "possible_violation_chain": risky_chain,
        "missing_or_reordered_activity": missing_symbol,
        "missing_or_reordered_label": missing_label,
        "violated_order_constraint": sequence_block.get("violated_order_constraint", ""),
        "risk_target_activity": risk_target,
        "related_apis": sequence_block.get("related_apis", []) if isinstance(sequence_block.get("related_apis", []), list) else [],
    }


def order_pairs(chain: list[str]) -> list[tuple[str, str]]:
    return [(chain[index], chain[index + 1]) for index in range(len(chain) - 1)]


def sequence_formula_clause(activity_model: dict[str, Any]) -> str:
    normal_chain = activity_model.get("normal_chain", [])
    risky_chain = activity_model.get("possible_violation_chain", activity_model.get("risky_chain", []))
    missing = activity_model.get("missing_or_reordered_activity", "")
    target = activity_model.get("risk_target_activity", "A_risk")
    if risky_chain:
        counts = Counter(risky_chain)
        repeated = [(symbol, count) for symbol, count in counts.items() if count >= 2]
        if repeated:
            symbol, count = sorted(repeated, key=lambda item: item[1], reverse=True)[0]
            return f'CountInSession(s,{symbol}) ≥ {count}'
    if missing:
        return f'Occurs(s,{target}) ∧ RequiredBefore({missing},{target}) ∧ ¬Before(s,{missing},{target})'
    pairs = order_pairs(risky_chain or normal_chain)
    if pairs:
        pair = pairs[-1]
        return f'Occurs(s,{pair[0]}) ∧ Occurs(s,{pair[1]}) ∧ RiskyAdjacentOrder(s,{pair[0]},{pair[1]})'
    return f'Occurs(s,{target}) ∧ SequenceOrderUncertain(s,{target})'


def activity_label_by_symbol(activity_model: dict[str, Any], symbol: str) -> str:
    for item in activity_model.get("activities", []) or []:
        if item.get("symbol") == symbol:
            return str(item.get("label", ""))
    return ""


def sequence_expression_scope(activity_model: dict[str, Any]) -> dict[str, str]:
    risky_chain = activity_model.get("possible_violation_chain", activity_model.get("risky_chain", []))
    if risky_chain:
        counts = Counter(risky_chain)
        repeated = [(symbol, count) for symbol, count in counts.items() if count >= 2]
        if repeated:
            symbol, count = sorted(repeated, key=lambda item: item[1], reverse=True)[0]
            return {
                "mode": "repeated_call",
                "activity": symbol,
                "activity_label": activity_label_by_symbol(activity_model, symbol),
                "threshold": str(count),
            }
    missing = activity_model.get("missing_or_reordered_activity", "")
    target = activity_model.get("risk_target_activity", "")
    if missing:
        return {
            "mode": "missing_or_reordered_step",
            "required_activity": missing,
            "required_activity_label": activity_label_by_symbol(activity_model, missing),
            "target_activity": target,
            "target_activity_label": activity_label_by_symbol(activity_model, target),
        }
    return {
        "mode": "risky_order",
        "target_activity": target,
        "target_activity_label": activity_label_by_symbol(activity_model, target),
    }


def should_combine_sequence_and_parameter(scenario: dict[str, Any]) -> bool:
    text_parts = []
    for key in ("risk_type", "overall_reason", "later_check_hint"):
        if scenario.get(key):
            text_parts.append(str(scenario.get(key)))
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    for block in (sequence_block, parameter_block):
        for value in block.values():
            if isinstance(value, list):
                text_parts.extend(str(item) for item in value)
            elif value:
                text_parts.append(str(value))
    text = "\n".join(text_parts).lower()
    if "both" in text or "两者" in text or "同时" in text:
        return True
    return bool(
        re.search(
            r"(参数|id|key|project|issue|user|object|对象).{0,20}(前置|上下文|来源|继承|来自|绑定|跳过|缺失)"
            r"|(?:前置|上下文|来源|继承|来自|绑定|跳过|缺失).{0,20}(参数|id|key|project|issue|user|object|对象)",
            text,
            re.I,
        )
    )


def has_real_parameter_risk(parameter_block: dict[str, Any]) -> bool:
    key_params = parameter_block.get("key_parameters_or_objects", [])
    if not isinstance(key_params, list):
        key_params = [key_params] if key_params else []
    key_params = [str(item).strip() for item in key_params if str(item).strip()]
    reason = str(parameter_block.get("risky_parameter_form") or "").strip()
    if not key_params and not reason:
        return False
    no_risk_patterns = (
        "无明显参数风险",
        "无参数风险",
        "无明显",
        "无",
        "none",
        "no obvious",
        "not applicable",
    )
    if not key_params and any(pattern.lower() in reason.lower() for pattern in no_risk_patterns):
        return False
    if key_params and all(item.lower() in {"无", "none", "n/a", "na"} for item in key_params):
        return False
    return True


def formula_for(
    scenario: dict[str, Any],
    security_type: str,
    entities: list[dict[str, str]],
    bindings: dict[str, str],
    boundary_model: dict[str, Any],
) -> tuple[list[dict[str, str]], str, list[str]]:
    title = str(scenario.get("scenario_title", "安全场景"))
    title_const = fol_string(title)
    risk_level = fol_string(bindings.get("risk_level", "medium"))
    category = fol_string(security_type)
    activity_model = build_activity_abstraction(scenario)
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    key_params = parameter_block.get("key_parameters_or_objects", [])
    key_param_text = fol_string(",".join(str(item) for item in key_params) if isinstance(key_params, list) else str(key_params or ""))
    has_parameter_risk = has_real_parameter_risk(parameter_block)
    has_sequence_risk = bool(activity_model.get("activities"))

    sequence_clause = sequence_formula_clause(activity_model)
    parameter_clause = f'ViolatesParameterConsistency(s,{key_param_text},{category})'
    expressions = []
    combine = has_sequence_risk and has_parameter_risk and should_combine_sequence_and_parameter(scenario)
    if combine:
        expressions.append(
            {
                "dimension": "sequence_order_and_parameter_consistency",
                "scope": {
                    "sequence": sequence_expression_scope(activity_model),
                    "parameters": key_params if isinstance(key_params, list) else [str(key_params)],
                },
                "formula": f'∀s (({sequence_clause} ∧ {parameter_clause}) → RatedCombinedSequenceParameterRisk(s,{category},{risk_level},{title_const}))',
                "meaning": "当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，产生组合风险评级。",
            }
        )
    elif has_sequence_risk:
        expressions.append(
            {
                "dimension": "sequence_order",
                "scope": sequence_expression_scope(activity_model),
                "formula": f'∀s ({sequence_clause} → RatedSequenceOrderRisk(s,{category},{risk_level},{title_const}))',
                "meaning": "如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，则产生序列顺序风险评级。",
            }
        )
    if has_parameter_risk and not combine:
        expressions.append(
            {
                "dimension": "parameter_consistency",
                "scope": {
                    "parameters": key_params if isinstance(key_params, list) else [str(key_params)],
                    "risk_form": parameter_block.get("risky_parameter_form", ""),
                },
                "formula": f'∀s ({parameter_clause} → RatedParameterRisk(s,{category},{risk_level},{title_const}))',
                "meaning": "如果会话中的关键对象参数存在中途替换、来源不明或组合不一致，则产生参数一致性风险评级。",
            }
        )
    predicates = [
        "Occurs(s,A)",
        "Before(s,A_before,A_after)",
        "RequiredBefore(A_required,A_target)",
        "RiskyAdjacentOrder(s,A_before,A_after)",
        "CountInSession(s,A)",
        "ViolatesParameterConsistency(s,key_parameters,security_category)",
        "RatedSequenceOrderRisk(s,security_category,risk_level,title)",
        "RatedParameterRisk(s,security_category,risk_level,title)",
        "RatedCombinedSequenceParameterRisk(s,security_category,risk_level,title)",
    ]
    plain = "表达式会按场景选择生成方式：如果参数风险依赖前置上下文或顺序链，则合并成一个组合表达式；如果两类风险相对独立，则拆成顺序表达式和参数表达式。"
    return expressions, plain, predicates


def evidence_mapping(security_type: str, scenario: dict[str, Any], context: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"predicate": "InSession(s,r)", "source": "原始 session 序列", "field_hint": "session_id 与步骤号"},
        {"predicate": "Calls(r,api)", "source": "原始请求日志", "field_hint": "HTTP method + path"},
        {"predicate": "ViolatesSequenceOrder", "source": "聚类代表序列 + 成员序列", "field_hint": "前置步骤、后置接口、敏感动作顺序、重复调用"},
        {"predicate": "ViolatesParameterConsistency", "source": "OpenAPI 参数文档 + 原始请求参数", "field_hint": "issueId/projectId/userId/avatarId 等关键对象参数是否中途替换或来源不明"},
        {"predicate": "RatedSequenceRisk", "source": "LLM 风险评级结果", "field_hint": "security_type、risk_type、risk_level、risk_score"},
    ]


def object_hint(context: list[dict[str, Any]]) -> str:
    names = sorted({p["name"] for item in context for p in item.get("object_parameters", [])})
    if names:
        return ", ".join(names)
    return "如果是搜索/列表接口，需要从响应结果中提取对象 ID/key，例如 issueKey/contentId/spaceKey/commentId"


def field_hint(context: list[dict[str, Any]]) -> str:
    names = sorted({p["name"] for item in context for p in item.get("sensitive_fields", [])})
    return ", ".join(names) if names else "reporter/assignee/status/resolution/security/visibility/sprint 等敏感字段"


def boundary_model_summary(boundary_model: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": "sequence_risk_rating",
        "project_boundary_available": bool(boundary_model.get("available")),
        "note": "项目权限表可作为参数一致性风险的辅助依据，但当前公式只输出序列顺序风险与参数合理性风险评级。",
    }


def compact_openapi_context(context: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for item in context[:5]:
        params = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        output.append(
            {
                "api": item.get("api", ""),
                "params": [str(p.get("name", "")) for p in params[:12] if isinstance(p, dict) and p.get("name")],
                "object_params": [str(p.get("name", "")) for p in item.get("object_parameters", [])[:8] if isinstance(p, dict) and p.get("name")],
                "sensitive_fields": [str(p.get("name", "")) for p in item.get("sensitive_fields", [])[:8] if isinstance(p, dict) and p.get("name")],
            }
        )
    return output


def compact_scenario_summary(scenario: dict[str, Any], security_type: str) -> dict[str, Any]:
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    return {
        "security_type": security_type,
        "risk_level": scenario.get("risk_level", ""),
        "risk_score": scenario.get("risk_score", ""),
        "risk_type": scenario.get("risk_type", ""),
        "normal_sequence": sequence_block.get("normal_sequence_pattern", []),
        "possible_violation_sequence": sequence_block.get(
            "possible_violation_sequence_pattern",
            sequence_block.get("risky_sequence_pattern", []),
        ),
        "violated_order_constraint": sequence_block.get("violated_order_constraint", ""),
        "parameter_objects": parameter_block.get("key_parameters_or_objects", []),
        "parameter_risk": parameter_block.get("risky_parameter_form", ""),
        "overall_reason": scenario.get("overall_reason", ""),
    }


def generate_expression(
    review: dict[str, Any],
    scenario: dict[str, Any],
    scenario_index: int,
    openapi_index: dict[str, dict[str, Any]],
    boundary_model: dict[str, Any],
) -> dict[str, Any]:
    raw_type = str(scenario.get("security_type") or "OTHER")
    security_type = normalize_security_type(raw_type)
    apis = related_apis(scenario)
    context = openapi_context_for(apis, openapi_index)
    missing = missing_requirements(scenario, security_type, apis, context)
    cluster_index = review.get("cluster_index")
    scenario_id = scenario.get("scenario_id") or f"C{cluster_index}-S{scenario_index}"

    source = {
        "cluster_index": cluster_index,
        "scenario_id": scenario_id,
        "business_pattern_name": review.get("business_pattern_name", ""),
        "scenario_title": scenario.get("scenario_title", ""),
        "security_type": security_type,
        "raw_security_type": raw_type,
        "trust_score": review.get("trust_score"),
    }
    if missing:
        return {
            "fol_id": f"FOL-{scenario_id}",
            "status": "skipped",
            "source": source,
            "skip_reason": "当前场景缺少足够具体的业务实体、关系或证据；不生成通用模板。",
            "missing_requirements": missing,
            "related_apis": apis,
            "openapi_summary": compact_openapi_context(context),
        }

    entities = infer_entities(scenario, security_type, context)
    bindings = formula_constants(scenario, security_type, context)
    activity_model = build_activity_abstraction(scenario)
    binding_missing = binding_missing_requirements(security_type, bindings, entities, activity_model, scenario)
    if binding_missing:
        return {
            "fol_id": f"FOL-{scenario_id}",
            "status": "skipped",
            "source": source,
            "skip_reason": "当前场景缺少可抽象的序列步骤或基础风险字段；不生成带占位符的公式。",
            "missing_requirements": binding_missing,
            "related_apis": apis,
            "formula_bindings": formula_binding_view(security_type, bindings),
            "activity_abstraction": activity_model,
            "openapi_summary": compact_openapi_context(context),
        }

    logic_expressions, plain, predicates = formula_for(scenario, security_type, entities, bindings, boundary_model)
    return {
        "fol_id": f"FOL-{scenario_id}",
        "status": "generated",
        "source": source,
        "scenario_summary": compact_scenario_summary(scenario, security_type),
        "predicates": predicates,
        "activity_abstraction": activity_model,
        "openapi_summary": compact_openapi_context(context),
        "logic_expression_count": len(logic_expressions),
        "logic_expressions": logic_expressions,
        "plain_language": plain,
        "generation_note": "默认输出已压缩；顺序风险和参数风险会按场景关系选择合并或拆分。",
    }


def iter_scenarios(review_payload: dict[str, Any], include_low_trust: bool):
    for review in review_payload.get("reviews", []) or []:
        if not isinstance(review, dict):
            continue
        if not include_low_trust and not review.get("is_trustworthy"):
            continue
        for index, scenario in enumerate(review.get("possible_security_scenarios", []) or [], start=1):
            if isinstance(scenario, dict):
                yield review, scenario, index


def predicate_library() -> list[dict[str, str]]:
    return [
        {"predicate": "Occurs(s,A)", "description": "活动 A 出现在会话 s 中"},
        {"predicate": "Before(s,A_before,A_after)", "description": "在会话 s 中，活动 A_before 早于 A_after"},
        {"predicate": "RequiredBefore(A_required,A_target)", "description": "正常业务中 A_required 通常应出现在 A_target 之前"},
        {"predicate": "RiskyAdjacentOrder(s,A_before,A_after)", "description": "会话 s 中出现可疑的相邻活动顺序"},
        {"predicate": "CountInSession(s,A)", "description": "活动 A 在会话 s 中出现的次数"},
        {"predicate": "ViolatesParameterConsistency(s,key_parameters,security_category)", "description": "关键对象参数存在中途替换、来源不明或组合不一致"},
        {"predicate": "RatedSequenceOrderRisk(s,security_category,risk_level,title)", "description": "序列顺序风险评级结果"},
        {"predicate": "RatedParameterRisk(s,security_category,risk_level,title)", "description": "参数一致性风险评级结果"},
        {"predicate": "RatedCombinedSequenceParameterRisk(s,security_category,risk_level,title)", "description": "序列顺序和参数一致性共同成立时的组合风险评级结果"},
    ]


def format_list(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "无"
    return " -> ".join(str(item) for item in items)


def activity_map_text(expression: dict[str, Any]) -> list[str]:
    activity = expression.get("activity_abstraction", {})
    activities = activity.get("activities", []) if isinstance(activity, dict) else []
    lines = []
    for item in activities:
        if not isinstance(item, dict):
            continue
        symbol = item.get("symbol", "")
        label = item.get("label", "")
        if symbol and label:
            lines.append(f"- {symbol}: {label}")
    return lines


def build_logic_markdown(site_id: str, expressions: list[dict[str, Any]]) -> str:
    lines = [
        f"# Site {site_id} 一阶逻辑表达式汇总",
        "",
        "## 生成模板说明",
        "",
        "- 顺序跳步/越序模板：`RequiredBefore(A_required,A_target) ∧ ¬Before(s,A_required,A_target)`",
        "- 重复调用模板：`CountInSession(s,A) ≥ n`",
        "- 参数一致性模板：`ViolatesParameterConsistency(s,key_parameters,security_category)`",
        "- 组合风险模板：`SequenceRisk(s) ∧ ParameterRisk(s)`",
        "",
    ]
    generated = [item for item in expressions if item.get("status") == "generated"]
    for index, item in enumerate(generated, start=1):
        source = item.get("source", {})
        summary = item.get("scenario_summary", {})
        logic_items = item.get("logic_expressions", []) or []
        lines.extend(
            [
                f"## {index}. {source.get('scenario_title') or item.get('fol_id')}",
                "",
                f"- FOL ID: `{item.get('fol_id', '')}`",
                f"- 场景: {source.get('business_pattern_name', '')}",
                f"- 类型: `{summary.get('security_type', source.get('security_type', ''))}` / 风险等级: `{summary.get('risk_level', '')}`",
                f"- 攻击场景概述: {summary.get('overall_reason', '')}",
                f"- 正常链路: {format_list(summary.get('normal_sequence'))}",
                f"- 可能违规链路: {format_list(summary.get('possible_violation_sequence'))}",
                f"- 参数风险: {summary.get('parameter_risk') or '无'}",
                "",
                "活动映射:",
            ]
        )
        activity_lines = activity_map_text(item)
        lines.extend(activity_lines or ["- 无"])
        lines.extend(["", "一阶逻辑表达式:"])
        if not logic_items:
            lines.append("- 无")
        for expr_index, expr in enumerate(logic_items, start=1):
            lines.extend(
                [
                    f"- 表达式 {expr_index} `{expr.get('dimension', '')}`:",
                    "",
                    "```text",
                    str(expr.get("formula", "")),
                    "```",
                    f"  说明: {expr.get('meaning', '')}",
                    "",
                ]
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    review_file = Path(args.review_file) if args.review_file else base_dir / "process_mining" / "llm_cluster_reviews" / f"site_{args.site_id}_cluster_review.json"
    openapi_file = Path(args.openapi_file) if args.openapi_file else base_dir / "API document" / f"site_{args.site_id}_openapi.json"
    boundary_file = Path(args.boundary_file) if args.boundary_file else base_dir / "object_boundary_mining" / f"site_{args.site_id}_project_issue_access.json"
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "fol_expressions"

    reviews = read_json(review_file)
    openapi_doc = read_json(openapi_file)
    openapi_index = build_openapi_index(openapi_doc)
    boundary_model = load_project_boundary(boundary_file)
    expressions = [
        generate_expression(review, scenario, index, openapi_index, boundary_model)
        for review, scenario, index in iter_scenarios(reviews, args.include_low_trust)
    ]
    generated = sum(1 for item in expressions if item.get("status") == "generated")
    skipped = sum(1 for item in expressions if item.get("status") == "skipped")
    payload = {
        "site_id": args.site_id,
        "review_file": str(review_file),
        "openapi_file": str(openapi_file),
        "boundary_file": str(boundary_file) if boundary_file.exists() else "",
        "authorization_context": boundary_model_summary(boundary_model),
        "expression_count": len(expressions),
        "generated_expression_count": generated,
        "skipped_expression_count": skipped,
        "predicate_library": predicate_library(),
        "expressions": expressions,
    }
    output_path = output_dir / f"site_{args.site_id}_fol_expressions.json"
    logic_markdown_path = output_dir / f"site_{args.site_id}_fol_logic_expressions.md"
    write_json(output_path, payload)
    write_text(logic_markdown_path, build_logic_markdown(args.site_id, expressions))
    print(
        f"site={args.site_id} expressions={len(expressions)} generated={generated} skipped={skipped} "
        f"output={output_path} logic_md={logic_markdown_path}"
    )


if __name__ == "__main__":
    main()
