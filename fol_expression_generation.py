# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_BASE_DIR = str(Path(__file__).resolve().parent / "artifacts" / "train")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

OBJECT_RE = re.compile(r"(issue|project|space|content|page|comment|worklog|attachment|board|sprint|filter|dashboard|avatar|user|group|id|key)", re.I)
FIELD_RE = re.compile(r"(reporter|creator|author|assignee|owner|status|resolution|security|visibility|role|permission|sprint|version|duedate|project|issuetype|transition)", re.I)
AUTH_RE = re.compile(r"(login|auth|session|cookie|token|xsrf|csrf|secure)", re.I)
ADMIN_RE = re.compile(r"(admin|permission|role|config|workflow|scheme|manage|delete|project.?role)", re.I)
FREQ_RE = re.compile(r"(search|upload|download|export|avatar|attachment|jql|cql|poll|notification|gadget|autocomplete)", re.I)
BENIGN_POLLING_RE = re.compile(
    r"(/notification/count|/quickreload/|/status/|/heartbeat|/ping|/health|/keepalive|/poll|/longpoll|"
    r"/events|/activity|/presence|/unread|/badge|/counter|/count(?:$|[/?#]))",
    re.I,
)
RESOURCE_IMPACT_RE = re.compile(r"(耗尽|打满|过载|异常高频|短时间|大量|洪泛|拒绝服务|dos|ddos|burst|flood|exhaust|overload|rate.?limit)", re.I)
STATUS_TOKEN_RE = re.compile(
    r"(?<!\d)(2xx|3xx|4xx|5xx|200|201|202|204|301|302|304|400|401|403|404|409|429|500|502|503|504)(?!\d)",
    re.I,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate scenario-bound first-order logic drafts.")
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--review-file", default="", help="Default: <base-dir>/process_mining/llm_cluster_reviews/site_<site_id>_cluster_review.json")
    parser.add_argument("--openapi-file", default="", help="Default: <base-dir>/API_document/site_<site_id>_openapi.json")
    parser.add_argument("--parameter-profile-file", default="", help="Default: <base-dir>/parameter_profiles/site_<site_id>_parameter_profile.json")
    parser.add_argument("--boundary-file", default="", help="Default: <base-dir>/object_boundary_mining/site_<site_id>_project_issue_access.json")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/fol_expressions")
    parser.add_argument("--include-low-trust", action="store_true")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(
            f"Required JSON file not found: {path}. "
            "Use --base-dir artifacts\\train or pass the explicit file path."
        )
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


def profile_param_records(params: Any, location: str) -> list[dict[str, Any]]:
    if not isinstance(params, dict):
        return []
    records = []
    for name, item in params.items():
        if not isinstance(item, dict):
            continue
        records.append(
            {
                "name": str(name),
                "in": location,
                "required": float(item.get("required_ratio", 0) or 0) >= 0.95,
                "type": (item.get("types", ["unknown"])[0] if isinstance(item.get("types"), list) and item.get("types") else "unknown"),
                "required_ratio": item.get("required_ratio", 0),
                "examples": item.get("examples", [])[:3] if isinstance(item.get("examples"), list) else [],
                "source": "parameter_profile",
            }
        )
    return records


def method_section_params(method_item: dict[str, Any], section: str) -> dict[str, Any]:
    value = method_item.get(section, {})
    if isinstance(value, dict) and isinstance(value.get("params"), dict):
        return value["params"]
    return {}


def build_parameter_profile_index(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    paths = doc.get("paths", []) if isinstance(doc, dict) else []
    if not isinstance(paths, list):
        return index
    for path_item in paths:
        if not isinstance(path_item, dict):
            continue
        path = str(path_item.get("openapi_path") or path_item.get("path") or "").strip()
        methods = path_item.get("methods", {})
        if not path or not isinstance(methods, dict):
            continue
        for method, method_item in methods.items():
            if not isinstance(method_item, dict):
                continue
            method_upper = str(method).upper()
            api = f"{method_upper} {path}"
            params: list[dict[str, Any]] = []
            params.extend(profile_param_records(method_section_params(method_item, "path"), "path"))
            params.extend(profile_param_records(method_section_params(method_item, "query"), "query"))
            params.extend(profile_param_records(method_section_params(method_item, "body"), "body"))
            params.extend(profile_param_records(method_section_params(method_item, "header"), "header"))
            index[api] = {
                "api": api,
                "summary": f"{method_upper} {path}",
                "operation_id": "",
                "parameters": params,
                "object_parameters": [p for p in params if OBJECT_RE.search(str(p.get("name", "")))],
                "sensitive_fields": [p for p in params if FIELD_RE.search(str(p.get("name", "")))],
                "auth_fields": [p for p in params if AUTH_RE.search(str(p.get("name", "")))],
                "source": "parameter_profile",
                "request_count": method_item.get("request_count", 0),
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
    def generalize(path: str) -> str:
        path = re.sub(r"\{[^/]+\}", "{}", path)
        path = re.sub(r"/(?:\d+|[A-Fa-f0-9-]{8,})(?=/|$)", "/{}", path)
        return path

    candidate_generalized = generalize(c_path)
    api_generalized = generalize(a_path)
    return c_path == a_path or candidate_generalized == api_generalized or c_path.endswith(a_path) or a_path.endswith(c_path)


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
        for key in ("normal_sequence_pattern", "possible_violation_sequence_pattern", "risky_sequence_pattern"):
            values = sequence_risk.get(key, [])
            if isinstance(values, list):
                for api in values:
                    api = normalize_api(str(api))
                    if re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", api, re.I):
                        apis.append(api)
    parameter_risk = scenario.get("parameter_consistency_risk", {})
    if isinstance(parameter_risk, dict):
        for key in ("target_apis", "context_apis", "normal_parameter_sequence"):
            values = parameter_risk.get(key, [])
            if isinstance(values, list):
                for api in values:
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


def is_benign_polling_resource_scenario(scenario: dict[str, Any], apis: list[str]) -> bool:
    if not apis:
        return False
    if not all(BENIGN_POLLING_RE.search(api) for api in apis):
        return False
    return not RESOURCE_IMPACT_RE.search(scenario_text(scenario))


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
        "sequence_subtype": str(sequence_block.get("sequence_subtype") or "").strip(),
        "authorization_precheck": sequence_block.get("authorization_precheck", {}) if isinstance(sequence_block.get("authorization_precheck"), dict) else {},
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


def is_authorization_precheck_scope(activity_model: dict[str, Any], security_type: str) -> bool:
    subtype = str(activity_model.get("sequence_subtype", "") or "").strip().lower()
    if subtype == "authorization_precheck":
        return True
    return str(security_type or "").strip().upper() == "AUTH_BYPASS"


def authorization_precheck_policy(activity_model: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    policy = activity_model.get("authorization_precheck", {})
    if not isinstance(policy, dict):
        policy = {}
    keywords = normalize_param_list(policy.get("required_response_keywords", [])) or [
        "token",
        "session",
        "permission",
        "permissions",
        "access",
        "allowed",
        "role",
        "roles",
    ]
    try:
        max_interval = int(str(policy.get("max_interval_seconds") or "300"))
    except ValueError:
        max_interval = 300
    output = {
        "precheck_required": bool(policy.get("precheck_required", True)),
        "required_response_keywords": keywords,
        "max_interval_seconds": max_interval,
        "browser_context_required": bool(policy.get("browser_context_required", False)),
    }
    if "required_activity" in scope:
        output["precheck_activity"] = scope.get("required_activity", "")
        output["precheck_activity_label"] = scope.get("required_activity_label", "")
    if "target_activity" in scope:
        output["target_activity"] = scope.get("target_activity", "")
        output["target_activity_label"] = scope.get("target_activity_label", "")
    return output


def sequence_expression_scope(activity_model: dict[str, Any], security_type: str = "") -> dict[str, Any]:
    risky_chain = activity_model.get("possible_violation_chain", activity_model.get("risky_chain", []))
    if risky_chain:
        counts = Counter(risky_chain)
        repeated = [(symbol, count) for symbol, count in counts.items() if count >= 2]
        if repeated:
            symbol, count = sorted(repeated, key=lambda item: item[1], reverse=True)[0]
            scope = {
                "mode": "repeated_call",
                "activity": symbol,
                "activity_label": activity_label_by_symbol(activity_model, symbol),
                "threshold": str(count),
            }
            if is_authorization_precheck_scope(activity_model, security_type):
                scope["sequence_subtype"] = "authorization_precheck"
                scope["authorization_precheck"] = authorization_precheck_policy(activity_model, scope)
            return scope
    missing = activity_model.get("missing_or_reordered_activity", "")
    target = activity_model.get("risk_target_activity", "")
    if missing:
        scope = {
            "mode": "missing_or_reordered_step",
            "required_activity": missing,
            "required_activity_label": activity_label_by_symbol(activity_model, missing),
            "target_activity": target,
            "target_activity_label": activity_label_by_symbol(activity_model, target),
        }
        if is_authorization_precheck_scope(activity_model, security_type):
            scope["sequence_subtype"] = "authorization_precheck"
            scope["authorization_precheck"] = authorization_precheck_policy(activity_model, scope)
        return scope
    scope = {
        "mode": "risky_order",
        "target_activity": target,
        "target_activity_label": activity_label_by_symbol(activity_model, target),
    }
    if is_authorization_precheck_scope(activity_model, security_type):
        scope["sequence_subtype"] = "authorization_precheck"
        scope["authorization_precheck"] = authorization_precheck_policy(activity_model, scope)
    return scope


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


def scenario_risk_type(scenario: dict[str, Any]) -> str:
    risk_type = str(scenario.get("risk_type") or "").strip().lower()
    return risk_type if risk_type in {"sequence_order", "parameter_consistency", "both"} else "both"


def has_sequence_risk_block(scenario: dict[str, Any]) -> bool:
    block = scenario.get("sequence_order_risk", {})
    if not isinstance(block, dict) or not block:
        return False
    normal = block.get("normal_sequence_pattern", [])
    risky = block.get("possible_violation_sequence_pattern", block.get("risky_sequence_pattern", []))
    if not isinstance(normal, list):
        normal = []
    if not isinstance(risky, list):
        risky = []
    return bool(normal or risky or str(block.get("missing_or_reordered_step", "")).strip())


def has_parameter_risk_block(scenario: dict[str, Any]) -> bool:
    block = scenario.get("parameter_consistency_risk", {})
    if not isinstance(block, dict) or not block:
        return False
    params = normalize_param_list(block.get("key_parameters_or_objects", []))
    risk_form = str(block.get("risky_parameter_form") or "").strip()
    target_apis = normalize_param_list(block.get("target_apis", []))
    context_apis = normalize_param_list(block.get("context_apis", []))
    return bool(params or risk_form or target_apis or context_apis)


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


def has_actionable_parameter_scope(p_scope: dict[str, Any]) -> bool:
    params = normalize_param_list(p_scope.get("parameters", []))
    target_apis = normalize_param_list(p_scope.get("target_api_scope", []))
    context_apis = normalize_param_list(p_scope.get("context_api_scope", []))
    dependency = str(p_scope.get("dependency_relation", "") or "").strip().lower()
    expected_source = str(p_scope.get("expected_source", "") or "").strip().lower()
    if not params or not target_apis:
        return False
    if dependency in {"", "unknown"} and expected_source in {"", "unknown"}:
        return False
    if dependency in {"derived_from_context_api", "bound_to_upstream_context"} and not context_apis:
        return False
    return True


def normalize_param_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value:
        return [str(value).strip()]
    return []


def normalize_record_list(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    records = []
    for item in value:
        if not isinstance(item, dict):
            continue
        record = {str(key): str(val).strip() for key, val in item.items() if str(val).strip()}
        if record:
            records.append(record)
    return records


def api_param_records_for_api(context: list[dict[str, Any]], api: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen = set()
    for item in context:
        item_api = str(item.get("api", "")).strip() if isinstance(item, dict) else ""
        if not item_api or not api_matches(item_api, api):
            continue
        for param in item.get("parameters", []) or []:
            if not isinstance(param, dict):
                continue
            name = str(param.get("name", "")).strip()
            if not name or name in seen:
                continue
            seen.add(name)
            records.append(
                {
                    "name": name,
                    "location": str(param.get("in", "") or "unknown"),
                    "api": item_api,
                }
            )
    return records


def api_param_names_for_api(context: list[dict[str, Any]], api: str) -> set[str]:
    return {item["name"] for item in api_param_records_for_api(context, api)}


def allowed_api_param_names(context: list[dict[str, Any]], apis: list[str]) -> list[str]:
    output = []
    seen = set()
    for api in apis:
        for item in api_param_records_for_api(context, api):
            name = item["name"]
            if name not in seen:
                seen.add(name)
                output.append(name)
    return output


def filter_params_by_api_context(
    params: list[str],
    context: list[dict[str, Any]],
    apis: list[str],
) -> tuple[list[str], list[str]]:
    allowed = set(allowed_api_param_names(context, apis))
    if not allowed:
        return params, []
    kept = []
    dropped = []
    for param in params:
        if param in allowed:
            kept.append(param)
        else:
            dropped.append(param)
    return kept, dropped


def param_exists_in_any_api(context: list[dict[str, Any]], param: str, apis: list[str]) -> bool:
    return any(param in api_param_names_for_api(context, api) for api in apis)


def filter_contextual_params_by_real_source_target(
    params: list[str],
    context_apis: list[str],
    target_apis: list[str],
    context: list[dict[str, Any]],
    dependency_relation: str,
    expected_source: str,
) -> tuple[list[str], list[str]]:
    dependency = str(dependency_relation or "").strip().lower()
    source = str(expected_source or "").strip().lower()
    requires_cross_api_source = (
        bool(context_apis)
        and (
            dependency in {"derived_from_context_api", "bound_to_upstream_context"}
            or source in {"upstream_context_api", "normal_sequence_context", "upstream_context"}
        )
    )
    if not requires_cross_api_source:
        return params, []
    kept = []
    dropped = []
    for param in params:
        has_source = param_exists_in_any_api(context, param, context_apis)
        has_target = param_exists_in_any_api(context, param, target_apis)
        if has_source and has_target:
            kept.append(param)
        else:
            dropped.append(param)
    return kept, dropped


def filter_parameter_occurrences_by_api_context(
    occurrences: list[dict[str, str]],
    context: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    kept = []
    dropped = []
    for occurrence in occurrences:
        api = str(occurrence.get("api", "")).strip()
        param = str(occurrence.get("parameter", "")).strip()
        if api and param and param in api_param_names_for_api(context, api):
            kept.append(occurrence)
        else:
            dropped.append(occurrence)
    return kept, dropped


def filter_context_binding_by_api_context(
    bindings: list[dict[str, str]],
    context: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    kept = []
    dropped = []
    for binding in bindings:
        source_api = str(binding.get("source_api", "")).strip()
        target_api = str(binding.get("target_api", "")).strip()
        source_parameter = str(binding.get("source_parameter") or binding.get("parameter") or "").strip()
        target_parameter = str(binding.get("target_parameter") or binding.get("parameter") or "").strip()
        source_ok = source_api and source_parameter in api_param_names_for_api(context, source_api)
        target_ok = target_api and target_parameter in api_param_names_for_api(context, target_api)
        same_parameter_relation = source_parameter.lower() == target_parameter.lower()
        if source_ok and target_ok and same_parameter_relation:
            normalized = dict(binding)
            normalized["source_parameter"] = source_parameter
            normalized["target_parameter"] = target_parameter
            kept.append(normalized)
        else:
            dropped.append(binding)
    return kept, dropped


def infer_cross_api_context_binding(
    target_apis: list[str],
    context_apis: list[str],
    context: list[dict[str, Any]],
    dependency_relation: str,
) -> list[dict[str, str]]:
    records = []
    for source_api in context_apis:
        source_records = api_param_records_for_api(context, source_api)
        source_params = [item["name"] for item in source_records if OBJECT_RE.search(item["name"])]
        if not source_params and len(source_records) == 1:
            source_params = [source_records[0]["name"]]
        for target_api in target_apis:
            target_records = api_param_records_for_api(context, target_api)
            target_params = [item["name"] for item in target_records if OBJECT_RE.search(item["name"])]
            if not target_params and len(target_records) == 1:
                target_params = [target_records[0]["name"]]
            for source_param in source_params:
                for target_param in target_params:
                    if source_param.lower() != target_param.lower():
                        continue
                    records.append(
                        {
                            "source_api": source_api,
                            "target_api": target_api,
                            "source_parameter": source_param,
                            "target_parameter": target_param,
                            "parameter": target_param,
                            "relation": dependency_relation or "same_business_object",
                            "explanation": f"{target_param} 是源 API 与目标 API 参数画像中共同存在的真实参数名，可作为跨 API 上下文绑定依据。",
                        }
                    )
    return records


def derive_parameter_occurrences(
    params: list[str],
    target_apis: list[str],
    context_apis: list[str],
    context: list[dict[str, Any]],
) -> list[dict[str, str]]:
    records = []
    for param in params:
        for api in context_apis:
            matches = [item for item in api_param_records_for_api(context, api) if item["name"] == param]
            if not matches:
                continue
            records.append(
                {
                    "parameter": param,
                    "api": api,
                    "location": matches[0].get("location", "unknown"),
                    "role": "context_source",
                    "evidence": "参数来自参数画像中该 API 的真实请求参数。",
                }
            )
        for api in target_apis:
            matches = [item for item in api_param_records_for_api(context, api) if item["name"] == param]
            if not matches:
                continue
            records.append(
                {
                    "parameter": param,
                    "api": api,
                    "location": matches[0].get("location", "unknown"),
                    "role": "target_parameter",
                    "evidence": "参数来自参数画像中该 API 的真实请求参数。",
                }
            )
    return records


def derive_context_binding(
    params: list[str],
    target_apis: list[str],
    context_apis: list[str],
    dependency_relation: str,
    context: list[dict[str, Any]],
) -> list[dict[str, str]]:
    if not params or not target_apis or not context_apis:
        return []
    records = []
    relation = dependency_relation or "bound_to_upstream_context"
    for param in params:
        for source_api in context_apis:
            if param not in api_param_names_for_api(context, source_api):
                continue
            for target_api in target_apis:
                if param not in api_param_names_for_api(context, target_api):
                    continue
                records.append(
                    {
                        "source_api": source_api,
                        "target_api": target_api,
                        "parameter": param,
                        "relation": relation,
                        "explanation": f"{param} 应由上游上下文约束目标 API，避免中途替换或脱离上下文。",
                    }
                )
    return records


def api_list_from_activity(activity_model: dict[str, Any]) -> list[str]:
    output = []
    for item in activity_model.get("activities", []) or []:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label", "")).strip()
        if label and re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", label, re.I) and label not in output:
            output.append(label)
    return output


def api_list_from_context(context: list[dict[str, Any]]) -> list[str]:
    output = []
    for item in context:
        if isinstance(item, dict) and item.get("api"):
            api = str(item["api"]).strip()
            if api and api not in output:
                output.append(api)
    return output


def normal_sequence_apis(scenario: dict[str, Any]) -> list[str]:
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    values = sequence_block.get("normal_sequence_pattern", [])
    if not isinstance(values, list):
        return []
    output = []
    for value in values:
        text = str(value or "").strip()
        if re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", text, re.I) and text not in output:
            output.append(text)
    return output


def split_context_and_target_apis(all_apis: list[str], normal_apis: list[str]) -> tuple[list[str], list[str]]:
    if not all_apis:
        return [], []
    target_apis = [api for api in all_apis if api in normal_apis] or all_apis[-1:]
    first_target_index = min((normal_apis.index(api) for api in target_apis if api in normal_apis), default=len(normal_apis))
    context_apis = [api for api in normal_apis[:first_target_index] if api not in target_apis]
    if not context_apis and len(normal_apis) > 1:
        context_apis = [api for api in normal_apis if api not in target_apis]
    return context_apis, target_apis


def parameter_scope(
    scenario: dict[str, Any],
    parameter_block: dict[str, Any],
    activity_model: dict[str, Any],
    context: list[dict[str, Any]],
) -> dict[str, Any]:
    params = normalize_param_list(parameter_block.get("key_parameters_or_objects", []))
    explicit_target_apis = normalize_param_list(parameter_block.get("target_apis", []))
    explicit_context_apis = normalize_param_list(parameter_block.get("context_apis", []))
    all_apis = api_list_from_context(context) or api_list_from_activity(activity_model)
    normal_apis = normal_sequence_apis(scenario) or api_list_from_activity(activity_model)
    context_apis, target_apis = split_context_and_target_apis(all_apis, normal_apis)
    if explicit_target_apis:
        target_apis = explicit_target_apis
    if explicit_context_apis:
        context_apis = explicit_context_apis
    params, dropped_params = filter_params_by_api_context(params, context, target_apis + context_apis)
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    expected_source = str(parameter_block.get("expected_parameter_source", "") or "").strip()
    if sequence_block.get("normal_sequence_pattern"):
        expected_source = expected_source or "normal_sequence_context"
    risk_form = str(parameter_block.get("risky_parameter_form", "") or "")
    if re.search(r"(前置|上下文|来源|继承|来自|绑定|跳过|缺失)", risk_form, re.I):
        expected_source = expected_source or "upstream_context"
    dependency_relation = str(parameter_block.get("parameter_dependency_relation", "") or "").strip() or "stable_within_target_api"
    if context_apis:
        dependency_relation = dependency_relation if dependency_relation != "unknown" else "derived_from_context_api"
    if re.search(r"(绑定|所属|owner|project|issue|user|context|上下文|来源|来自)", risk_form, re.I):
        dependency_relation = dependency_relation if dependency_relation != "unknown" else "bound_to_upstream_context"
    normal_parameter_sequence = normalize_param_list(parameter_block.get("normal_parameter_sequence", [])) or normal_apis or all_apis
    params, dropped_unbound_params = filter_contextual_params_by_real_source_target(
        params,
        context_apis,
        target_apis,
        context,
        dependency_relation,
        expected_source,
    )
    if dropped_unbound_params and not params:
        target_only_params, target_dropped_params = filter_params_by_api_context(dropped_unbound_params, context, target_apis)
        if target_only_params:
            params = target_only_params
            dropped_unbound_params = target_dropped_params
            context_apis = []
            expected_source = "target_api_observed_values"
            dependency_relation = "stable_within_target_api"
    parameter_occurrences = normalize_record_list(parameter_block.get("parameter_occurrences", []))
    parameter_occurrences, dropped_occurrences = filter_parameter_occurrences_by_api_context(parameter_occurrences, context)
    if not parameter_occurrences:
        parameter_occurrences = derive_parameter_occurrences(params, target_apis, context_apis, context)
    context_binding = normalize_record_list(parameter_block.get("context_binding", []))
    context_binding, dropped_bindings = filter_context_binding_by_api_context(context_binding, context)
    if not context_binding:
        context_binding = derive_context_binding(params, target_apis, context_apis, dependency_relation, context)
    if not context_binding:
        context_binding = infer_cross_api_context_binding(target_apis, context_apis, context, dependency_relation)
        for binding in context_binding:
            for param in (binding.get("source_parameter", ""), binding.get("target_parameter", "")):
                if param and param not in params:
                    params.append(param)
        if context_binding:
            derived_occurrences = derive_parameter_occurrences(params, target_apis, context_apis, context)
            seen_occurrences = {
                (item.get("parameter", ""), item.get("api", ""), item.get("role", ""))
                for item in parameter_occurrences
            }
            for item in derived_occurrences:
                marker = (item.get("parameter", ""), item.get("api", ""), item.get("role", ""))
                if marker not in seen_occurrences:
                    parameter_occurrences.append(item)
                    seen_occurrences.add(marker)
    return {
        "target_api_scope": target_apis or all_apis,
        "context_api_scope": context_apis,
        "normal_parameter_sequence": normal_parameter_sequence,
        "parameters": params,
        "parameter_occurrences": parameter_occurrences,
        "context_binding": context_binding,
        "dropped_unverified_parameters": dropped_params + dropped_unbound_params,
        "dropped_unverified_parameter_occurrences": dropped_occurrences,
        "dropped_unverified_context_bindings": dropped_bindings,
        "parameter_source_policy": "parameter_profile_parameter_names",
        "expected_source": expected_source or "same_api_context",
        "dependency_relation": dependency_relation,
        "risk_form": risk_form,
    }


def fol_list(values: list[str]) -> str:
    return "{" + ",".join(fol_string(value) for value in values) + "}"


def symbol_list(values: list[str], prefix: str) -> tuple[list[str], list[dict[str, str]]]:
    symbols = []
    bindings = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        symbol = f"{prefix}{len(symbols) + 1}"
        symbols.append(symbol)
        bindings.append({"symbol": symbol, "value": text})
    return symbols, bindings


def symbolic_parameter_scope(p_scope: dict[str, Any]) -> tuple[dict[str, Any], dict[str, list[dict[str, str]]]]:
    context_symbols, context_bindings = symbol_list(normalize_param_list(p_scope.get("context_api_scope", [])), "C")
    target_symbols, target_bindings = symbol_list(normalize_param_list(p_scope.get("target_api_scope", [])), "T")
    param_symbols, param_bindings = symbol_list(normalize_param_list(p_scope.get("parameters", [])), "P")
    symbolic_scope = dict(p_scope)
    symbolic_scope.update(
        {
            "context_api_scope_symbols": context_symbols,
            "target_api_scope_symbols": target_symbols,
            "parameter_symbols": param_symbols,
        }
    )
    symbol_bindings = {
        "context_api_scope": context_bindings,
        "target_api_scope": target_bindings,
        "parameters": param_bindings,
    }
    return symbolic_scope, symbol_bindings


def fol_symbol_set(symbols: list[str]) -> str:
    return "{" + ",".join(symbols) + "}"


def scenario_status_text(scenario: dict[str, Any]) -> str:
    parts: list[str] = []

    def visit(value: Any, status_context: bool = False) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_l = str(key).lower()
                child_status_context = status_context or any(
                    marker in key_l
                    for marker in (
                        "status",
                        "response",
                        "状态码",
                        "响应码",
                        "sequence_status_observation",
                        "precheck_api_status_observation",
                        "target_api_status_observation",
                        "parameter_api_status_observation",
                        "risk_level_adjustment_reason",
                    )
                )
                visit(child, child_status_context)
        elif isinstance(value, list):
            for child in value:
                visit(child, status_context)
        elif value is not None:
            text = str(value)
            text_l = text.lower()
            if status_context or STATUS_TOKEN_RE.search(text) or any(
                word in text_l for word in ("status", "response", "响应码", "状态码", "返回", "2xx", "3xx", "4xx", "5xx")
            ):
                parts.append(text)

    visit(scenario)
    return "\n".join(parts)


def status_classes_from_text(text: str) -> set[str]:
    text_l = str(text or "").lower()
    classes = set(re.findall(r"(?<!\d)[2345]xx(?!\d)", text_l))
    for code in re.findall(r"(?<!\d)[1-5]\d\d(?!\d)", text_l):
        classes.add(f"{code[0]}xx")
        classes.add(code)
    return classes


def status_code_constraints(
    scenario: dict[str, Any],
    security_type: str,
    risk_type: str,
    activity_model: dict[str, Any],
    p_scope: dict[str, Any],
) -> dict[str, Any]:
    text = scenario_status_text(scenario)
    if not text.strip():
        return {}
    classes = status_classes_from_text(text)
    constraints: dict[str, Any] = {}
    target_symbol = str(activity_model.get("risk_target_activity") or "")
    missing_symbol = str(activity_model.get("missing_or_reordered_activity") or "")

    if target_symbol and "2xx" in classes:
        constraints["target_activity"] = target_symbol
        constraints["target_status_classes"] = ["2xx"]
    if missing_symbol and ({"401", "403", "4xx"} & classes):
        constraints["precheck_activity"] = missing_symbol
        constraints["precheck_status_codes"] = ["401", "403"]
    if "404" in classes:
        constraints["object_context_status_codes"] = ["404"]
    if "5xx" in classes:
        constraints["server_error_status_classes"] = ["5xx"]
        if target_symbol:
            constraints.setdefault("target_activity", target_symbol)
    if "3xx" in classes or "304" in classes:
        constraints["redirect_or_cache_status_classes"] = ["3xx"]
        constraints["cache_status_codes"] = ["304"]
    if risk_type in {"parameter_consistency", "both"} and p_scope.get("target_api_scope"):
        constraints.setdefault("target_api_scope", normalize_param_list(p_scope.get("target_api_scope", [])))
        if "2xx" in classes:
            constraints.setdefault("target_status_classes", ["2xx"])
    if text:
        constraints["status_code_analysis"] = text[:1200]
    return constraints


def status_formula_clause(status_scope: dict[str, Any]) -> str:
    clauses = []
    target = status_scope.get("target_activity", "")
    precheck = status_scope.get("precheck_activity", "")
    if target and status_scope.get("target_status_classes"):
        clauses.append(f"StatusClassIn(s,{target},{fol_list(status_scope['target_status_classes'])})")
    if precheck and status_scope.get("precheck_status_codes"):
        clauses.append(f"PrecheckFailedOrMissing(s,{precheck},{fol_list(status_scope['precheck_status_codes'])})")
    if target and status_scope.get("server_error_status_classes"):
        clauses.append(f"StatusClassIn(s,{target},{fol_list(status_scope['server_error_status_classes'])})")
    if status_scope.get("target_api_scope") and status_scope.get("target_status_classes"):
        clauses.append(
            f"ApiStatusClassIn(s,{fol_list(status_scope['target_api_scope'])},{fol_list(status_scope['target_status_classes'])})"
        )
    return " ∧ ".join(dict.fromkeys(clauses))


def attach_status_scope(scope: dict[str, Any], status_scope: dict[str, Any]) -> dict[str, Any]:
    if not status_scope:
        return scope
    output = dict(scope)
    output["status_code_constraints"] = status_scope
    return output


def sequence_detector_config(scope: dict[str, Any]) -> dict[str, Any]:
    config = {
        "engine": "sequence_order",
        "mode": scope.get("mode", "risky_order"),
        "required_activity": scope.get("required_activity", ""),
        "target_activity": scope.get("target_activity", ""),
        "activity": scope.get("activity", ""),
        "threshold": int(str(scope.get("threshold") or "2")) if str(scope.get("threshold") or "2").isdigit() else 2,
        "api_match": "exact",
        "ignore_apis": [],
    }
    if scope.get("sequence_subtype"):
        config["sequence_subtype"] = scope.get("sequence_subtype")
    if isinstance(scope.get("authorization_precheck"), dict):
        config["authorization_precheck"] = scope.get("authorization_precheck")
    if isinstance(scope.get("status_code_constraints"), dict):
        config["status_code_constraints"] = scope.get("status_code_constraints")
    return config


def parameter_detector_config(p_scope: dict[str, Any]) -> dict[str, Any]:
    dependency = str(p_scope.get("dependency_relation", "") or "").strip()
    expected_source = str(p_scope.get("expected_source", "") or "").strip()
    require_context = bool(normalize_param_list(p_scope.get("context_api_scope", []))) and (
        dependency in {"derived_from_context_api", "bound_to_upstream_context"}
        or expected_source in {"upstream_context_api", "normal_sequence_context", "upstream_context"}
    )
    config = {
        "engine": "parameter_consistency",
        "checks": ["target_value_switch", "context_missing", "not_from_context"] if require_context else ["target_value_switch"],
        "parameters": normalize_param_list(p_scope.get("parameters", [])),
        "parameter_aliases": {},
        "target_api_scope": normalize_param_list(p_scope.get("target_api_scope", [])),
        "context_api_scope": normalize_param_list(p_scope.get("context_api_scope", [])),
        "dependency_relation": dependency,
        "expected_source": expected_source,
        "require_context": require_context,
        "min_distinct_target_values": 2,
        "ignore_values": ["", "null", "undefined"],
        "api_match": "exact",
    }
    if isinstance(p_scope.get("status_code_constraints"), dict):
        config["status_code_constraints"] = p_scope.get("status_code_constraints")
    return config


def formula_for(
    scenario: dict[str, Any],
    security_type: str,
    entities: list[dict[str, str]],
    bindings: dict[str, str],
    boundary_model: dict[str, Any],
    context: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], str, list[str]]:
    title = str(scenario.get("scenario_title", "安全场景"))
    title_const = fol_string(title)
    risk_level = fol_string(bindings.get("risk_level", "medium"))
    category = fol_string(security_type)
    activity_model = build_activity_abstraction(scenario)
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    p_scope = parameter_scope(scenario, parameter_block, activity_model, context)
    symbolic_p_scope, parameter_symbol_bindings = symbolic_parameter_scope(p_scope)
    key_params = p_scope["parameters"]
    key_param_text = fol_symbol_set(symbolic_p_scope["parameter_symbols"])
    target_api_scope_text = fol_symbol_set(symbolic_p_scope["target_api_scope_symbols"])
    context_api_scope_text = fol_symbol_set(symbolic_p_scope["context_api_scope_symbols"])
    expected_source_text = fol_string(p_scope["expected_source"])
    dependency_relation_text = fol_string(p_scope["dependency_relation"])
    risk_type = scenario_risk_type(scenario)
    status_scope = status_code_constraints(scenario, security_type, risk_type, activity_model, p_scope)
    status_clause = status_formula_clause(status_scope)
    parameter_requires_context = bool(normalize_param_list(p_scope.get("context_api_scope", []))) and p_scope.get("dependency_relation") in {
        "derived_from_context_api",
        "bound_to_upstream_context",
    }
    has_parameter_risk = (
        risk_type in {"parameter_consistency", "both"}
        and has_parameter_risk_block(scenario)
        and has_real_parameter_risk(parameter_block)
        and has_actionable_parameter_scope(p_scope)
    )
    has_sequence_risk = (
        risk_type in {"sequence_order", "both"}
        and has_sequence_risk_block(scenario)
        and bool(activity_model.get("activities"))
    )

    sequence_clause = sequence_formula_clause(activity_model)
    if parameter_requires_context:
        parameter_clause = (
            f'ParameterFlowContext(s,{context_api_scope_text},{target_api_scope_text},{key_param_text},{dependency_relation_text}) ∧ '
            f'ParameterAppearsOrDerived(s,{target_api_scope_text},{key_param_text}) ∧ '
            f'¬ParameterConsistentWithContext(s,{context_api_scope_text},{target_api_scope_text},{key_param_text},{expected_source_text})'
        )
    else:
        parameter_clause = (
            f'ParameterAppearsOrDerived(s,{target_api_scope_text},{key_param_text}) ∧ '
            f'DistinctTargetParameterValuesAtLeast(s,{target_api_scope_text},{key_param_text},2)'
        )
    if status_clause:
        sequence_clause_with_status = f"{sequence_clause} ∧ {status_clause}"
        parameter_clause_with_status = f"{parameter_clause} ∧ {status_clause}"
        combined_status_clause = f" ∧ {status_clause}"
    else:
        sequence_clause_with_status = sequence_clause
        parameter_clause_with_status = parameter_clause
        combined_status_clause = ""
    expressions = []
    combine = has_sequence_risk and has_parameter_risk and should_combine_sequence_and_parameter(scenario)
    if combine:
        seq_scope = attach_status_scope(sequence_expression_scope(activity_model, security_type), status_scope)
        symbolic_p_scope_with_status = attach_status_scope(symbolic_p_scope, status_scope)
        p_scope_with_status = attach_status_scope(p_scope, status_scope)
        expressions.append(
            {
                "dimension": "sequence_order_and_parameter_consistency",
                "scope": {
                    "sequence": seq_scope,
                    "parameter": symbolic_p_scope_with_status,
                },
                "detector": {
                    "engine": "all",
                    "children": [
                        sequence_detector_config(seq_scope),
                        parameter_detector_config(p_scope_with_status),
                    ],
                },
                "symbol_bindings": {"parameter": parameter_symbol_bindings},
                "formula": f'∀s (({sequence_clause} ∧ {parameter_clause}{combined_status_clause}) → RatedCombinedSequenceParameterRisk(s,{category},{risk_level},{title_const}))',
                "meaning": "当顺序链被破坏，并且关键对象参数也存在来源不明、中途替换或上下文不一致时，结合响应状态码证据产生组合风险评级。",
            }
        )
    elif has_sequence_risk:
        seq_scope = attach_status_scope(sequence_expression_scope(activity_model, security_type), status_scope)
        expressions.append(
            {
                "dimension": "sequence_order",
                "scope": seq_scope,
                "detector": sequence_detector_config(seq_scope),
                "formula": f'∀s ({sequence_clause_with_status} → RatedSequenceOrderRisk(s,{category},{risk_level},{title_const}))',
                "meaning": "如果会话中出现跳步、越序、关键步骤缺失或敏感步骤过早出现，并且响应状态码证据支持该场景，则产生序列顺序风险评级。",
            }
        )
    if has_parameter_risk and not combine:
        symbolic_p_scope_with_status = attach_status_scope(symbolic_p_scope, status_scope)
        p_scope_with_status = attach_status_scope(p_scope, status_scope)
        expressions.append(
            {
                "dimension": "parameter_consistency",
                "scope": symbolic_p_scope_with_status,
                "detector": parameter_detector_config(p_scope_with_status),
                "symbol_bindings": {"parameter": parameter_symbol_bindings},
                "formula": f'∀s ({parameter_clause_with_status} → RatedParameterRisk(s,{category},{risk_level},{title_const}))',
                "meaning": "如果目标 API 中出现关键参数，但该参数没有按正常业务上下文传递、绑定或保持一致，并且响应状态码证据支持该场景，则产生参数一致性风险评级。",
            }
        )
    predicates = [
        "Occurs(s,A)",
        "Before(s,A_before,A_after)",
        "RequiredBefore(A_required,A_target)",
        "RiskyAdjacentOrder(s,A_before,A_after)",
        "CountInSession(s,A)",
        "StatusCodeIn(s,A,status_codes)",
        "StatusClassIn(s,A,status_classes)",
        "ApiStatusClassIn(s,api_scope,status_classes)",
        "PrecheckFailedOrMissing(s,A_precheck,status_codes)",
        "ParameterFlowContext(s,context_api_scope,target_api_scope,key_parameters,dependency_relation)",
        "ParameterAppearsOrDerived(s,target_api_scope,key_parameters)",
        "ParameterConsistentWithContext(s,context_api_scope,target_api_scope,key_parameters,expected_source)",
        "DistinctTargetParameterValuesAtLeast(s,target_api_scope,key_parameters,threshold)",
        "RatedSequenceOrderRisk(s,security_category,risk_level,title)",
        "RatedParameterRisk(s,security_category,risk_level,title)",
        "RatedCombinedSequenceParameterRisk(s,security_category,risk_level,title)",
    ]
    plain = "表达式会按场景选择生成方式：只有参数画像证明源 API 与目标 API 存在真实同名参数关系时，才生成跨 API 参数来源约束；否则降级为目标 API 内部参数值切换/枚举检测。若场景中有响应码证据，会加入 StatusCodeIn/StatusClassIn/ApiStatusClassIn 作为证据谓词。响应码只作为风险可信度证据，不单独证明越权或攻击成功。"
    return expressions, plain, predicates


def evidence_mapping(security_type: str, scenario: dict[str, Any], context: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"predicate": "InSession(s,r)", "source": "原始 session 序列", "field_hint": "session_id 与步骤号"},
        {"predicate": "Calls(r,api)", "source": "原始请求日志", "field_hint": "HTTP method + path"},
        {"predicate": "ViolatesSequenceOrder", "source": "聚类代表序列 + 成员序列", "field_hint": "前置步骤、后置接口、敏感动作顺序、重复调用"},
        {"predicate": "ParameterFlowContext", "source": "正常序列 + OpenAPI 参数文档", "field_hint": "参数来源上下文 API、目标 API、关键参数"},
        {"predicate": "ParameterAppearsOrDerived", "source": "原始请求参数 + OpenAPI 参数/响应文档", "field_hint": "参数在哪个 API 中出现，或只能从响应/业务上下文推断"},
        {"predicate": "ParameterConsistentWithContext", "source": "原始请求参数 + 上下文 API", "field_hint": "目标 API 参数是否与上游上下文一致"},
        {"predicate": "DistinctTargetParameterValuesAtLeast", "source": "参数画像 + 目标 API 请求参数", "field_hint": "缺少真实源 API 参数关系时，只检测目标 API 内同一参数的多值切换/枚举"},
        {"predicate": "StatusClassIn / StatusCodeIn / ApiStatusClassIn / PrecheckFailedOrMissing", "source": "原始事件状态码 + 聚类状态码证据", "field_hint": "status_code/http.status_code 与同一步 API 对齐；响应码只作为风险可信度证据"},
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


def compact_scenario_summary(
    scenario: dict[str, Any],
    security_type: str,
    context: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sequence_block = scenario.get("sequence_order_risk", {}) if isinstance(scenario.get("sequence_order_risk"), dict) else {}
    parameter_block = scenario.get("parameter_consistency_risk", {}) if isinstance(scenario.get("parameter_consistency_risk"), dict) else {}
    context = context or []
    output = {
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
        "overall_reason": scenario.get("overall_reason", ""),
    }
    if has_real_parameter_risk(parameter_block):
        p_scope = parameter_scope(scenario, parameter_block, build_activity_abstraction(scenario), context)
        output.update(
            {
                "parameter_target_apis": p_scope.get("target_api_scope", []),
                "parameter_context_apis": p_scope.get("context_api_scope", []),
                "parameter_normal_sequence": p_scope.get("normal_parameter_sequence", []),
                "parameter_objects": p_scope.get("parameters", []),
                "parameter_occurrences": p_scope.get("parameter_occurrences", []),
                "parameter_context_binding": p_scope.get("context_binding", []),
                "parameter_dependency_relation": p_scope.get("dependency_relation", ""),
                "expected_parameter_source": p_scope.get("expected_source", ""),
                "parameter_risk": p_scope.get("risk_form", ""),
            }
        )
    return output


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
    if security_type == "RESOURCE_CONSUMPTION" and is_benign_polling_resource_scenario(scenario, apis):
        return {
            "fol_id": f"FOL-{scenario_id}",
            "status": "skipped",
            "source": source,
            "skip_reason": "良性轮询/状态计数类接口重复出现，缺少异常高频、过载、洪泛或资源耗尽证据；不生成资源消耗规则。",
            "related_apis": apis,
            "openapi_summary": compact_openapi_context(context),
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

    logic_expressions, plain, predicates = formula_for(scenario, security_type, entities, bindings, boundary_model, context)
    return {
        "fol_id": f"FOL-{scenario_id}",
        "status": "generated",
        "source": source,
        "scenario_summary": compact_scenario_summary(scenario, security_type, context),
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
        {"predicate": "ParameterFlowContext(s,context_api_scope,target_api_scope,key_parameters,dependency_relation)", "description": "参数一致性检查的上下文 API、目标 API、关键参数和依赖关系"},
        {"predicate": "ParameterAppearsOrDerived(s,target_api_scope,key_parameters)", "description": "关键参数出现在目标 API 中，或者需要从响应、搜索条件、OpenAPI 文档中推断"},
        {"predicate": "ParameterConsistentWithContext(s,context_api_scope,target_api_scope,key_parameters,expected_source)", "description": "目标 API 参数与上游上下文、同一对象或同一会话来源保持一致"},
        {"predicate": "RatedSequenceOrderRisk(s,security_category,risk_level,title)", "description": "序列顺序风险评级结果"},
        {"predicate": "RatedParameterRisk(s,security_category,risk_level,title)", "description": "参数一致性风险评级结果"},
        {"predicate": "RatedCombinedSequenceParameterRisk(s,security_category,risk_level,title)", "description": "序列顺序和参数一致性共同成立时的组合风险评级结果"},
    ]


def format_list(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "无"
    return " -> ".join(str(item) for item in items)


def format_record_list(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "无"
    parts = []
    for item in items[:8]:
        if not isinstance(item, dict):
            parts.append(str(item))
            continue
        if {"parameter", "api"} <= set(item):
            parts.append(
                f"{item.get('parameter')} @ {item.get('api')} "
                f"[{item.get('location', 'unknown')}, {item.get('role', 'unknown')}]"
            )
        elif {"source_api", "target_api"} <= set(item):
            parts.append(
                f"{item.get('source_api')} -> {item.get('target_api')} "
                f"({item.get('parameter', '')}, {item.get('relation', 'unknown')})"
            )
        else:
            parts.append(", ".join(f"{key}={value}" for key, value in item.items()))
    if len(items) > 8:
        parts.append(f"... 共 {len(items)} 条")
    return "；".join(parts)


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
        "- 参数一致性模板：`ParameterFlowContext(...) ∧ ParameterAppearsOrDerived(...) ∧ ¬ParameterConsistentWithContext(...)`",
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
            ]
        )
        if "parameter_risk" in summary:
            lines.extend(
                [
                    f"- 参数目标 API: {format_list(summary.get('parameter_target_apis'))}",
                    f"- 参数上下文 API: {format_list(summary.get('parameter_context_apis'))}",
                    f"- 参数完整链路: {format_list(summary.get('parameter_normal_sequence'))}",
                    f"- 参数出现位置: {format_record_list(summary.get('parameter_occurrences'))}",
                    f"- 参数上下文绑定: {format_record_list(summary.get('parameter_context_binding'))}",
                    f"- 参数依赖关系: {summary.get('parameter_dependency_relation') or '无'}",
                    f"- 参数期望来源: {summary.get('expected_parameter_source') or '无'}",
                    f"- 参数风险: {summary.get('parameter_risk') or '无'}",
                ]
            )
        lines.extend(["", "活动映射:"])
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
    openapi_file = Path(args.openapi_file) if args.openapi_file else base_dir / "API_document" / f"site_{args.site_id}_openapi.json"
    parameter_profile_file = (
        Path(args.parameter_profile_file)
        if args.parameter_profile_file
        else base_dir / "parameter_profiles" / f"site_{args.site_id}_parameter_profile.json"
    )
    boundary_file = Path(args.boundary_file) if args.boundary_file else base_dir / "object_boundary_mining" / f"site_{args.site_id}_project_issue_access.json"
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "fol_expressions"

    reviews = read_json(review_file)
    if parameter_profile_file.exists():
        api_doc = read_json(parameter_profile_file)
        api_index = build_parameter_profile_index(api_doc)
        api_context_source = "parameter_profile"
        api_context_file = parameter_profile_file
    else:
        api_doc = read_json(openapi_file)
        api_index = build_openapi_index(api_doc)
        api_context_source = "openapi_fallback"
        api_context_file = openapi_file
    boundary_model = load_project_boundary(boundary_file)
    expressions = [
        generate_expression(review, scenario, index, api_index, boundary_model)
        for review, scenario, index in iter_scenarios(reviews, args.include_low_trust)
    ]
    generated = sum(1 for item in expressions if item.get("status") == "generated")
    skipped = sum(1 for item in expressions if item.get("status") == "skipped")
    payload = {
        "site_id": args.site_id,
        "review_file": str(review_file),
        "api_context_source": api_context_source,
        "api_context_file": str(api_context_file),
        "parameter_profile_file": str(parameter_profile_file) if parameter_profile_file.exists() else "",
        "openapi_file": str(openapi_file) if openapi_file.exists() else "",
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
