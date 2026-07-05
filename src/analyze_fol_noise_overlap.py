# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_BASE_DIR = r"D:\browser\Innovation\sequence\log_process"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze overlap between FOL rule detections and DBSCAN noise sessions."
    )
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--site-id", required=True)
    parser.add_argument(
        "--cluster-file",
        default="",
        help="Default: <base-dir>/process_mining/site_<site_id>_business_session_clusters.json",
    )
    parser.add_argument(
        "--violation-file",
        default="",
        help="Default: <base-dir>/fol_rule_violations/site_<site_id>_fol_rule_violations.json",
    )
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/fol_rule_violations")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def safe_ratio(part: int, total: int) -> float:
    return round(part / total, 6) if total else 0.0


def session_ids_from_noise(cluster_payload: dict[str, Any]) -> set[str]:
    output = set()
    for item in cluster_payload.get("noise_sessions", []) or []:
        if isinstance(item, dict) and item.get("session_id"):
            output.add(str(item["session_id"]))
    return output


def session_ids_from_clustered(cluster_payload: dict[str, Any]) -> set[str]:
    output = set()
    for cluster in cluster_payload.get("clusters", []) or []:
        if not isinstance(cluster, dict):
            continue
        if cluster.get("representative_session_id"):
            output.add(str(cluster["representative_session_id"]))
        for member in cluster.get("member_sessions", []) or []:
            if isinstance(member, dict) and member.get("session_id"):
                output.add(str(member["session_id"]))
    return output


def findings_by_session(violation_payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in violation_payload.get("findings", []) or []:
        if isinstance(finding, dict) and finding.get("session_id"):
            output[str(finding["session_id"])].append(finding)
    return dict(output)


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    security_counter = Counter()
    rule_counter = Counter()
    dimension_counter = Counter()
    for finding in findings:
        security_counter[str(finding.get("security_type", ""))] += 1
        rule_counter[str(finding.get("fol_id", ""))] += 1
        for expr_hit in finding.get("expression_hits", []) or []:
            if isinstance(expr_hit, dict):
                dimension_counter[str(expr_hit.get("dimension", ""))] += 1
    return {
        "finding_count": len(findings),
        "security_type_count": dict(security_counter),
        "fol_rule_count": dict(rule_counter),
        "dimension_count": dict(dimension_counter),
    }


def compact_session_detail(session_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "finding_count": len(findings),
        "rules": sorted({str(item.get("fol_id", "")) for item in findings if item.get("fol_id")}),
        "security_types": sorted({str(item.get("security_type", "")) for item in findings if item.get("security_type")}),
        "scenario_titles": sorted({str(item.get("scenario_title", "")) for item in findings if item.get("scenario_title")})[:20],
    }


def build_markdown(site_id: str, payload: dict[str, Any]) -> str:
    lines = [
        f"# Site {site_id} FOL 命中与聚类噪声重合分析",
        "",
        "## 总览",
        "",
        f"- 检测命中 session 数: {payload['summary']['detected_session_count']}",
        f"- 聚类噪声 session 数: {payload['summary']['noise_session_count_available']}",
        f"- 重合 session 数: {payload['summary']['overlap_session_count']}",
        f"- 命中 session 中落在噪声的比例: {payload['summary']['detected_in_noise_ratio']}",
        f"- 噪声 session 被规则命中的比例: {payload['summary']['noise_detected_ratio']}",
        "",
    ]
    warnings = payload.get("warnings", [])
    if warnings:
        lines.extend(["## 注意", ""])
        lines.extend(f"- {item}" for item in warnings)
        lines.append("")
    lines.extend(["## 重合 Session", ""])
    overlap = payload.get("overlap_sessions", [])
    if not overlap:
        lines.append("无")
    for item in overlap[:200]:
        lines.extend(
            [
                f"- `{item['session_id']}`: findings={item['finding_count']}, "
                f"rules={', '.join(item['rules'])}, types={', '.join(item['security_types'])}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    cluster_file = (
        Path(args.cluster_file)
        if args.cluster_file
        else base_dir / "process_mining" / f"site_{args.site_id}_business_session_clusters.json"
    )
    violation_file = (
        Path(args.violation_file)
        if args.violation_file
        else base_dir / "fol_rule_violations" / f"site_{args.site_id}_fol_rule_violations.json"
    )
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "fol_rule_violations"

    cluster_payload = read_json(cluster_file)
    violation_payload = read_json(violation_file)

    noise_ids = session_ids_from_noise(cluster_payload)
    clustered_ids = session_ids_from_clustered(cluster_payload)
    by_session = findings_by_session(violation_payload)
    detected_ids = set(by_session)
    overlap_ids = detected_ids & noise_ids
    detected_clustered_ids = detected_ids & clustered_ids
    detected_unknown_ids = detected_ids - noise_ids - clustered_ids

    warnings = []
    declared_noise_count = int(cluster_payload.get("noise_session_count", 0) or 0)
    if declared_noise_count and len(noise_ids) < declared_noise_count:
        warnings.append(
            "聚类文件中的 noise_sessions 可能被 cluster_member_limit 截断；"
            f"文件声明 noise_session_count={declared_noise_count}，但实际保存 noise_sessions={len(noise_ids)}。"
            "建议重新运行 process_mining.py --cluster-member-limit 0 后再分析完整重合。"
        )

    overlap_findings = [finding for sid in overlap_ids for finding in by_session.get(sid, [])]
    non_noise_findings = [finding for sid in detected_ids - noise_ids for finding in by_session.get(sid, [])]
    payload = {
        "site_id": args.site_id,
        "cluster_file": str(cluster_file),
        "violation_file": str(violation_file),
        "warnings": warnings,
        "summary": {
            "total_session_count": cluster_payload.get("session_count", 0),
            "detected_session_count": len(detected_ids),
            "detected_finding_count": sum(len(items) for items in by_session.values()),
            "noise_session_count_declared": declared_noise_count,
            "noise_session_count_available": len(noise_ids),
            "clustered_session_count_available": len(clustered_ids),
            "overlap_session_count": len(overlap_ids),
            "detected_clustered_session_count": len(detected_clustered_ids),
            "detected_unknown_session_count": len(detected_unknown_ids),
            "detected_in_noise_ratio": safe_ratio(len(overlap_ids), len(detected_ids)),
            "noise_detected_ratio": safe_ratio(len(overlap_ids), len(noise_ids)),
        },
        "overlap_findings_summary": summarize_findings(overlap_findings),
        "non_noise_findings_summary": summarize_findings(non_noise_findings),
        "overlap_sessions": [
            compact_session_detail(session_id, by_session[session_id])
            for session_id in sorted(overlap_ids)
        ],
        "detected_clustered_sessions": [
            compact_session_detail(session_id, by_session[session_id])
            for session_id in sorted(detected_clustered_ids)
        ],
        "detected_unknown_sessions": [
            compact_session_detail(session_id, by_session[session_id])
            for session_id in sorted(detected_unknown_ids)
        ],
    }

    json_path = output_dir / f"site_{args.site_id}_fol_noise_overlap.json"
    md_path = output_dir / f"site_{args.site_id}_fol_noise_overlap.md"
    write_json(json_path, payload)
    write_text(md_path, build_markdown(args.site_id, payload))
    print(
        f"site={args.site_id} detected_sessions={len(detected_ids)} noise_sessions={len(noise_ids)} "
        f"overlap={len(overlap_ids)} json={json_path} md={md_path}"
    )


if __name__ == "__main__":
    main()
