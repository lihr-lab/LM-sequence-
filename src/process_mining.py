# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import math
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


DEFAULT_BASE_DIR = r"D:\browser\Innovation\sequence\log_process"

STEP_RE = re.compile(r"^Step\s+\d+:\s+(?P<body>.+)$")
SESSION_HEADER_RE = re.compile(r"^===\s+(?P<header>.*?)\s*===")
STATUS_SUFFIX_RE = re.compile(r"\s+\[(?P<status>\d+)\](?:\s+.*)?$")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cluster complete API sessions by similar business patterns."
    )
    parser.add_argument("--base-dir", default=os.getenv("SEQ_OUTPUT_DIR", DEFAULT_BASE_DIR))
    parser.add_argument("--input-dir", default="", help="Session JSONL dir or compressed txt dir. Default: <base-dir>/log_sequence")
    parser.add_argument("--output-dir", default="", help="Default: <base-dir>/process_mining")
    parser.add_argument("--site-id", default="", help="Only mine one site_id.")
    parser.add_argument("--bucket", default="all", choices=["short_1_2", "main_3_50", "long_51_plus", "all"])
    parser.add_argument("--max-sessions", type=int, default=0, help="0 means no limit.")
    parser.add_argument("--eps", type=float, default=0.0, help="DBSCAN cosine-distance threshold. 0 means auto by k-distance elbow.")
    parser.add_argument("--min-samples", type=int, default=3, help="DBSCAN minimum sessions required around a core session.")
    parser.add_argument("--eps-min", type=float, default=0.15, help="Lower bound for auto eps.")
    parser.add_argument("--eps-max", type=float, default=0.6, help="Upper bound for auto eps.")
    parser.add_argument("--api-presence-weight", type=float, default=1.0)
    parser.add_argument("--api-frequency-weight", type=float, default=0.8)
    parser.add_argument("--direct-transition-weight", type=float, default=1.4)
    parser.add_argument("--skip-transition-weight", type=float, default=1.1)
    parser.add_argument("--length-weight", type=float, default=0.25)
    parser.add_argument("--endpoint-weight", type=float, default=0.8)
    parser.add_argument("--frequency-cap", type=int, default=5)
    parser.add_argument("--cluster-member-limit", type=int, default=0, help="Other complete sessions kept per cluster. 0 means all.")
    parser.add_argument("--min-cluster-size", type=int, default=3)
    parser.add_argument("--max-skip-distance", type=int, default=5, help="Use A -> B transitions with up to this many skipped steps.")
    parser.add_argument("--top-clusters", type=int, default=0, help="Maximum clusters to output. 0 means all clusters.")
    return parser.parse_args()


def clean_token(token: str) -> str:
    token = str(token or "").strip()
    token = STATUS_SUFFIX_RE.sub("", token).strip()
    if " action=" in token:
        token = token.split(" action=", 1)[0].strip()
    if " label=" in token:
        token = token.split(" label=", 1)[0].strip()
    if " BODY " in token:
        token = token.split(" BODY ", 1)[0].strip()
    return token


def token_to_api(token: str) -> str:
    text = clean_token(token)
    if "?" in text:
        text = text.split("?", 1)[0].strip()
    if " " not in text:
        return text
    method, target = text.split(" ", 1)
    method = method.upper().strip()
    target = target.strip()
    parsed = urlparse("http://local" + target if target.startswith("/") else target)
    path = unquote(parsed.path or target)
    return f"{method} {path}" if method in HTTP_METHODS else text


def infer_site_id_from_name(path: Path) -> str:
    stem = path.stem
    if "site_" in stem:
        return stem.rsplit("site_", 1)[-1].split("_", 1)[0]
    return "unknown_site"


def file_matches_site(path: Path, site_id: str) -> bool:
    return not site_id or infer_site_id_from_name(path) == site_id


def iter_json_blocks(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = [block.strip() for block in text.split("\n\n") if block.strip()]
    if len(blocks) > 1:
        for block in blocks:
            try:
                payload = json.loads(block)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                yield payload
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


def session_from_json(session_obj: dict[str, Any]) -> dict[str, Any]:
    raw_sequence = session_obj.get("full_api_sequence", [])
    if not isinstance(raw_sequence, list) or not raw_sequence:
        raw_sequence = session_obj.get("api_sequence", [])
    if not isinstance(raw_sequence, list) or not raw_sequence:
        sequence_obj = session_obj.get("sequence", {})
        raw_sequence = []
        if isinstance(sequence_obj, dict):
            for _, event in sorted(sequence_obj.items(), key=lambda item: int(item[0])):
                if isinstance(event, dict):
                    raw_sequence.append(event.get("full_api_request") or event.get("token") or event.get("api_request_pattern") or "")
    raw = [str(item).strip() for item in raw_sequence if str(item).strip()]
    apis = [token_to_api(item) for item in raw if token_to_api(item)]
    return {
        "site_id": str(session_obj.get("site_id") or "unknown_site"),
        "session_id": str(session_obj.get("session_id") or ""),
        "source_ip": str(session_obj.get("source_ip") or session_obj.get("client_key") or ""),
        "start_time": str(session_obj.get("start_time") or ""),
        "end_time": str(session_obj.get("end_time") or ""),
        "raw_sequence": raw,
        "api_sequence": apis,
    }


def iter_compressed_txt(path: Path):
    site_id = infer_site_id_from_name(path)
    current: list[str] = []
    current_session_id = ""
    session_index = 0

    def emit():
        nonlocal current, current_session_id
        if not current:
            return None
        raw = current
        payload = {
            "site_id": site_id,
            "session_id": current_session_id or f"{site_id}_txt_{session_index}",
            "source_ip": "",
            "start_time": "",
            "end_time": "",
            "raw_sequence": raw,
            "api_sequence": [token_to_api(item) for item in raw if token_to_api(item)],
        }
        current = []
        current_session_id = ""
        return payload

    with path.open("r", encoding="utf-8", errors="replace") as fin:
        for raw_line in fin:
            line = raw_line.strip()
            if not line:
                continue
            header = SESSION_HEADER_RE.match(line)
            if header:
                previous = emit()
                if previous:
                    yield previous
                session_index += 1
                current_session_id = header.group("header").strip().replace(" ", "_")
                continue
            step = STEP_RE.match(line)
            if step:
                token = clean_token(step.group("body"))
                if token:
                    current.append(token)
    previous = emit()
    if previous:
        yield previous


def discover_input_files(input_dir: Path, bucket: str, site_id: str) -> list[Path]:
    if not input_dir.exists():
        raise FileNotFoundError(f"input dir not found: {input_dir}")
    site_part = site_id if site_id else "*"
    patterns = [f"session_site_{site_part}.jsonl", f"*site_{site_part}.txt"]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(sorted(input_dir.glob(pattern)))
    if not files and bucket != "all" and (input_dir / bucket).exists():
        for pattern in patterns:
            files.extend(sorted((input_dir / bucket).glob(pattern)))
    if not files:
        for pattern in patterns:
            files.extend(sorted(input_dir.glob(f"**/{pattern}")))
    return [path for path in files if file_matches_site(path, site_id)]


def iter_sessions(files: list[Path]):
    for path in files:
        if path.suffix.lower() == ".jsonl":
            for payload in iter_json_blocks(path):
                session = session_from_json(payload)
                if session["api_sequence"]:
                    yield session
        elif path.suffix.lower() == ".txt":
            for session in iter_compressed_txt(path):
                if session["api_sequence"]:
                    yield session


def add_feature(vector: dict[str, float], name: str, value: float) -> None:
    if value:
        vector[name] = vector.get(name, 0.0) + value


def capped_log_count(count: int, cap: int) -> float:
    return math.log(min(max(count, 0), max(cap, 1)) + 1)


def build_session_vector(session: dict[str, Any], max_length: int, args: argparse.Namespace) -> dict[str, float]:
    sequence = session["api_sequence"]
    vector: dict[str, float] = {}
    api_counts = Counter(sequence)

    for api, count in api_counts.items():
        add_feature(vector, f"api_seen::{api}", args.api_presence_weight)
        add_feature(vector, f"api_freq::{api}", args.api_frequency_weight * capped_log_count(count, args.frequency_cap))

    for index in range(len(sequence) - 1):
        source = sequence[index]
        target = sequence[index + 1]
        add_feature(vector, f"direct::{source}->{target}", args.direct_transition_weight)

    for index, source in enumerate(sequence):
        stop = min(len(sequence), index + args.max_skip_distance + 1)
        for target_index in range(index + 2, stop):
            skipped_steps = target_index - index - 1
            decay = 1.0 / (skipped_steps + 1)
            target = sequence[target_index]
            add_feature(vector, f"skip::{source}->{target}", args.skip_transition_weight * decay)

    if sequence:
        add_feature(vector, f"start::{sequence[0]}", args.endpoint_weight)
        add_feature(vector, f"end::{sequence[-1]}", args.endpoint_weight)

    length_scale = math.log(max_length + 1) if max_length > 0 else 1.0
    add_feature(vector, "session_length", args.length_weight * (math.log(len(sequence) + 1) / length_scale))
    return vector


def vector_norm(vector: dict[str, float]) -> float:
    return math.sqrt(sum(value * value for value in vector.values()))


def cosine_distance(left: dict[str, float], right: dict[str, float], left_norm: float, right_norm: float) -> float:
    if left_norm <= 0 or right_norm <= 0:
        return 1.0
    if len(left) > len(right):
        left, right = right, left
    dot = sum(value * right.get(feature, 0.0) for feature, value in left.items())
    similarity = max(0.0, min(1.0, dot / (left_norm * right_norm)))
    return 1.0 - similarity


def build_feature_vectors(sessions: list[dict[str, Any]], args: argparse.Namespace) -> tuple[list[dict[str, float]], list[float]]:
    max_length = max((len(session["api_sequence"]) for session in sessions), default=1)
    vectors = [build_session_vector(session, max_length, args) for session in sessions]
    norms = [vector_norm(vector) for vector in vectors]
    return vectors, norms


def build_distance_cache(sessions: list[dict[str, Any]], args: argparse.Namespace):
    vectors, norms = build_feature_vectors(sessions, args)
    cache: dict[tuple[int, int], float] = {}

    def distance(left_index: int, right_index: int) -> float:
        if left_index == right_index:
            return 0.0
        key = (left_index, right_index) if left_index < right_index else (right_index, left_index)
        if key not in cache:
            cache[key] = cosine_distance(vectors[left_index], vectors[right_index], norms[left_index], norms[right_index])
        return cache[key]

    return distance


def best_representative(cluster: list[int], distance) -> int:
    return min(
        cluster,
        key=lambda candidate: sum(distance(candidate, other) for other in cluster),
    )


def clamp(value: float, lower: float, upper: float) -> float:
    if lower > upper:
        lower, upper = upper, lower
    return max(lower, min(upper, value))


def kth_neighbor_distances(session_count: int, distance, min_samples: int) -> list[float]:
    if session_count <= 1:
        return []
    neighbor_rank = max(1, min(min_samples - 1, session_count - 1))
    output = []
    for index in range(session_count):
        distances = sorted(distance(index, other) for other in range(session_count) if other != index)
        output.append(distances[neighbor_rank - 1])
    return output


def knee_distance_desc(sorted_distances: list[float]) -> float:
    if not sorted_distances:
        return 0.0
    if len(sorted_distances) <= 2:
        return sorted_distances[-1]

    first_x, first_y = 0.0, sorted_distances[0]
    last_x, last_y = float(len(sorted_distances) - 1), sorted_distances[-1]
    line_dx = last_x - first_x
    line_dy = last_y - first_y
    line_norm = math.sqrt(line_dx * line_dx + line_dy * line_dy) or 1.0

    best_index = 0
    best_distance = -1.0
    for index, value in enumerate(sorted_distances):
        x = float(index)
        y = value
        perpendicular = abs(line_dy * x - line_dx * y + last_x * first_y - last_y * first_x) / line_norm
        if perpendicular > best_distance:
            best_distance = perpendicular
            best_index = index
    return sorted_distances[best_index]


def resolve_eps(session_count: int, distance, args: argparse.Namespace) -> tuple[float, dict[str, Any]]:
    if args.eps > 0:
        return args.eps, {"mode": "manual", "eps": args.eps}

    kth_distances = kth_neighbor_distances(session_count, distance, args.min_samples)
    sorted_desc = sorted(kth_distances, reverse=True)
    raw_eps = knee_distance_desc(sorted_desc)
    eps = clamp(raw_eps, args.eps_min, args.eps_max)
    return eps, {
        "mode": "auto_k_distance_elbow",
        "neighbor_rank": max(1, args.min_samples - 1),
        "raw_eps": round(raw_eps, 6),
        "eps": round(eps, 6),
        "eps_min": args.eps_min,
        "eps_max": args.eps_max,
        "k_distance_min": round(min(kth_distances), 6) if kth_distances else 0.0,
        "k_distance_max": round(max(kth_distances), 6) if kth_distances else 0.0,
        "k_distance_avg": round(sum(kth_distances) / len(kth_distances), 6) if kth_distances else 0.0,
    }


def region_query(index: int, session_count: int, distance, eps: float) -> list[int]:
    return [other for other in range(session_count) if distance(index, other) <= eps]


def dbscan_sessions(sessions: list[dict[str, Any]], args: argparse.Namespace) -> tuple[list[int], list[list[int]], list[int], dict[str, Any]]:
    distance = build_distance_cache(sessions, args)
    session_count = len(sessions)
    eps, eps_info = resolve_eps(session_count, distance, args)
    labels = [-1] * session_count
    visited = [False] * session_count
    cluster_id = 0

    for index in range(session_count):
        if visited[index]:
            continue
        visited[index] = True
        neighbors = region_query(index, session_count, distance, eps)
        if len(neighbors) < args.min_samples:
            labels[index] = -1
            continue

        labels[index] = cluster_id
        seeds = list(neighbors)
        seed_pos = 0
        while seed_pos < len(seeds):
            neighbor = seeds[seed_pos]
            if not visited[neighbor]:
                visited[neighbor] = True
                neighbor_neighbors = region_query(neighbor, session_count, distance, eps)
                if len(neighbor_neighbors) >= args.min_samples:
                    for candidate in neighbor_neighbors:
                        if candidate not in seeds:
                            seeds.append(candidate)
            if labels[neighbor] == -1:
                labels[neighbor] = cluster_id
            seed_pos += 1
        cluster_id += 1

    cluster_map: dict[int, list[int]] = defaultdict(list)
    noise_indexes = []
    for index, label in enumerate(labels):
        if label == -1:
            noise_indexes.append(index)
        else:
            cluster_map[label].append(index)

    ordered_clusters = sorted(cluster_map.values(), key=len, reverse=True)
    ordered_representatives = [best_representative(cluster, distance) for cluster in ordered_clusters if cluster]
    return ordered_representatives, ordered_clusters, noise_indexes, eps_info


def cluster_members(
    sessions: list[dict[str, Any]],
    indexes: list[int],
    representative_index: int,
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    distance = build_distance_cache(sessions, args)
    candidates = sorted(
        (index for index in indexes if index != representative_index),
        key=lambda index: distance(index, representative_index),
    )
    output = []
    limit = args.cluster_member_limit if args.cluster_member_limit > 0 else len(candidates)
    for index in candidates[:limit]:
        output.append(
            {
                "session_id": sessions[index].get("session_id", ""),
                "distance_to_representative": round(distance(index, representative_index), 6),
                "length": len(sessions[index]["api_sequence"]),
                "trace": sessions[index]["api_sequence"],
            }
        )
    return output


def cluster_summary(
    sessions: list[dict[str, Any]],
    indexes: list[int],
    representative_index: int,
    args: argparse.Namespace,
) -> dict[str, Any]:
    cluster_sessions_list = [sessions[index] for index in indexes]
    size = len(indexes)
    return {
        "cluster_size": size,
        "representative_session_id": sessions[representative_index].get("session_id", ""),
        "representative_length": len(sessions[representative_index]["api_sequence"]),
        "representative_trace": sessions[representative_index]["api_sequence"],
        "length": {
            "min": min(len(session["api_sequence"]) for session in cluster_sessions_list),
            "max": max(len(session["api_sequence"]) for session in cluster_sessions_list),
            "avg": round(sum(len(session["api_sequence"]) for session in cluster_sessions_list) / size, 3),
        },
        "member_session_count": max(0, size - 1),
        "member_sessions": cluster_members(sessions, indexes, representative_index, args),
    }


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base_dir)
    input_dir = Path(args.input_dir) if args.input_dir else base_dir / "log_sequence"
    output_dir = Path(args.output_dir) if args.output_dir else base_dir / "process_mining"
    output_dir.mkdir(parents=True, exist_ok=True)

    files = discover_input_files(input_dir, args.bucket, args.site_id)
    if not files:
        raise FileNotFoundError(f"no input sequence files found in {input_dir}")
    sessions = []
    for session in iter_sessions(files):
        if args.site_id and session["site_id"] != args.site_id:
            continue
        sessions.append(session)
        if args.max_sessions > 0 and len(sessions) >= args.max_sessions:
            break
    if not sessions:
        raise RuntimeError("no sessions loaded")

    site_id = args.site_id or sessions[0]["site_id"]
    representatives, clusters, noise_indexes, eps_info = dbscan_sessions(sessions, args)
    filtered = [
        (representative, cluster)
        for representative, cluster in zip(representatives, clusters)
        if len(cluster) >= args.min_cluster_size
    ]
    selected_clusters = filtered[: args.top_clusters] if args.top_clusters > 0 else filtered
    cluster_payloads = [
        cluster_summary(sessions, cluster, representative, args)
        for representative, cluster in selected_clusters
    ]
    payload = {
        "site_id": site_id,
        "session_count": len(sessions),
        "clustered_session_count": sum(len(cluster) for cluster in clusters),
        "noise_session_count": len(noise_indexes),
        "source_files": [str(path) for path in files],
        "algorithm": {
            "name": "feature_vector_dbscan",
            "distance": "cosine_distance",
            "eps": eps_info["eps"],
            "eps_selection": eps_info,
            "min_samples": args.min_samples,
            "features": {
                "api_presence": args.api_presence_weight,
                "api_frequency": args.api_frequency_weight,
                "direct_transition": args.direct_transition_weight,
                "skip_transition": args.skip_transition_weight,
                "session_length": args.length_weight,
                "start_end_api": args.endpoint_weight,
            },
            "frequency_cap": args.frequency_cap,
            "max_skip_distance": args.max_skip_distance,
            "min_cluster_size": args.min_cluster_size,
            "cluster_member_limit": args.cluster_member_limit,
        },
        "noise_sessions": [
            {
                "session_id": sessions[index].get("session_id", ""),
                "length": len(sessions[index]["api_sequence"]),
                "trace": sessions[index]["api_sequence"],
            }
            for index in noise_indexes[: args.cluster_member_limit if args.cluster_member_limit > 0 else len(noise_indexes)]
        ],
        "clusters": cluster_payloads,
    }
    json_path = output_dir / f"site_{site_id}_business_session_clusters.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"site={site_id} sessions={len(sessions)} clusters={len(cluster_payloads)} "
        f"noise_sessions={len(noise_indexes)} eps={eps_info['eps']} eps_mode={eps_info['mode']} json={json_path}"
    )


if __name__ == "__main__":
    main()
