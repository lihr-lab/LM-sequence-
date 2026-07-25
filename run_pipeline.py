# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


STEPS = ("preprocess", "openapi", "cluster", "review", "fol", "detect")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the API access-control mining pipeline.")
    parser.add_argument("--base-dir", default="artifacts")
    parser.add_argument("--dataset", default="train", choices=["train", "test"])
    parser.add_argument("--train-data-dir", default="train_data")
    parser.add_argument("--sites", nargs="+", default=None, help="Site ids to process. Defaults to auto-discovery from session_site_*.jsonl.")
    parser.add_argument("--start-at", choices=STEPS, default="preprocess")
    parser.add_argument("--stop-after", choices=STEPS, default="detect")
    parser.add_argument(
        "--api-key",
        default=os.getenv("AUTODL_API_KEY", os.getenv("LLM_API_KEY", "")),
    )
    parser.add_argument("--model", default=os.getenv("AUTODL_MODEL", os.getenv("LLM_MODEL", "GLM-5")))
    parser.add_argument("--llm-url", default=os.getenv("AUTODL_BASE_URL", os.getenv("LLM_URL", "https://www.autodl.art/api/v1")))
    parser.add_argument("--skip-llm", action="store_true", help="Generate profiles and clusters, but skip AutoDL calls.")
    parser.add_argument("--max-openapi-paths", type=int, default=50)
    parser.add_argument("--max-clusters", type=int, default=0)
    parser.add_argument("--cluster-max-sessions", type=int, default=0)
    parser.add_argument("--review-dry-run", action="store_true", help="Write review prompts without calling AutoDL.")
    return parser.parse_args()


def step_enabled(step: str, args: argparse.Namespace) -> bool:
    start = STEPS.index(args.start_at)
    stop = STEPS.index(args.stop_after)
    current = STEPS.index(step)
    return start <= current <= stop


def run(command: list[str]) -> None:
    print("\n$ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def require_api_key(args: argparse.Namespace, step: str) -> None:
    if args.skip_llm or args.review_dry_run:
        return
    if not args.api_key:
        raise SystemExit(
            f"{step} requires an AutoDL API key. Set AUTODL_API_KEY/LLM_API_KEY "
            "or pass --api-key, or rerun with --skip-llm/--review-dry-run."
        )


def discover_sites(log_sequence_dir: Path) -> list[str]:
    sites = []
    for path in sorted(log_sequence_dir.glob("session_site_*.jsonl")):
        site_id = path.stem.removeprefix("session_site_")
        if site_id and site_id not in sites:
            sites.append(site_id)
    if sites:
        return sites
    raise FileNotFoundError(
        f"no session_site_*.jsonl files found in {log_sequence_dir}; run preprocessing first or pass --sites explicitly"
    )


def main() -> int:
    args = parse_args()
    base_dir = Path(args.base_dir) / args.dataset
    request_dir = base_dir / "request_line_sequences"
    request_jsonl = request_dir / f"{args.dataset}_data_merged_request_lines.jsonl"
    log_sequence_dir = base_dir / "log_sequence"
    profile_dir = base_dir / "parameter_profiles"
    openapi_dir = base_dir / "API_document"

    if step_enabled("preprocess", args):
        run(
            [
                sys.executable,
                "preprocess/request_table_to_lines.py",
                str(args.train_data_dir),
                "--json",
                "--output-dir",
                str(request_dir),
                "--session-output-dir",
                str(log_sequence_dir),
                "--merged-name",
                f"{args.dataset}_data_merged",
            ]
        )

    sites = list(args.sites) if args.sites else discover_sites(log_sequence_dir)
    print(f"sites={' '.join(sites)}", flush=True)

    if step_enabled("openapi", args):
        profile_site_args = [["--site-id", site_id] for site_id in sites]
        for site_args in profile_site_args:
            command = [
                sys.executable,
                "parameter_profile.py",
                "--input",
                str(request_jsonl),
                "--output-dir",
                str(profile_dir),
                "--openapi-output-dir",
                str(openapi_dir),
                "--max-openapi-paths",
                str(args.max_openapi_paths),
                "--model",
                args.model,
                "--llm-url",
                args.llm_url,
            ]
            command.extend(site_args)
            if args.skip_llm:
                command.append("--no-generate-openapi-llm")
            else:
                require_api_key(args, "openapi")
                command.extend(["--api-key", args.api_key])
            run(command)

    if step_enabled("cluster", args):
        for site_id in sites:
            command = [
                sys.executable,
                "process_mining.py",
                "--base-dir",
                str(base_dir),
                "--input-dir",
                str(log_sequence_dir),
                "--site-id",
                site_id,
            ]
            if args.cluster_max_sessions > 0:
                command.extend(["--max-sessions", str(args.cluster_max_sessions)])
            run(command)

    if step_enabled("review", args):
        for site_id in sites:
            command = [
                sys.executable,
                "llm_cluster_review.py",
                "--base-dir",
                str(base_dir),
                "--site-id",
                site_id,
                "--openapi-file",
                str(openapi_dir / f"site_{site_id}_openapi.json"),
                "--model",
                args.model,
                "--llm-url",
                args.llm_url,
            ]
            if args.max_clusters > 0:
                command.extend(["--max-clusters", str(args.max_clusters)])
            if args.skip_llm or args.review_dry_run:
                command.append("--dry-run")
            else:
                require_api_key(args, "review")
                command.extend(["--api-key", args.api_key])
            run(command)

    if step_enabled("fol", args):
        for site_id in sites:
            run(
                [
                    sys.executable,
                    "fol_expression_generation.py",
                    "--base-dir",
                    str(base_dir),
                    "--site-id",
                    site_id,
                    "--openapi-file",
                    str(openapi_dir / f"site_{site_id}_openapi.json"),
                ]
            )

    if step_enabled("detect", args):
        for site_id in sites:
            run(
                [
                    sys.executable,
                    "fol_rule_detect.py",
                    "--base-dir",
                    str(base_dir),
                    "--input-dir",
                    str(log_sequence_dir),
                    "--site-id",
                    site_id,
                ]
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
