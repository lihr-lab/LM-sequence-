# -*- coding: utf-8 -*-
from __future__ import annotations

from update_agent import parse_merge_args, run_rule_merge


def main() -> None:
    args = parse_merge_args()
    report = run_rule_merge(args)
    summary = report.get("summary", {})
    print(
        f"site={args.site_id} "
        f"base_rules={summary.get('base_rule_count', 0)} "
        f"updated_rules={summary.get('updated_rule_count', 0)} "
        f"merged_rules={summary.get('merged_rule_count', 0)} "
        f"replaced={len(summary.get('replaced_fol_ids', []))} "
        f"merged_file={report.get('merged_rules_file', '')}"
    )


if __name__ == "__main__":
    main()
