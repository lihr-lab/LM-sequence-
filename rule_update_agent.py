# -*- coding: utf-8 -*-
from __future__ import annotations

from update_agent import parse_args, run_rule_update


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
        f"target_rule_fp_rate={float(report.get('target_rule_fp_rate') or 0.0):.4f} "
        f"target_rule_min_f1={float(report.get('target_rule_min_f1') or 0.0):.4f} "
        f"accepted_changes={report.get('accepted_change_count', 0)} "
        f"stopped={report.get('stopped_reason', '')} "
        f"next_rules_file={report.get('next_rules_file', '')}"
    )


if __name__ == "__main__":
    main()
