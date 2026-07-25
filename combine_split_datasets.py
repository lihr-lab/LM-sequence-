# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DATASETS = [
    ("train", "bacalarm", Path("train_data")),
    ("test", "humhub", Path("test_data")),
]


def load_sessions(path: Path, dataset: str, site_id: str) -> list[dict[str, Any]]:
    sessions = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(sessions, list):
        raise ValueError(f"{path} must contain a JSON array.")
    output = []
    for index, session in enumerate(sessions, start=1):
        if not isinstance(session, dict):
            continue
        item = dict(session)
        original_user_index = str(item.get("user_index", index))
        item["source_dataset"] = dataset
        item["source_site_id"] = site_id
        item["site_id"] = site_id
        item["original_user_index"] = original_user_index
        item["user_index"] = f"{dataset}_{site_id}_{original_user_index}"
        output.append(item)
    return output


def write_combined(kind: str, output_root: Path) -> int:
    combined: list[dict[str, Any]] = []
    for dataset, site_id, root in DATASETS:
        combined.extend(load_sessions(root / f"{kind}.json", dataset, site_id))
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / f"{kind}.json").write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(combined)


def main() -> int:
    output_root = Path("combined_data")
    normal_count = write_combined("normal", output_root)
    abnormal_count = write_combined("abnormal", output_root)
    print(f"{output_root / 'normal.json'} sessions={normal_count}")
    print(f"{output_root / 'abnormal.json'} sessions={abnormal_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
