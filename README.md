# Security Scenario Mining and Rule Pipeline

This repository implements an end-to-end workflow for API business-session mining, LLM-assisted security scenario inference, FOL-style rule generation, rule replay detection, and false-positive-driven rule updates.

The current combined dataset is treated as one site:

```text
site_id = combined
```

## 1. Data Layout

Raw split-and-combined inputs:

```text
combined_data/normal.json
combined_data/abnormal.json
```

Preprocessed outputs for the combined single-site workflow:

```text
artifacts/combined_flat/normal/request_line_sequences/normal_request_lines.jsonl
artifacts/combined_flat/normal/log_sequence/session_site_combined.jsonl

artifacts/combined_flat/abnormal/request_line_sequences/abnormal_request_lines.jsonl
artifacts/combined_flat/abnormal/log_sequence/session_site_combined.jsonl
```

The normal file is used to mine normal business patterns and generate rules. The abnormal file is mainly used later for detection/evaluation.

## 2. Rebuild Normal/Abnormal Combined Data

If the split files need to be rebuilt from the original train/test JSON files:

```powershell
python split_normal_abnormal.py train_data\BACAlarm.json test_data\humhub.json
python combine_split_datasets.py
```

Expected combined counts:

```text
combined_data/normal.json    2428 sessions
combined_data/abnormal.json   269 sessions
```

## 3. Preprocess Combined Data

Normal data:

```powershell
python preprocess/request_table_to_lines.py combined_data\normal.json `
  --json `
  --site-id combined `
  --single-session-file session_site_combined.jsonl `
  --output-dir artifacts\combined_flat\normal\request_line_sequences `
  --session-output-dir artifacts\combined_flat\normal\log_sequence `
  --merged-name normal
```

Abnormal data:

```powershell
python preprocess/request_table_to_lines.py combined_data\abnormal.json `
  --json `
  --site-id combined `
  --single-session-file session_site_combined.jsonl `
  --output-dir artifacts\combined_flat\abnormal\request_line_sequences `
  --session-output-dir artifacts\combined_flat\abnormal\log_sequence `
  --merged-name abnormal
```

Key outputs:

```text
artifacts/combined_flat/normal/log_sequence/session_site_combined.jsonl
artifacts/combined_flat/abnormal/log_sequence/session_site_combined.jsonl
```

## 4. Build Parameter Profiles and OpenAPI Context

Generate parameter profiles from normal request records. This stage can also call the LLM to build OpenAPI documents.

Without LLM OpenAPI generation:

```powershell
python parameter_profile.py `
  --input artifacts\combined_flat\normal\request_line_sequences\normal_request_lines.jsonl `
  --site-id combined `
  --output-dir artifacts\combined_flat\normal\parameter_profiles `
  --openapi-output-dir artifacts\combined_flat\normal\API_document `
  --no-generate-openapi-llm
```

With LLM OpenAPI generation:

```powershell
python parameter_profile.py `
  --input artifacts\combined_flat\normal\request_line_sequences\normal_request_lines.jsonl `
  --site-id combined `
  --output-dir artifacts\combined_flat\normal\parameter_profiles `
  --openapi-output-dir artifacts\combined_flat\normal\API_document `
  --model GLM-5 `
  --llm-url https://www.autodl.art/api/v1 `
  --api-key <YOUR_API_KEY>
```

Expected files:

```text
artifacts/combined_flat/normal/parameter_profiles/site_combined_parameter_profile.json
artifacts/combined_flat/normal/API_document/site_combined_openapi.json
```

## 5. Cluster Normal Business Sessions

Run process mining on normal sessions:

```powershell
python process_mining.py `
  --base-dir artifacts\combined_flat\normal `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --site-id combined
```

Output:

```text
artifacts/combined_flat/normal/process_mining/site_combined_business_session_clusters.json
```

Cluster threshold behavior:

- `--eps 0.0` means automatic DBSCAN threshold selection.
- Auto mode uses k-distance elbow and clamps the value into `--eps-min` to `--eps-max`.
- Pass `--eps <value>` to force a manual threshold.

Example manual clustering threshold:

```powershell
python process_mining.py `
  --base-dir artifacts\combined_flat\normal `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --site-id combined `
  --eps 0.35
```

## 6. Infer Security Scenarios with LLM

Use the normal business clusters, parameter profile, and OpenAPI context to infer possible security scenarios:

```powershell
python llm_cluster_review.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --openapi-file artifacts\combined_flat\normal\API_document\site_combined_openapi.json `
  --parameter-profile-file artifacts\combined_flat\normal\parameter_profiles\site_combined_parameter_profile.json `
  --model GLM-5 `
  --llm-url https://www.autodl.art/api/v1 `
  --api-key <YOUR_API_KEY>
```

Dry run, only writing prompts:

```powershell
python llm_cluster_review.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --openapi-file artifacts\combined_flat\normal\API_document\site_combined_openapi.json `
  --parameter-profile-file artifacts\combined_flat\normal\parameter_profiles\site_combined_parameter_profile.json `
  --dry-run
```

Output:

```text
artifacts/combined_flat/normal/process_mining/llm_cluster_reviews/site_combined_cluster_review.json
```

## 7. Generate FOL Rules

Generate FOL-style detection rules from inferred security scenarios:

```powershell
python fol_expression_generation.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --review-file artifacts\combined_flat\normal\process_mining\llm_cluster_reviews\site_combined_cluster_review.json `
  --openapi-file artifacts\combined_flat\normal\API_document\site_combined_openapi.json `
  --parameter-profile-file artifacts\combined_flat\normal\parameter_profiles\site_combined_parameter_profile.json
```

Output:

```text
artifacts/combined_flat/normal/fol_expressions/site_combined_fol_expressions.json
artifacts/combined_flat/normal/fol_expressions/site_combined_fol_logic_expressions.md
```

Important parameter-filtering behavior:

- Before rule generation, parameters are checked against the parameter profile.
- Cross-API context binding is kept only when the source API and target API contain a real, same-name parameter relationship.
- If a target parameter exists only in the target API, the rule is downgraded to target-side value switching/enumeration detection.
- This prevents false context bindings like `cguid -> contentId`.

## 8. Replay Rules on Normal Data

Use this to estimate false positives on normal sessions:

```powershell
python fol_rule_detect.py `
  --base-dir artifacts\combined_flat\normal `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --site-id combined `
  --fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions.json `
  --output-dir artifacts\combined_flat\normal\fol_rule_violations
```

Output:

```text
artifacts/combined_flat/normal/fol_rule_violations/site_combined_fol_rule_violations.json
```

## 9. Replay Rules on Abnormal Data

Use the rules generated from normal data, then replay them on abnormal sessions:

```powershell
python fol_rule_detect.py `
  --base-dir artifacts\combined_flat\abnormal `
  --input-dir artifacts\combined_flat\abnormal\log_sequence `
  --site-id combined `
  --fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions.json `
  --output-dir artifacts\combined_flat\abnormal\fol_rule_violations
```

Output:

```text
artifacts/combined_flat/abnormal/fol_rule_violations/site_combined_fol_rule_violations.json
```

## 10. Update Rules from False Positives

The update agent replays rules on normal sessions, asks the LLM to analyze false-positive causes per rule, proposes rule changes, verifies every candidate by replay, and only accepts candidates that reduce false positives.

Update all noisy rules:

```powershell
python rule_update_agent.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions.json `
  --target-rule-fp-rate 0.1 `
  --max-evidence-sessions-per-rule 5 `
  --model GLM-5 `
  --llm-url https://www.autodl.art/api/v1 `
  --api-key <YOUR_API_KEY>
```

Update one specific rule:

```powershell
python rule_update_agent.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions.json `
  --target-fol-id FOL-C2-S2 `
  --target-rule-fp-rate 0.1 `
  --max-evidence-sessions-per-rule 5 `
  --model GLM-5 `
  --llm-url https://www.autodl.art/api/v1 `
  --api-key <YOUR_API_KEY>
```

Dry run for prompt inspection:

```powershell
python rule_update_agent.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions.json `
  --target-fol-id FOL-C2-S2 `
  --dry-run
```

Outputs:

```text
artifacts/combined_flat/normal/fol_rule_updates/site_combined_rule_update_report.json
artifacts/combined_flat/normal/fol_rule_updates/prompts/
artifacts/combined_flat/normal/fol_expressions/site_combined_fol_expressions_next.json
```

Update behavior:

- Each rule is analyzed independently.
- `false_positive_reason` must explain why the rule caused false positives.
- `modified_scope` changes the executable detector behavior.
- `modified_expression` can update the displayed FOL expression.
- `replace_expression` can include both `modified_scope` and `modified_expression`.
- A candidate is written to `site_combined_fol_expressions_next.json` only if replay proves that it reduces false positives.

## 11. Merge Verified Updates

After update verification, merge the accepted updates into a final rule file:

```powershell
python rule_merge_agent.py `
  --base-dir artifacts\combined_flat\normal `
  --site-id combined `
  --base-fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions.json `
  --updated-fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions_next.json `
  --output-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions_merged.json
```

Then replay the merged rules:

```powershell
python fol_rule_detect.py `
  --base-dir artifacts\combined_flat\normal `
  --input-dir artifacts\combined_flat\normal\log_sequence `
  --site-id combined `
  --fol-file artifacts\combined_flat\normal\fol_expressions\site_combined_fol_expressions_merged.json `
  --output-dir artifacts\combined_flat\normal\fol_rule_violations_merged
```

## 12. Suggested End-to-End Order

Recommended full workflow:

```text
1. split_normal_abnormal.py
2. combine_split_datasets.py
3. preprocess/request_table_to_lines.py for normal and abnormal
4. parameter_profile.py on normal request JSONL
5. process_mining.py on normal sessions
6. llm_cluster_review.py to infer security scenarios
7. fol_expression_generation.py to generate FOL rules
8. fol_rule_detect.py on normal sessions to measure false positives
9. rule_update_agent.py to reduce false positives
10. rule_merge_agent.py to produce merged rules
11. fol_rule_detect.py on abnormal sessions to evaluate detection coverage
```

## 13. Quick Commands

Minimal normal-data rule generation path after preprocessing:

```powershell
python parameter_profile.py --input artifacts\combined_flat\normal\request_line_sequences\normal_request_lines.jsonl --site-id combined --output-dir artifacts\combined_flat\normal\parameter_profiles --openapi-output-dir artifacts\combined_flat\normal\API_document --no-generate-openapi-llm

python process_mining.py --base-dir artifacts\combined_flat\normal --input-dir artifacts\combined_flat\normal\log_sequence --site-id combined

python llm_cluster_review.py --base-dir artifacts\combined_flat\normal --site-id combined --openapi-file artifacts\combined_flat\normal\API_document\site_combined_openapi.json --parameter-profile-file artifacts\combined_flat\normal\parameter_profiles\site_combined_parameter_profile.json --dry-run

python fol_expression_generation.py --base-dir artifacts\combined_flat\normal --site-id combined
```

Replace `--dry-run` with `--api-key <YOUR_API_KEY>` when you want real LLM security scenario inference.
