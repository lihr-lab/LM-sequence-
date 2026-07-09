# WAF Unsupervised Detection

面向 WAF / HTTP 访问日志的无监督异常检测项目。项目将日志清洗、特征工程、无监督模型训练、检测评估和误报漏报分析串成一套本地 Python 工作流，适合用于从正常流量中学习行为分布，并在检测集上识别疑似攻击或异常请求。

## 功能特性

- 支持 `IsolationForest`、`One-Class SVM`、`Autoencoder` 三类无监督模型。
- 内置 WAF 领域特征工程：URL、query、header、body、HTTP 解析字段、规则命中模式、event_type 相关特征等。
- 训练和检测阶段自动过滤二进制乱码、协议不合规、空 path 等低质量样本。
- 支持带标签检测集评估，输出混淆矩阵、Precision、Recall、F1 等指标。
- 支持检测阈值扫描，辅助选择 `decision_threshold`。
- 提供日志切分与标注脚本，可将混合 WAF 日志拆分为 access/security/unknown，并按 `request_id` 生成带标签数据。
- 提供误报、漏报样本导出和特征分析脚本，方便迭代规则和阈值。

## 项目结构

```text
.
├── waf_unsupervised/
│   ├── config.py              # 数据路径、模型类型和默认参数
│   ├── train.py               # 模型训练入口
│   ├── detect.py              # 模型检测入口
│   ├── model.py               # 特征流水线 + 模型封装
│   ├── features.py            # WAF/HTTP 特征工程
│   ├── data_cleaning.py       # 数据清洗规则
│   ├── autoencoder.py         # PyTorch 自编码器异常检测器
│   └── rule_engine.py         # 规则层辅助逻辑
├── waf_log_pipeline.py        # 混合 WAF 日志切分、匹配和标注
├── analyze_threshold.py
├── analyze_event_types.py
├── llm_fp.py
├── filter_fp.py
├── filter_and_detect_events.py
├── filter_samples_by_event_type.py
├── models/                    # 已训练模型输出目录
├── data/                      # 训练/检测数据目录
├── artifacts/output/          # 检测结果、分析结果输出目录
└── requirements.txt
```

## 环境准备

建议使用 Python 3.10+。

```bash
pip install -r requirements.txt
```

如果需要 GPU 版 PyTorch，请按本机 CUDA 版本参考 PyTorch 官方安装命令。若希望用 GPU 加速 One-Class SVM，可额外安装与本机 CUDA 匹配的 `thundersvm`。

## 数据准备


训练和检测脚本支持 JSON 或 CSV。推荐每条记录包含尽可能完整的 HTTP/WAF 字段，例如：

```json
{
  "timestamp": "2026-05-24T12:00:00+08:00",
  "method": "GET",
  "uri": "/api/search?q=test",
  "http": "GET /api/search?q=test HTTP/1.1...",
  "http_parsed": {
    "path": "/api/search",
    "query": "q=test"
  },
  "event_type": "access",
  "label": 0
}
```

字段不必完全一致，特征工程会尽量从已有字段中解析 URL、path、query、HTTP 原文和规则命中信息。但数据越完整，模型效果通常越稳定。

## 从原始 WAF 日志生成标注数据

如果手头是 access/security 混合日志，可先使用 `waf_log_pipeline.py` 按 tag 切分，再根据 `request_id` 匹配 security 命中结果生成带标签 access 数据。

```bash
python waf_log_pipeline.py path\to\mixed_waf.log ^
  --start-time 2026-05-24T00:00:00+08:00 ^
  --end-time 2026-05-25T00:00:00+08:00 ^
  --labeled-output data\train.jsonl
```

脚本会识别：

- `tag:waf_log_webaccess`
- `tag:waf_log_websec`
- `request_id:...`
- `event_type:...`

匹配到 security 记录的 access 样本会被标为异常，未匹配样本会被标为正常。

## 训练模型

从项目根目录运行模块方式命令：

```bash
python -m waf_unsupervised.train --model isolation_forest --train-path data\train.json
```

训练 One-Class SVM：

```bash
python -m waf_unsupervised.train ^
  --model one_class_svm ^
  --train-path data\train.json ^
  --ocsvm-nu 0.05
```

训练自编码器：

```bash
python -m waf_unsupervised.train ^
  --model autoencoder ^
  --train-path data\train.json ^
  --ae-epochs 30 ^
  --ae-batch-size 2048
```

常用参数：

- `--max-train-samples N`：限制训练样本量，便于快速实验。
- `--augment-normal-detect-path PATH`：从检测集补充正常样本。
- `--augment-normal-count N`：追加 `label=0` 的正常样本数量，默认 `50000`。
- `--feature-jobs N`：特征提取并行进程数。
- `--keep-binary-noise`：保留疑似二进制乱码样本。
- `--keep-noncompliant-protocol`：保留协议不合规样本。
- `--decision-threshold VALUE`：写入模型配置的默认判定阈值。

训练完成后，模型会保存到 `models/`：

```text
models/isolation_forest.joblib
models/one_class_svm.joblib
models/autoencoder.joblib
```

## 执行检测

```bash
python -m waf_unsupervised.detect ^
  --model one_class_svm ^
  --detect-path data\detection_1.json ^
  --pred-out artifacts\output\detect_predictions.json
```

如果检测数据包含 `label` 列，脚本会打印混淆矩阵和分类指标。

常用参数：

- `--decision-threshold VALUE`：覆盖模型默认阈值。分数越小越异常，判断逻辑为 `score < threshold`。
- `--optimize-threshold-f1`：在带标签检测集上自动搜索异常类 F1 最优阈值。
- `--event-type TYPE`：只检测指定 `event_type`。
- `--max-detect-samples N`：按清洗/过滤后的出现顺序截取前 N 条检测。
- `--sample-out PATH`：保存截取后的检测样本，便于后续 FP/FN 导出直接对齐。
- `--append-event-type TYPE` / `--append-event-count N`：向检测集追加某类事件样本。
- `--keep-binary-noise`、`--keep-noncompliant-protocol`：关闭默认清洗过滤。

输出结果默认写入：

```text
artifacts/output/detect_predictions.json
```

## 阈值分析

在带标签评估集上扫描阈值，寻找 F1、Youden J、Accuracy 等指标表现较好的 `decision_threshold`。

```bash
python analyze_decision_threshold.py ^
  --model one_class_svm ^
  --eval-path data\detection_1.json ^
  --label-column label ^
  --mode quantile ^
  --steps 101 ^
  --optimize f1 ^
  --csv-out artifacts\output\threshold_sweep.csv ^
  --json-summary artifacts\output\threshold_summary.json
```

阈值解释：

- 模型输出 `decision_function` 分数。
- 分数越小越异常。
- `score < decision_threshold` 判定为异常。
- 降低阈值通常会减少误报，但也可能增加漏报。
- 提高阈值通常会提高召回，但也可能增加误报。

## 误报漏报分析

导出漏报样本：

```bash
python export_detection_cases.py ^
  --data data\detection_1.json ^
  --pred artifacts\output\detect_predictions.json ^
  --case_type fn ^
  --max-detect-samples 0 ^
  --limit 1000 ^
  --out artifacts\output\fn_samples.json
```

导出误报样本：

```bash
python export_detection_cases.py ^
  --data data\detection_1.json ^
  --pred artifacts\output\detect_predictions.json ^
  --case_type fp ^
  --max-detect-samples 0 ^
  --limit 1000 ^
  --out artifacts\output\fp_samples.json
```

如果检测时使用了 `--max-detect-samples N`，导出和特征分析也传同样的 `--max-detect-samples N`。如果检测时同时指定了 `--sample-out`，也可以把该文件作为 `--data` 并加 `--data-already-aligned`，这样最不容易错位。

进一步可使用：

- `analyze_fn_fp_features.py`：分析误报/漏报样本特征；支持 `--max-detect-samples` 与检测阶段数据上限对齐。
- `analyze_detection_cases_with_llm.py`：调用本地 Ollama/LLM 对导出的误报/漏报样本做原因分析。
- `analyze_event_types.py`：统计不同 `event_type` 的样本分布和检测表现。
- `filter_samples_by_event_type.py`：按事件类型筛选样本。
- `filter_and_detect_events.py`：筛选后直接检测指定事件类型。

如果服务器上有 Ollama 模型，并已通过 SSH 隧道映射到本机：

```bash
ssh -L 11434:localhost:11434 debian@10.50.104.101
```

可以让 `deepseek-r1:14b` 分析误报原因：

```bash
python analyze_detection_cases_with_llm.py ^
  --cases artifacts\output\fp_samples.json ^
  --bucket fp ^
  --limit 20 ^
  --batch-size 5 ^
  --model deepseek-r1:14b ^
  --endpoint http://127.0.0.1:11434 ^
  --out artifacts\output\llm_fp_analysis.md
```

## 推荐工作流

1. 准备或生成 `data/train.json` 和 `data/detection_1.json`。
2. 使用正常流量或低污染样本训练基线模型。
3. 在带标签检测集上运行检测，查看混淆矩阵。
4. 使用 `analyze_threshold.py` 扫描阈值。
5. 根据业务偏好选择高召回或低误报阈值。
6. 导出 FP/FN 样本，分析集中错误类型。
7. 调整清洗逻辑、规则特征、训练样本和阈值后重新训练。

## 性能建议

- 大数据量下 `One-Class SVM` 训练较慢，可先用 `--max-train-samples` 抽样验证。
- `IsolationForest` 通常训练更快，适合作为初始基线。
- `Autoencoder` 适合数据量较大、特征分布较复杂的场景。
- 可通过环境变量或参数控制特征并行度：
顺序检测前两万条数据的结果
检测指标:
  Accuracy  (准确率):  0.9779 (97.79%)
  Precision (精确率):  0.9259 (92.59%)
  Recall    (召回率):  0.9978 (99.78%)
  F1-Score  (F1分数):  0.9605