# Evaluation Report（评估报告）

## 1. 实验目的

- 验证 `Qwen2-0.5B-Instruct + LoRA` 在 PHP Webshell 二分类任务上的可用性
- 验证“模型分数 + 静态规则融合”对于市面上存在的waf检测不到的情况下能否复测到webshell的可能性。

## 2. 实验设置

- 数据集：`nbuser32/PHP-Webshell-Dataset`
- 本地切分：`train/val/test = 8/1/1`（分层切分，`seed=42`）
- 训练硬件：Colab Tesla T4
- 训练参数：
  - `lr=2e-4`
  - `batch=16`
  - `grad_acc=1`
  - `epoch=1`
  - `max_len=256`
  - `optimizer=adamw_torch`

## 3. 主结果（模型 only，test split）

说明：该 `test split` 来自公开数据集分层切分，包含 benign 与 webshell 两类样本。

| 指标      |       值 |
| --------- | -------: |
| Accuracy  | 0.973571 |
| Precision | 0.993016 |
| Recall    | 0.957746 |
| F1        | 0.975062 |
| Loss      | 0.086890 |

按上述指标反推的混淆矩阵（唯一整数解，`N=3027`）：

- TP = 1564
- FP = 11
- FN = 69
- TN = 1383

## 4. 融合策略结果（`tools/php_fusion_scan.csv`）

样本总量：`42`

分层结果：

- `high`：1
- `review`：40
- `low`：1

动作结果：

- `block`：1
- `manual_review`：40
- `allow`：1

分数统计：

- `model_prob`：min=0.988281, max=1.000000, mean=0.999686
- `rule_prob`：min=0.120000, max=0.800000, mean=0.545714
- `fused_score`：min=0.684383, max=1.000000, mean=0.842485

## 5. 阈值参数

- `W_MODEL = 0.65`
- `W_RULE = 0.35`
- `TH_REVIEW = 0.78`
- `TH_HIGH = 0.95`

## 6. 当前边界与结论解释

- 已有“公开数据集上的严格 test 指标”，且该 test 含 benign 与 webshell。
- 42 文件融合扫描集主要用于“策略行为观察”（高危/复核/放行分层），不等价于生产分布评测。
