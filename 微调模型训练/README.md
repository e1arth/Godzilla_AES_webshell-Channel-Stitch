# PHP Webshell 对抗检测 研究
本文件记录了一个用于 PHP Webshell 对抗检测的实用工作流：

首先在 PHP Webshell 数据集上微调 Qwen/Qwen2-0.5B-Instruct 模型
对PHP文件运行模型推理
将模型评分与静态规则相融合，以减少生产环境中的误报，达到真实检测时对webshell的分析，以便研究可以绕过检测的webshell

# 为什么建立此项目?

纯模型分类对于分析来说并不实际，同时要对phpwebshell进行全面的验证，也要避免模型过于敏感自动联想任何高危或可执行的函数。

主要是为了验证channel_stitch_AES.py生成的webshell是否可通过AI检测.
  
本项目采用“模型 + 规则融合”策略，在保持召回能力的同时，用分级处置控制误报。

### 方法
当前的方法保持了强大的Recall，同时增加了基于规则的控制，以便做出更安全的决策：

high（高风险）：拦截（block）
review（审查风险）：人工审查（manual review）
low（低风险）：放行（allow）

----
1. 二分类微调：`webshell` vs `benign`
2. 模型输出：`model_prob`（恶意概率）
3. 静态信号抽取：`sink`、`taint`、`decode`、`network`、`fileop`、`stealth`
4. 融合打分：
------

### 核心理念
使用 LoRA 在 Webshell 与正常（benign）标签上训练一个轻量级分类器。
保留模型输出的概率值（model_prob）。
从代码中提取静态信号（如：危险函数 sink、污点 taint、解码 decode、网络 network、文件操作 fileop、隐藏特征 stealth）。

## 构建融合评分：

Plaintext
fused_score = w_model * model_prob + w_rule * rule_prob
1. 二分类微调：`webshell` vs `benign`
2. 模型输出：`model_prob`（恶意概率）
3. 静态信号抽取：`sink`、`taint`、`decode`、`network`、`fileop`、`stealth`
4. 融合打分：

使用到的工具/
- `tools/generate_php_fixture_dataset_v3.py`  
  生成用于检测基准评估的非可执行仿真样本
- `tools/generate_callback_chain_fixture.py`  
  生成 `callback_chain_sim` 样本
- `tools/generate_channel_stitch_fixture.py`  
  生成 `channel_stitch_sim` 样本
- `tools/generate_crypto_reflect_fixture.py`  
  生成 `crypto_reflect_c2_sim` 样本
  

使用到的数据集/
- `[nbuser32/PHP-Webshell-Dataset](https://huggingface.co/datasets/nbuser32/PHP-Webshell-Dataset)`  

#### 典型
在 Colab 中训练适配器（adapter）：

colab-T4:

GPU-16G/CUDA核心数-2560/显存带宽-320GB/s/FP32-8.1 TFLOPS/FP16-65 TFLOPS/Tensor Cores	320/

基础模型：Qwen/Qwen2-0.5B-Instruct

数据集：nbuser32/PHP-Webshell-Dataset

对于.php文件进行验证。

导出包含以下字段的 CSV 文件：

model_prob
rule_prob
fused_score
prediction
risk_level
action

在混合验证集（webshell + 真实的正常代码）上调整阈值。

## 数据统计

- 总样本数：`30,270`
- 全量标签分布：
  - `webshell(1)=16,324`（53.928%）
  - `benign(0)=13,946`（46.072%）
- 本地切分规模：
  - `train=24,216`
  - `val=3,027`
  - `test=3,027`
- 说明：采用分层切分，子集标签比例与全量接近

## 决策策略
fused_score >= 0.95 -> webshell，high，block

0.78 <= fused_score < 0.95 -> suspicious，review，manual_review

< 0.78 -> benign，low，allow


## 后续想法(最近没时间，等有空)
添加具有迷惑性的正常样本，同时提高模型的过度敏感性来试试。
使用类似生产环境的流量来校准阈值。
添加持续集成检查，用于监控精确率、recall和FPR的回归情况。


## 边界

- Add hard-benign samples to reduce over-sensitivity.
- Calibrate thresholds with production-like traffic.
- Add CI checks for regression on precision/recall/FPR.

-----
- 本项目仅用于授权安全研究与防御测试
- 不应将样本直接用于任何未授权环境
- 生产落地需保留审计日志与人工复核通道

## Safety Notes
- 数据集卡：`docs/DATASET_CARD.zh-CN.md`
- 模型卡：`docs/MODEL_CARD.zh-CN.md`
- 评估报告：`docs/EVALUATION_REPORT_TEMPLATE.zh-CN.md`


---  

## 2026-03-04

### Best regards,

#### by e0art1h
