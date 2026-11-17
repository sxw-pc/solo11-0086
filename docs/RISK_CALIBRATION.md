# 风险校准与自动交付门槛

## 1. 业务风险定义

批量解码的风险不是“编码标签猜中比例”，而是**自动交付了错误的 UTF-8 文本**。
`scorer.choose_best` 的置信度只是单文件启发式分数，没有经过独立标注样本校准。
本模块在完全离线的条件下，用合成标注响应回答：“达到何种证据才允许自动交付？”

风险统计的单位是**来源组**（同一原始网页的多个编码/声明变体），不是组内变体。
同组变体共享同一错误机制，当作独立样本会虚增可信度。

## 2. 两类发布合同

| 合同 | 自动交付条件 | 错误定义 |
| --- | --- | --- |
| `forensic_archive` 取证归档 | 文本正确 **且** 规范编码标签唯一确定 | 错误文本，或标签不确定（即使候选文本相同） |
| `search_index` 搜索索引 | 仅要求交付文本正确 | 错误文本；标签不确定只记录“编码归因未定” |

- 纯 ASCII 字节在 utf-8、gb18030、big5 等候选下严格解码得到同一文本：搜索索引
  合同可以自动交付并记录 `encoding_attribution_unresolved`；取证归档合同必须拒判。
- 两种编码都严格可解但产出不同文本（如 `a2ad` 在 GB18030/Big5 下）时，即使统计
  评分选出了获胜者，也要由独立验证的风险上界决定，不能因“分数接近且有一个正确
  标签”的样本冲淡错误文本风险。

## 3. 模块

| 模块 | 职责 |
| --- | --- |
| `riskstats.py` | 组级二项风险的单侧 95% 精确上界（Clopper-Pearson，纯标准库） |
| `calibration.py` | 标注加载与校验、来源组拆分、确定性特征、门槛网格、校准与工件 |
| `gate.py` | 校准工件在新本地响应上的应用，输出交付结论与警告 |

门槛输入全部无标注、可复核：候选评分与置信度（`scorer`）、声明可靠性（声明编码
能否严格解码、是否与统计获胜者一致）、严格解码成败、文本等价类（不同严格解码
文本的稳定哈希）。

## 4. 标注文件与来源组规则

标注 JSON 含 `samples` 数组，每条样本提供：

- `sample_id`、`source_group`（来源组 ID）
- `raw_base64`：原始响应字节
- `expected_text`：期望 Unicode 文本
- `allowed_encodings`：允许的规范编码集合（每个都必须能严格解码出期望文本）
- `declared_encoding`：该变体的声明编码（可为空）

加载时拒绝：

1. 重复 `sample_id` 或组内完全重复的变体；
2. 冲突标注（同组期望文本或允许编码集合不一致、同组原始字节不同）；
3. 训练/验证泄漏（同一原始字节出现在多个来源组）；
4. 允许编码无法严格解码或解码文本不等于期望文本。

## 5. 拆分、门槛网格与精确上界

- `split_groups` 按来源组做确定性哈希拆分（默认 70% 定门槛 / 30% 独立验证），
  同组变体绝不跨集；两个集合都为空时直接报错。
- 门槛网格是有限候选：定门槛集观察到的置信度分位点 × 是否要求可靠声明 ×
  是否要求声明与获胜者一致 ×（取证合同）是否要求标签唯一。
- 对每条规则按来源组统计：覆盖率 = 覆盖组数 / 总组数；错误率上界使用
  `riskstats.clopper_pearson_upper(error_groups, covered_groups, 0.95)`。
- **零错误不等于零风险**：n 个零错误组的上界为 `1 - 0.05**(1/n)`；n=0 时上界
  为 1.0。上界仍超过合同预算（默认 0.05）时必须拒判。

## 6. 选择、独立验证与推广

1. 仅在定门槛集上选择“精确上界满足预算且覆盖率最大”的规则（并列时优先不依赖
   声明、约束更严格者）。
2. 用完全未参与选择的验证来源组计算独立上界。
3. 验证集无覆盖或独立上界超过预算 → 不推广，应用端对该合同一律拒判
   （`no_promoted_rule_for_contract`）。

校准工件绑定 `rule_version`、候选编码集合与 `annotation_digest`。规则版本或
候选集合不匹配时 fail-closed（`rule_binding_mismatch`）；规则或标注变化必须
重新校准，不得沿用旧统计。

## 7. 流水线应用

```bash
python -m decodebench calibrate \
  --config configs/demo.yml --annotations labels.json --out calibration.json
python -m decodebench pipeline --config configs/demo.yml \
  --gate-artifact calibration.json --gate-contract search_index
```

启用门槛后，每个文件仍保留原始 resolver 的 encoding 决策与全部诊断证据，另在
manifest 的 `delivery` 块列出：自动交付/拒判、文本等价类、标签确定性、编码归因、
拒判原因、风险预算与独立验证上界。拒判文件：

- 不调用转码、不写 UTF-8 产物，`transcode` 为 `null`，绝不伪装成成功；
- 不覆盖任何既有转码文件或原始响应；
- 产生高严重度警告 `W_RISK_GATE_REJECTED`；
- 自动交付但归因未定时产生低严重度 `W_ENCODING_ATTRIBUTION_UNRESOLVED`。
