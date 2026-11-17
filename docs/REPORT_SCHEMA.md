# 输出与 Schema 说明

## 1. 输出位置

默认配置 `configs/demo.yml` 的路径相对于配置文件所在目录解析：

```text
out/
  manifest.json
  decodebench.sqlite3
  reports/
    report.json
    report.md
    report.html
  transcoded/
    <与扫描根相同的相对目录结构>
```

可通过 `output.dir`、`output.manifest`、`output.reports_dir`、`output.transcode_dir`、`output.database` 覆盖。输出目录不得位于扫描根目录内。

## 2. `manifest.json`

顶层字段按以下固定顺序构造：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `schema_version` | string | 当前为 `1.0` |
| `project` | string | 固定为 `decodebench` |
| `rule_version` | string | 规则/检测器版本 |
| `generated_at` | string | `--now` 归一化后的 UTC ISO-8601 |
| `config_fingerprint` | string | 合并默认值后配置的 SHA-256 |
| `scan_root` | string | POSIX 风格的扫描根绝对路径 |
| `config_snapshot` | object | 合并默认值后的 YAML 配置快照 |
| `summary` | object | 批次汇总 |
| `files` | array | 按 `rel_path` 升序的文件条目 |

### 2.1 文件条目

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `rel_path` | string | 相对扫描根的 POSIX 路径 |
| `source_size` | int | 源文件字节数 |
| `source_sha256` | string | 源文件 SHA-256 |
| `source_mtime` | string | UTC 秒精度修改时间 |
| `sidecar` | object | `path`、`present`、`error` |
| `bom` | object/null | `encoding`、`length`、`hex` |
| `evidence` | array | 编码证据链，顺序固定 |
| `statistical_candidates` | array | 所有候选的严格解码与评分 |
| `decision` | object | 最终决策、置信度、方法、冲突、错误码 |
| `transcode` | object | 输出路径、源/输出哈希、重写、替换信息 |
| `mojibake` | object | 风险等级、发现列表、建议 |
| `warnings` | array | 已排序的警告 |
| `warning_count` | int | 警告条数 |

### 2.2 evidence

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `source` | string | `bom`、`http_header`、`xml_declaration`、`meta_charset`、`fallback`、`statistical` |
| `declared` | string/null | 声明或候选编码名 |
| `offset` | int/null | 源字节偏移；统计/HTTP/fallback 通常为 null |
| `line` | int/null | 声明所在行；统计/HTTP/fallback 通常为 null |
| `matches_decision` | bool/null | 声明的规范编码是否与最终决策兼容 |
| `note` | string | 可读证据说明 |

### 2.3 statistical_candidates

每项包含 `encoding`、`success`、`score`、`decoded_chars`、`replacement_count`、`control_ratio`、`printable_ratio`、`cjk_ratio`、`latin_ratio`、`unassigned_ratio`、`private_ratio`、`ascii_ratio`、`error`。所有比例固定六位小数，失败候选 `score` 为 `0.0`。

### 2.4 decision

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `encoding` | string | 规范编码名 |
| `confidence` | float | 0..1，六位小数 |
| `method` | string | `bom`、`http_header`、`xml_declaration`、`meta_charset`、`fallback`、`statistical`、`unresolved` |
| `reason` | string | 可读裁决原因 |
| `error_codes` | array | 稳定错误码，按产生顺序 |
| `conflicts` | array | 冲突说明，空数组代表无冲突 |

### 2.5 transcode

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `success` | bool | 是否成功写出 UTF-8 |
| `encoding` | string | 使用的编码 |
| `errors` | string | `strict` 或 `replace` |
| `output_rel_path` | string/null | 输出相对路径 |
| `source_sha256` | string | 转码前源 SHA-256 |
| `output_sha256` | string/null | 输出 SHA-256 |
| `bytes_written` | int | UTF-8 输出字节数 |
| `decoded_chars` | int | 解码字符数 |
| `replacement_count` | int | 输出中的 U+FFFD 数量 |
| `replacement_used` | bool | 是否发生字符替换 |
| `bom_removed` | bool | 是否移除 BOM |
| `rewrites` | array | charset 声明重写记录 |
| `error` | string/null | 失败原因 |

`rewrites` 每项包含 `kind`、`original`、`new`、`line`、`offset`、`position_basis`、`end_offset`。偏移以去除 BOM 后的解码源文本字符为单位。

### 2.6 mojibake

`level` 为 `none`、`low`、`medium`、`high`。`findings` 每项包含 `code`、`severity`、`message`、`line`、`column`、`offset`、`snippet`。`recommendation` 只给建议，不包含自动修复动作。

### 2.7 summary

包含 `files_total`、`conflict_files`、`transcode_success`、`transcode_failed`、`files_with_warnings`、`warnings_total`、`warning_distribution`、`method_distribution`、`risk_distribution`。

`warning_distribution` 按错误码升序，每项为 `code`、`count`、`severity`。`conflict_files` 按“拥有非空 conflicts 的文件数”统计，而不是冲突消息条数。

## 3. `reports/report.json`

报告是面向复核的稳定摘要，不是 manifest 的复制：

| 字段 | 含义 |
| --- | --- |
| `schema_version` / `project` / `generated_at` / `rule_version` | 与 manifest 一致 |
| `config_fingerprint` | 配置指纹 |
| `batch_id` | 确定性批次 ID |
| `scan_root` | 扫描根 |
| `summary` | manifest 汇总 |
| `warning_distribution` | 警告分布 |
| `files` | 每文件决策摘要，按路径升序 |
| `ledger` | SQLite 台账摘要 |

每文件摘要包含 `rel_path`、`encoding`、`confidence`、`method`、`conflict`、`error_codes`、`transcode_success`、`output_rel_path`、`output_sha256`、`risk_level`、`warning_count`、`warning_codes`。

`report.md` 与 `report.html` 使用同一数据源。HTML 内联 CSS，不包含外链、远程脚本、远程字体或图片；Markdown 使用固定标题和表格顺序。

## 4. SQLite 表

数据库路径由 `output.database` 指定。所有时间均为传入的 `--now`（UTC ISO-8601）。

### batches

`batch_id`（确定性 ID）、`batch_key`（唯一）、`input_root`、`rule_version`、`config_fingerprint`、`created_at`、`updated_at`、`run_count`、`status`、`file_count`、`conflict_count`、`transcoded_count`。

重复运行同一批次时更新该行：`run_count + 1`，`status = reprocessed`。`created_at` 保留第一次运行时间。

### files

`id`、`batch_id`、`idempotency_key`、`rel_path`、`source_size`、`source_sha256`、`source_mtime`、`final_encoding`、`confidence`、`method`、`conflict_count`、`warning_count`、`risk_level`、`transcode_success`、`output_rel_path`、`output_sha256`、`replacement_used`、`created_at`、`updated_at`。

唯一约束：`(idempotency_key, rel_path)`。`idempotency_key = <source_sha256>:<rule_version>:<config_fingerprint>`。

### evidence

`id`、`file_id`、`ordinal`、`source`、`declared`、`byte_offset`、`line_number`、`matches_decision`、`note`。`matches_decision` 使用 0/1，未知时为 NULL。

### decisions

`file_id` 主键、`encoding`、`confidence`、`method`、`reason`、`conflicts_json`、`error_codes_json`。JSON 字段保持数组结构。

### warnings

`id`、`file_id`、`code`、`severity`、`message`、`line_number`、`byte_offset`、`snippet`。按文件重建，不累积重复警告。

## 5. 确定性约定

- 文件按相对路径升序；警告按 code、行、偏移、消息升序。
- JSON 缩进 2 空格、末尾换行、键按构造顺序，不排序键。
- 浮点比例和置信度固定六位小数。
- `report.json`、`report.md`、`report.html` 与 `manifest.json` 不包含 SQLite 自增 ID、`run_count`、`updated_at` 等易变字段。
- 固定 `--now` 后，同一输入与配置的 manifest 与三份报告应字节稳定；`decodebench.sqlite3` 的物理文件不承诺字节稳定。

## 6. 事后人工抽样审计

`audit` 只读取 `manifest.json` 与只读 SQLite 查询，不修改编码裁决、转码文件、
台账或自动交付门槛。

### 6.1 抽样框（`audit-frame/1.0`）

由 `manifest.build_audit_frame` 构造，抽样单位为 `rel_path` 对应的已交付文件：

| 字段 | 含义 |
| --- | --- |
| `batch_id` / `batch_key` | 与原批次一致的确定性身份 |
| `rule_version` / `config_fingerprint` / `manifest_generated_at` | 绑定原批次 |
| `delivered_files[]` | 每个已交付文件：`rel_path`、`source_sha256`、`output_sha256`、`output_bytes`、`output_rel_path`、`risk_level` |
| `excluded_files[]` | 转码失败等未交付文件及原因；不进入字节分母 |
| `population` | 已交付文件数、已交付输出字节数与各风险层总体数 |
| `frame_digest` | 对其余字段的规范化 SHA-256；被改写即拒绝 |

### 6.2 抽样计划（`audit-plan/1.0`）

- `design = stratified_srs_without_replacement`，按 `risk_level` 分层；
- `strata[]` 记录每层 `population`、`sample_size`、`inclusion_probability`
  与 `sampled_paths`；
- `units[]` 记录每个交付文件的 `stratum_sample_size`、`inclusion_probability`
  与是否 `sampled`；
- `estimable` 为假时 `blocking_reason` 说明预算不足以让每个非空层都有正入样概率；
- `plan_digest` 绑定整份计划，事后缩小入样概率会被拒绝。

### 6.3 人工标签（`audit-label/1.0`）

每条标签绑定 `batch_id`、`batch_key`、`frame_digest`、`plan_digest`、
`rel_path`、`source_sha256`、`output_sha256` 与 `verdict`
（`correct` / `wrong` / `undecidable`）。批次、框、计划、源/输出 SHA 任一不符、
重复提交或文件未入样都会抛 `AuditError`。未回应文件记为 `no_response`，
输出文件缺失记为 `output_missing`，二者都不计为 `correct`。

### 6.4 估计结果（`audit-estimate/1.0`）

| 口径 | 点估计 | 分母 |
| --- | --- | --- |
| `file_lens` | 错误文件数（权重 `1/π`）及其比例 | 已交付文件数 |
| `byte_lens` | 错误文件中的 UTF-8 输出字节（权重 `output_bytes/π`）及比例 | 已交付 UTF-8 输出字节数 |

`byte_lens.not_exact_error_bytes` 恒为真：该口径是“错误文件中的输出字节暴露”，
不是精确错误字节数，也不能用 `warning_count`、文件个数或源字节数替代。

- 全审且全部回应时 `estimate_type = census`，区间无抽样方差；
- 预算不足时点估计标为 `design_weighted_estimate`，并按各层超几何单侧界给出
  错误文件数上界；字节上界在该层上界允许的未确认文件内按输出字节数降序分配，
  不会用文件数界乘平均文件大小；
- `confidence_allocation = bonferroni_equal_split_across_nonempty_strata`，
  `per_stratum_alpha = (1-confidence)/层数`；
- `thresholds.file_verdict` / `thresholds.byte_verdict` 取 `exceeds`、
  `within` 或 `insufficient`；阈值落在上下界之间时两者都为 `insufficient`。

审计结果可注入 `report.json` / `report.md` / `report.html` 的
`postdelivery_audit` 字段；不注入时报告字节与既有 golden 一致。
