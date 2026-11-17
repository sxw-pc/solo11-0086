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
| `validation_events` | array | 按 `rel_path_304` 升序的离线 304 验证事件；无状态 sidecar 时为空数组 |
| `files` | array | 按 `rel_path` 升序的文件条目（不含 304 零字节验证响应） |

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

### 2.8 validation_events

每个带本地状态 sidecar 的 304 响应产生一个事件，无论是否归属成功：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `rel_path_304` | string | 304 零字节响应的相对路径 |
| `status` | string | `attributed` 或 `unattributed` |
| `resource_key` / `etag_304` / `captured_at_304` | string/null | 304 sidecar 中的资源键、强 ETag、捕获时间 |
| `request_vary` | object | 304 的 Vary 请求输入（键名小写归一） |
| `donor_rel_path` / `donor_captured_at` | string/null | 被归属 200 的路径与捕获时间 |
| `entity_sha256` | string/null | 被复用的 200 原始实体字节摘要 |
| `sidecar_200_sha256` / `sidecar_304_sha256` | string/null | 两份 sidecar 原文摘要，分别记录 |
| `header_edition` | string/null | 头部版次标识（如 `200-original+304-override`） |
| `synthesized_headers` | array | 合成头字段，每项含 `name`、`value`、`source`（`status_200`/`status_304`） |
| `error_codes` | array | 归属/发布错误码与复核警告 |
| `candidate_rel_paths` | array | 参与匹配的候选 200 路径 |
| `views` | array | 两个合同视图；无法归属时为空数组 |

`views` 每项含 `contract`（`forensic_original`/`refreshed_view`）、`view_rel_path`、`success`、`published`、`encoding`、`method`、`entity_sha256`、`output_sha256`、`header_basis`。refreshed 被拒绝时 `published=false`、`view_rel_path` 下无文件，并在 `rejection` 中保留矛盾说明；refreshed 成功时附带独立 `evidence`、`decision`、`transcode` 块。两视图的 `entity_sha256` 必须相同。

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

### validation_events / validation_views

`validation_events`：`id`、`batch_id`、`rel_path_304`、`status`、`resource_key`、`etag_304`、`request_vary_json`、`captured_at_304`、`donor_rel_path`、`donor_captured_at`、`entity_sha256`、`sidecar_200_sha256`、`sidecar_304_sha256`、`header_edition`、`synthesized_headers_json`、`error_codes_json`、`reason`、时间戳；唯一约束 `(batch_id, rel_path_304)`。

`validation_views`：`event_id` 外键、`contract`、`view_rel_path`、`encoding`、`method`、`success`、`published`、`entity_sha256`、`output_sha256`、`detail_json`；唯一约束 `(event_id, contract)`。无法归属的事件没有视图行。只读查询见 `ledger_queries.list_validation_events`。

## 5. 确定性约定

- 文件按相对路径升序；警告按 code、行、偏移、消息升序。
- JSON 缩进 2 空格、末尾换行、键按构造顺序，不排序键。
- 浮点比例和置信度固定六位小数。
- `report.json`、`report.md`、`report.html` 与 `manifest.json` 不包含 SQLite 自增 ID、`run_count`、`updated_at` 等易变字段。
- 固定 `--now` 后，同一输入与配置的 manifest 与三份报告应字节稳定；`decodebench.sqlite3` 的物理文件不承诺字节稳定。
