# 受控共享与使用合同

采文解码台的所有证据默认留在本机。需要让外部复核者阅读结果时，必须通过
`export` 命令按使用合同导出发布包；内部 manifest、SQLite 台账与本地只读
复核台不受影响，仍保留完整字节证据。

## 1. 两种使用合同

| 合同 | 面向 | 内容 |
| --- | --- | --- |
| `local_forensic` | 获授权本地审计员 | 原始路径、源/输出 SHA-256、证据 note、警告/乱码片段、精确计数 |
| `share_review` | 外部复核者 | 本次导出的不透明文件代号、编码决策、通过联合发布检查的类别/汇总 |

```bash
python -m decodebench pipeline --config configs/demo.yml --now 2024-01-01T00:00:00Z
python -m decodebench export --config configs/demo.yml --contract share_review
python -m decodebench export --config configs/demo.yml --contract local_forensic
```

导出只读已有 manifest 与台账，不上传、不监听任何地址；共享包内不含源文件
或转码正文。可用 `--route`、`--min-group-size`、`--secret`、`--output-dir`
覆盖配置中的 `sharing.*` 默认值。

## 2. 共享视图的构造原则

共享视图**从显式允许清单构造**，不是对内部 manifest 删除字段：

- 逐文件允许字段（`projection.SHARED_FILE_FIELDS`）：`file_token`、
  `encoding`、`confidence_band`、`method`、`transcode_success`、
  `risk_level`、`warning_count`、`warning_codes`、`conflict`、`error_codes`。
- 禁止出现的内部字段（`projection.SUPPRESSED_INTERNAL_FIELDS`，机器检查与
  文档共用同一份清单）：`rel_path`、`source_sha256`、`output_sha256`、
  `source_size`、`source_mtime`、`scan_root`、`config_snapshot`、
  `config_fingerprint`、`batch_id`、`evidence`、`note`、`snippet`、
  `output_rel_path`、`ledger` 等。
- 外部可获知本批编码决策、冲突/警告类别与审计联系
  （`sharing.audit_contact`），但无法由路径、文件名、扫描根、配置快照、
  原始头部 note、警告/乱码片段、源/输出哈希、精确大小/mtime 或导出文件名
  重识别源响应。

## 3. 导出批次身份与文件代号

- 每次导出默认生成新的随机密钥；`export_id`（`X-` 前缀）与文件代号
  （`F-` 前缀）都由该密钥经 HMAC-SHA256 派生。
- 文件代号**不是对路径的普通哈希**：没有本次密钥无法验证猜测；
  同一包内 JSON/Markdown/HTML 的代号一致，可把同一决定与告警对应起来；
  独立导出之间默认不可关联。
- 代号与源文件的映射表不随包发布，也不写入任何输出；共享包不引用内部
  输出路径，导出文件名固定为 `share.json/md/html` + `share_schema.json`。
- 需要可复现导出（golden 回归）时可显式传 `--secret`；相同密钥与输入
  产生字节稳定的共享包。

## 4. 联合发布检查

逐文件匿名不够：精确的 `files_total`、`risk_distribution`、
`warning_distribution` 与逐文件可见的编码/告警组合可形成补集反推。
例如两份响应中一份可从公开编码特征识别为无乱码，另一份存在唯一 high
乱码——即使第二份隐藏了行级风险标签，`high=1` 的精确汇总仍然暴露它。

因此行级与汇总级的可发布性由同一次检查联合决定：

1. 以敏感画像（风险等级 × 警告码集合 × 冲突标记）分组，样本量小于
   `min_group_size`（默认 2）的组为低样本组，组内文件受保护；
2. 只要存在受保护文件，风险/警告/冲突三个敏感维度**整体受限**——
   否则任一维度的精确汇总都能通过补集反推被藏文件的对应属性；
3. 同一文件的 `warning_count`、`warning_codes`、`conflict`、`error_codes`
   与汇总按同一发布决定处理；相关行、列总计无法反算被藏单元。

两条均合规的发布路线（同一批次给出不同的可见审计结果）：

- `suppress`：受保护文件的全部敏感行级标签替换为 `suppressed`，
  三个敏感维度的分布与列总计整体不发布；
- `interval`：敏感计数转为包含真实值的 `{min, max}` 区间
  （跨度至少覆盖 `min_group_size-1` 个相邻值），受保护文件的风险等级
  转为 `none_or_low` / `medium_or_high` 区间带，行级与汇总联合保证
  无法反算精确值。

共享视图不会把所有数字清零：文件总数、转码成功/失败数、方法分布保持
精确；未受保护文件的行级标签保持精确；无低样本组时全部分布精确发布。
`disclosure.retained_conclusions` 与 `undeterminable_conclusions` 逐条
说明哪些结论被保留、哪些无法从共享数据判断。

## 5. 可机器检查的 schema

每个共享包带 `share_schema.json`（内容即 `projection.SHARE_SCHEMA`）：

- `top_level_fields` / `file_fields` / `summary_fields`：预期可见字段；
- `suppressed_internal_fields`：抑制字段清单；
- `export_identity`：导出批次身份（`export_id`、`file_token`、
  不可关联性、映射表不发布）；
- `routes`：两条发布路线的语义。

`share.json` 的 `disclosure` 块携带本次导出的实际发布决定
（路线、最小组样本量、受保护文件数、各敏感维度状态），
可据此机器校验共享包是否满足合同。

## 6. 本地复核台的共享预览

复核台新增只读页面 `/batch/<batch_id>/share`，用同一份统一投影模拟
外部复核者可见的内容。预览代号每次访问重新随机，预览之间也不默认可
关联；页面仍只监听回环地址，没有任何写接口。
