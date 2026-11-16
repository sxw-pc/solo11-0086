# 架构说明

## 1. 边界

采文解码台只处理“已经落盘”的采集响应字节。它不发起网络请求，不做浏览器渲染、正文抽取、表格抽取、链接巡检、WARC 封装与任务调度。所有输入来自本地配置指定的扫描目录，所有输出写入独立输出目录。

源响应目录只读。转码文件、清单、报告、SQLite 台账通过配置中的 `output.dir` 统一定位，配置校验会拒绝把输出目录放进扫描根目录。

## 2. 模块职责

| 模块 | 职责 |
| --- | --- |
| `config.py` | 读取 YAML、合并默认值、解析路径、校验回环地址、生成配置指纹 |
| `scanner.py` | 确定性扫描扩展名、计算 SHA-256、记录 mtime、读取 sidecar 并提取 Content-Encoding 声明 |
| `gzip_members.py` | 逐 gzip member 校验头、deflate 流、尾、CRC32 与 ISIZE，并执行字节/膨胀上限 |
| `decompress.py` | 仅在可信 sidecar 声明 gzip 时离线解封装，提供 strict 与 verified_prefix 两条归档路线 |
| `evidence.py` | 提取 BOM、HTTP 头、XML declaration、HTML meta、fallback 证据与 Content-Encoding 声明 |
| `detectors.py` | BOM 表、编码别名、严格解码、字符比例、UTF-16 形态识别 |
| `scorer.py` | 对严格解码结果做确定性评分与排序，选择统计获胜者 |
| `resolver.py` | 按优先级裁决、生成冲突错误码、置信度与警告 |
| `transcoder.py` | 严格/替换解码、BOM 去除、声明重写、原子写入 UTF-8 |
| `mojibake.py` | 替换字符、典型 mojibake、控制字符、连续问号、代理项诊断 |
| `manifest.py` | 构建稳定字段顺序的 `manifest.json` 与汇总 |
| `ledger_schema.py` | SQLite 表结构 SQL |
| `ledger.py` | 批次/文件/证据/决策/警告的幂等写入 |
| `ledger_queries.py` | 只读查询，供复核台和测试使用 |
| `reporting.py` | JSON/Markdown 报告与自包含 HTML 调度 |
| `report_html.py` | 零外链、零脚本 HTML 渲染 |
| `web.py` | Flask 只读复核台，仅 GET 路由 |
| `pipeline.py` | 端到端编排 |
| `cli.py` | `pipeline` 与 `serve` 子命令、固定时钟解析 |
| `models.py` | 扫描、证据、候选、决策、转码、mojibake 数据结构 |
| `util.py` | 原子写入与确定性 JSON 序列化 |

仓库根目录的 `decodebench/__init__.py` 只是开发期路径 shim，让未安装时的 `python -m decodebench` 能找到 `src/decodebench`；安装后的包来自 `src/`。

## 3. 数据流

```text
YAML config
  → load_config()（路径解析 + 配置指纹）
  → scan()（源文件元数据 + sidecar + Content-Encoding 声明）
  → decompress()（仅可信 gzip 声明时逐 member 验收并解封装）
  → collect_evidence()（字节与声明证据）
  → analyze_candidates()（标准库严格解码评分）
  → resolve()（优先级裁决 + 冲突 + 警告）
  → transcode()（UTF-8 输出，不覆盖源；失败时清理旧产物）
  → diagnose_bytes()（乱码风险，只诊断）
  → build_manifest()（证据清单）
  → record_batch()（SQLite 幂等台账）
  → write_reports()（JSON/Markdown/HTML）
```

`--now` 固定了 manifest、数据库批次时间和报告的 `generated_at`。相同输入 + 相同配置 + 相同 `--now` 的清单与报告字节稳定。

## 3.1 Content-Encoding 与离线解封装

采集管道可能把 HTTP 的 gzip 实体字节原样落盘。只有当**可信本地 sidecar** 中的
`Content-Encoding` 明确为单一 `gzip`（或 `x-gzip`）时，才进入离线解封装；没有该
声明的旧样本完全沿用原字节流程，`content_encoding.status` 为 `none`。

- 原实体字节始终保留为证据：`entity_sha256` 与 `source_sha256` 相同，成员偏移均
  相对原实体。字符集/BOM/文档声明只从**经过校验的正文**提取；报告同时给出
  `entity_sha256` 与实际参与裁决的 `decoded_sha256`。
- 串接的多 member 逐个独立验收：固定头（含 FEXTRA/FNAME/FCOMMENT/FHCRC）、
  deflate 流、8 字节尾、CRC32、ISIZE。任一 member 失败即整体不完整。
- 两条授权路线由 `content_encoding.failure_route` 选择：
  - `strict`：整体验收失败时不发布任何正文，只记录实体摘要与失败位置；
  - `verified_prefix`：仅把此前**完整验收**的 member 正文写成独立、标为
    partial 的 UTF-8 产物（`output.partial_dir`，后缀 `.partial.utf8`），
    `transcode.success=false`，不计入成功数；损坏 member 的字节永不写入。
- `content_encoding.enabled=false` 时完全回到旧字节流程。
- sidecar 声明了不支持的编码（例如 `br`）或 gzip 声明与实体不符
  （magic/边界不可信）时按失败处理，不尝试从原字节猜字符集。
- 解封装前后各有上限：`entity_max_bytes`（超限时不载入实体解压）、
  `inflate_max_bytes` 与 `max_expansion_ratio`（按已分配/已产出累计，超过即停止）。
  上限命中留下稳定诊断码 `E_GZIP_ENTITY_LIMIT`、`E_GZIP_INFLATE_LIMIT` 或
  `E_GZIP_RATIO_LIMIT`，对外统一为 `E_GZIP_EXPANSION_LIMIT` 警告。

## 4. 编码检测顺序

1. **BOM**：UTF-32/UTF-16/UTF-8 的已知 BOM 表，优先于其他所有声明。
2. **可信 HTTP 头**：sidecar `headers.Content-Type` 中的 charset，`trusted_http_headers` 可关闭。
3. **文档内声明**：XML declaration 优先于 HTML `<meta charset>`。
4. **配置 fallback**：`detection.fallback_encoding`，仅在严格解码成功时采用。
5. **统计分析**：对配置候选集逐项严格解码，按非法序列、替换字符、控制字符、未分配码点、私用区、可打印率和 CJK/拉丁比例评分。

统计评分仍会计算并写入证据，即使最终由更高优先级来源裁决。声明无法严格解码时记录 `E_DECLARATION_UNDECODABLE`；最终编码与声明不一致时按来源记录冲突码。统计候选不能覆盖 BOM、可信 HTTP 头或有效文档声明，只负责“声明均不可用”时的兜底裁决。

评分使用确定性公式：扣除控制字符、私用区、未分配码点、替换字符和不可打印比例；对合法 UTF-8、具有足够高位字节比例的 CJK 多字节候选给少量加成；对没有 UTF-16 字节形态的 UTF-16 候选重罚。平局按配置候选顺序决定。

## 5. 证据与冲突

每条证据包含 `source`、`declared`、`offset`、`line`、`matches_decision`、`note`。HTTP sidecar 证据没有字节偏移；统计证据没有单一原文位置，但附带候选排名说明。manifest 同时保留完整候选评分数组。

冲突码对应来源：

| 错误码 | 场景 |
| --- | --- |
| `E_BOM_DECL_CONFLICT` | BOM 与文档声明不一致 |
| `E_BOM_HEADER_CONFLICT` | BOM 与可信 HTTP 头不一致 |
| `E_HEADER_DECL_CONFLICT` | HTTP 头与文档声明不一致 |
| `E_DOC_DECL_CONFLICT` | 文档内多个声明互相不一致 |
| `E_META_BYTE_CONFLICT` | meta 声明与最终字节裁决不一致 |
| `E_DECL_BYTE_CONFLICT` | XML 声明与最终字节裁决不一致 |
| `E_HEADER_BYTE_CONFLICT` | HTTP 头与最终字节裁决不一致 |
| `E_DECLARATION_UNDECODABLE` | 声明编码不能严格解码当前字节 |
| `E_UNDECODABLE` | 没有候选可严格解码 |
| `E_LOW_CONFIDENCE` | 统计置信度低于配置阈值 |
| `W_FALLBACK_USED` | 使用配置 fallback |
| `W_STATISTICAL_DECISION` | 使用统计裁决 |
| `W_SIDECAR_INVALID` | sidecar 不是合法 JSON 或结构错误 |
| `E_CONTENT_ENCODING_INVALID` | sidecar 的 Content-Encoding 不可用或不受支持 |
| `E_GZIP_NOT_GZIP` | 声明 gzip 但实体不是 gzip |
| `E_GZIP_MEMBER_BOUNDARY` | 串接 member 边界不可信 |
| `E_GZIP_HEADER_INVALID` / `E_GZIP_HEADER_CRC_MISMATCH` | member 头不合法 |
| `E_GZIP_MEMBER_TRUNCATED` / `E_GZIP_TRAILER_MISSING` | member 正文或尾被截断 |
| `E_GZIP_CRC_MISMATCH` / `E_GZIP_ISIZE_MISMATCH` | member 尾校验失败 |
| `E_GZIP_DECOMPRESS_ERROR` | deflate 流损坏 |
| `E_GZIP_MEMBER_LIMIT` | member 数超过上限 |
| `E_GZIP_EXPANSION_LIMIT` | 解封装前字节或解压膨胀超限（对外统一警告码） |
| `W_GZIP_PARTIAL_PREFIX` | 仅归档了已验证前缀正文 |
| `W_REPLACEMENT_CHARS` | 正文包含 U+FFFD |
| `W_MOJIBAKE_SEQUENCE` | 典型 mojibake 片段 |
| `W_CONTROL_CHARS` | 不可打印控制字符 |
| `W_QUESTION_RUNS` | 连续问号 |
| `W_SURROGATE_TRACE` | 非法代理项痕迹 |

冲突与警告是证据，不是自动修复指令。程序不会反复猜编码直到“看起来正常”。

## 6. 幂等键与台账

文件幂等键严格由三部分组成：

```text
<source_sha256>:<rule_version>:<config_fingerprint>
```

`config_fingerprint` 是“合并默认值后的 YAML + 规则版本”的 SHA-256；它不包含运行时当前时间。`files` 表用 `(idempotency_key, rel_path)` 唯一约束，既满足同一源字节的幂等更新，也避免两个路径下完全相同字节被合并成一条记录。

批次键由排序后的“文件幂等键 + 相对路径”列表哈希得到，`batch_id` 为批次键前 20 个十六进制字符。重复运行同一批输入时：

- `batches` 仍只有一行，`run_count` 增加，`status` 变为 `reprocessed`；
- 文件行按唯一约束更新，不新增重复记录；
- 该文件的 evidence/decision/warnings 先删除再重建，避免重复行。

Content-Encoding 相关列（`sidecar_sha256`、`entity_sha256`、`decoded_sha256`、
`content_encoding_status`、`content_encoding_published`、`transcode_partial`）在
旧数据库上通过 `ALTER TABLE ... ADD COLUMN` 幂等补齐，不丢已有台账。

报告只读取稳定计数，不包含 `run_count`、`updated_at` 或 SQLite 自增 ID，因此重复执行仍可字节稳定。

## 7. 写入安全

源文件只以 `rb` 打开（超过解封装前上限的实体不会被载入解压）。转码输出路径必须落在
`transcode_dir`（partial 前缀产物落在 `partial_dir`）内；配置禁止输出目录位于扫描根内。
manifest、报告和转码文件都先写 `.tmp` 再 `os.replace`，避免半成品；任一路径失败时会移除
同名旧产物，防止上次成功文件被当成本次结果。Flask 复核台只打开 SQLite 只读 URI（`mode=ro`），没有上传、修改、删除或远程触发路由。

## 8. 确定性

- 扫描结果按 POSIX 相对路径排序。
- manifest 的字段按构造顺序输出，文件顺序固定。
- 候选顺序来自配置，平局不依赖字典遍历。
- 警告按 code、行号、偏移、消息排序。
- JSON 使用 `ensure_ascii=False`、固定缩进和固定键顺序。
- 报告不读取当前系统时间，只使用传入的 `now`。
- 自包含 HTML 不引用 CDN、远程字体、脚本或图片。
