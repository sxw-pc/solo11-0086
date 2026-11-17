# 架构说明

## 1. 边界

采文解码台只处理“已经落盘”的采集响应字节。它不发起网络请求，不做浏览器渲染、正文抽取、表格抽取、链接巡检、WARC 封装与任务调度。所有输入来自本地配置指定的扫描目录，所有输出写入独立输出目录。

源响应目录只读。转码文件、清单、报告、SQLite 台账通过配置中的 `output.dir` 统一定位，配置校验会拒绝把输出目录放进扫描根目录。

## 2. 模块职责

| 模块 | 职责 |
| --- | --- |
| `config.py` | 读取 YAML、合并默认值、解析路径、校验回环地址、生成配置指纹 |
| `scanner.py` | 确定性扫描扩展名、计算 SHA-256、记录 mtime、读取 sidecar 与 sidecar 摘要，识别带本地状态的 304 验证响应 |
| `validation.py` | 完全离线的 304 状态解析、200 归属（资源键/Vary/强 ETag/捕获时间）、头部合成与严格解码合同 |
| `pipeline_validation.py` | 304 双合同视图的证据/裁决/转码编排与 manifest/台账事件结构 |
| `ledger_validation.py` | 304 验证事件与双合同视图的 SQLite 幂等写入 |
| `evidence.py` | 提取 BOM、HTTP 头、XML declaration、HTML meta、fallback 证据，以及 304 合成头证据 |
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
  → scan()（源文件元数据 + sidecar）
  → collect_evidence()（字节与声明证据）
  → analyze_candidates()（标准库严格解码评分）
  → resolve()（优先级裁决 + 冲突 + 警告）
  → transcode()（UTF-8 输出，不覆盖源）
  → diagnose_bytes()（乱码风险，只诊断）
  → build_manifest()（证据清单）
  → record_batch()（SQLite 幂等台账）
  → write_reports()（JSON/Markdown/HTML）
```

`--now` 固定了 manifest、数据库批次时间和报告的 `generated_at`。相同输入 + 相同配置 + 相同 `--now` 的清单与报告字节稳定。

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
| `W_REPLACEMENT_CHARS` | 正文包含 U+FFFD |
| `W_MOJIBAKE_SEQUENCE` | 典型 mojibake 片段 |
| `W_CONTROL_CHARS` | 不可打印控制字符 |
| `W_QUESTION_RUNS` | 连续问号 |
| `W_SURROGATE_TRACE` | 非法代理项痕迹 |

冲突与警告是证据，不是自动修复指令。程序不会反复猜编码直到“看起来正常”。

## 5A. 离线 304 验证响应处理

采集器落盘的 304 响应只有更新后的头部、没有正文；把零字节当空文本转码会让复核者误以为页面内容消失。带本地状态合成 sidecar（`local_capture: true`，并含 `resource_key`、`captured_at`、`request_vary`、`etag`）的 304 因此走独立入口，全程只读本地文件，不访问网络。没有该标记的文件继续沿用逐文件流程。

### 归属合同

304 必须先归属到唯一一个满足全部条件的已保存 200：同一 `resource_key`、相同 `request_vary` 请求值、同一**强** ETag（`W/` 弱标记拒绝）、200 捕获时间严格早于 304、且 200 原始实体字节完整可读。以下情况一律标记为无法归属/待复核（`E_304_*` + `W_304_ATTRIBUTION_REVIEW`），不产出任何文本：

- 多个候选 200 的实体 SHA-256 互相矛盾（`E_304_ENTITY_CONFLICT`）；
- 只存在弱验证标记（`E_304_WEAK_VALIDATOR`）；
- Vary 请求输入缺失（`E_304_VARY_INPUT_MISSING`）或 ETag 不匹配（`E_304_ETAG_MISMATCH`）；
- 找不到候选（`E_304_NO_CANDIDATE_200`）或旧正文不可读/为空（`E_304_ORIGINAL_UNREADABLE`）。

禁止用最近文件名、当前同目录文件或空 304 文件冒充正文；不同 Vary 语言变体之间不得继承旧 charset。

### 头部合成与双合同

合成有效头部时，只允许 304 中实际出现的头字段覆盖 200 的同名字段（大小写不敏感），未出现的字段沿用 200 旧值；每个字段记录来源版本（`status_200`/`status_304`）。事件分别记录：被验证实体摘要、200 与 304 各自 sidecar 原文摘要、头部合成结果与来源。304 的零字节文件不计入转码正文。

- `forensic_original`：304 仅记录为一次验证事件，继续展示 200 当时的原始头部与按原裁决得到的 UTF-8 文本（输出即 200 普通转码产物）。
- `refreshed_view`：复用 200 的**同一原始字节**，按 304 合成后的有效头部重新裁决，写入独立目录 `transcoded/_validation_views/`，旧视图仍可查。

若 304 头部声明与复用字节无法严格解码、或与其 BOM 冲突（`E_304_REFRESHED_UNDECODABLE`），保留两边证据并拒绝发布 refreshed 视图，不用 fallback 或替换解码掩盖矛盾；forensic 视图不受影响。

最小反例：200 字节 `C3 A9`、强 ETag `"v1"`、`charset=windows-1252`；后续同资源同 Vary 的 304 保持 `"v1"` 但改为 `charset=utf-8`。forensic 视图是 `Ã©`，refreshed 视图是 `é`，两者实体摘要完全相同、头部证据版次不同。304 不改 Content-Type 时两合同文本相同，但验证事件与头部版次仍分别记录。

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

304 验证事件写入 `validation_events` 表（归属状态、资源键、ETag、Vary 输入、实体摘要、两份 sidecar 摘要、合成头 JSON、错误码），每个事件的两个合同视图写入 `validation_views` 表（含是否发布、实体与输出摘要）；批次键同时包含文件幂等片段与验证事件身份片段，因此新增 304 证据会形成独立批次，重复运行仍保持幂等。无法归属的事件只落事件行、不产生视图行，也没有伪空文本产物。

报告只读取稳定计数，不包含 `run_count`、`updated_at` 或 SQLite 自增 ID，因此重复执行仍可字节稳定。

## 7. 写入安全

源文件只以 `rb` 打开。转码输出路径必须落在 `transcode_dir` 内；配置禁止输出目录位于扫描根内。manifest、报告和转码文件都先写 `.tmp` 再 `os.replace`，避免半成品。Flask 复核台只打开 SQLite 只读 URI（`mode=ro`），没有上传、修改、删除或远程触发路由。

## 8. 确定性

- 扫描结果按 POSIX 相对路径排序。
- manifest 的字段按构造顺序输出，文件顺序固定。
- 候选顺序来自配置，平局不依赖字典遍历。
- 警告按 code、行号、偏移、消息排序。
- JSON 使用 `ensure_ascii=False`、固定缩进和固定键顺序。
- 报告不读取当前系统时间，只使用传入的 `now`。
- 自包含 HTML 不引用 CDN、远程字体、脚本或图片。
