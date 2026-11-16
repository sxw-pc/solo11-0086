# 离线 fixture 说明

fixture 由 `scripts/gen_fixtures.py` 生成，全部位于仓库内，不依赖真实网页或网络。运行期间扫描器只读 `fixtures/responses` 与 `fixtures/sidecars`。

## 1. 文件矩阵

| 文件 | 实际字节编码 | 编码声明 | 预期最终决策 | 预期警告/错误码 |
| --- | --- | --- | --- | --- |
| `utf8_bom.html` | UTF-8 + BOM | HTML meta `utf-8` | `utf-8` / `bom` | 无 |
| `utf8_meta.html` | UTF-8，无 BOM | HTML meta `UTF-8` | `utf-8` / `meta_charset` | 无 |
| `gb18030_no_meta.html` | GB18030 | 无 | `gb18030` / `statistical` | `W_STATISTICAL_DECISION` |
| `gb18030_with_utf8_meta.html` | GB18030 | HTML meta `utf-8`（错误声明） | `gb18030` / `statistical` | `E_DECLARATION_UNDECODABLE`、`E_META_BYTE_CONFLICT`、`W_STATISTICAL_DECISION` |
| `utf16le_bom.xml` | UTF-16LE + BOM | BOM、XML `UTF-16`、sidecar `charset=utf-16le` | `utf-16-le` / `bom` | 无 |
| `utf16be_decl.xml` | UTF-16BE，无 BOM | XML `UTF-16BE` | `utf-16-be` / `xml_declaration` | 无 |
| `big5_meta.html` | Big5 | HTML meta `big5` | `big5` / `meta_charset` | 无 |
| `mixed_eol.css` | UTF-8 | 无 | `utf-8` / `fallback` | `W_FALLBACK_USED` |
| `plain_latin.txt` | Windows-1252 | 无 | `windows-1252` / `statistical` | `W_STATISTICAL_DECISION` |
| `corrupted_replacement.html` | UTF-8 | HTML meta `utf-8` | `utf-8` / `meta_charset` | `W_REPLACEMENT_CHARS`、`W_MOJIBAKE_SEQUENCE`、`W_QUESTION_RUNS` |

总体预期：10 个文件、1 个冲突文件、10 个转码成功、9 条警告、9 个 `none` 风险与 1 个 `high` 风险。这些 fixture 都没有 `Content-Encoding` 声明，`content_encoding.status` 全部为 `none`。

## 2. 关键样本细节

### UTF-8 BOM 样本

`utf8_bom.html` 以 `EF BB BF` 开头。BOM 是最高优先级证据；转码输出会去掉 BOM，且正文仍然是 UTF-8。

### 声明冲突样本

`gb18030_with_utf8_meta.html` 的字节由 GB18030 编码，但文档内写成 `<meta charset="utf-8">`。UTF-8 严格解码失败，统计评分选择 GB18030。resolver 同时记录：

- 声明编码不可严格解码；
- meta 声明与最终字节裁决冲突；
- 统计裁决信息。

这是“不要相信单一声明”的核心回归样本。

### UTF-16 两种路径

- `utf16le_bom.xml`：有 BOM，并带 sidecar 响应头与 XML declaration；决策走 BOM。三处声明彼此兼容。
- `utf16be_decl.xml`：没有 BOM，按 NUL 字节形态识别出 UTF-16BE，并从 UTF-16 文本中提取 XML declaration。决策走文档声明。

两者的转码输出都会把 XML `encoding` 改写为 `utf-8`，并在 `transcode.rewrites` 中记录原文值、新值和位置。

### Big5 样本

`big5_meta.html` 由 Big5 编码，自带的 meta 声明合法。最终决策走 `meta_charset`，输出 UTF-8，meta 被改写为 `utf-8`。

### 无声明 fallback 与统计样本

`mixed_eol.css` 与 `plain_latin.txt` 都没有编码声明：

- CSS 文件能被 fallback UTF-8 严格解码，方法记为 `fallback`；混合 CRLF/LF/CR 在解码和输出中保持不变。
- 拉丁文本含 Windows-1252 弯引号、重音字符和长破折号，UTF-8 fallback 严格解码失败，统计评分选择 `windows-1252`。

### 已知损坏样本

`corrupted_replacement.html` 是合法 UTF-8，但正文已经包含：

- U+FFFD 替换字符；
- 典型 mojibake 片段 `Ã©`；
- 连续三个问号。

诊断等级为 `high`，只给出证据与人工复核建议，不自动二次转码。

## 3. sidecar 文件

sidecar 支持两种命名：`<filename>.<sidecar_suffix>` 和 `<stem>.<sidecar_suffix>`。仓库中的 fixture 使用 stem 形式：

| sidecar | 内容 | 作用 |
| --- | --- | --- |
| `gb18030_with_utf8_meta.headers.json` | `Content-Type: text/html`，无 charset | 保留“没有可采信 HTTP 编码声明”的场景 |
| `utf16le_bom.headers.json` | `Content-Type: application/xml; charset=utf-16le` | 验证 HTTP 头、BOM 与 XML declaration 的一致证据 |

sidecar 的 URL 只使用保留域名 `example.invalid`，不指向真实站点。

## 4. gzip 解封装测试样本

离线 gzip 场景不写入仓库 fixture 目录，而是在 `tests/gzip_support.py` 中用标准库
`zlib` 现场构造，避免把压缩字节当成不易复核的二进制 fixture：

| 测试构造 | 预期 `content_encoding.status` | 预期产物 |
| --- | --- | --- |
| 两个完整 member 串接 | `complete` | `transcoded/<path>`，`success=true` |
| 第二 member CRC 错 + `strict` | `strict_failed` | 无正文、无产物 |
| 第二 member CRC 错 + `verified_prefix` | `verified_prefix` | 仅 `partial/<path>.partial.utf8`，`success=false` |
| 第二 member 截断 | `strict_failed` | 无正文、无产物 |
| 解压后字节或膨胀比超限 | `strict_failed` / `E_GZIP_EXPANSION_LIMIT` | 无正文、无产物 |
| sidecar 错宣 gzip，实体为明文 | `strict_failed` / `E_GZIP_NOT_GZIP` | 无正文，不猜字符集 |
| 无 `Content-Encoding` 的旧样本 | `none` | 原字节流程与既有 fixture 完全一致 |

失败 member 的字节不会出现在任何输出中；`transcode_partial` 单独计数，从不进入
`transcode_success`。

## 5. 重新生成与回归

```bash
python scripts/gen_fixtures.py
```

脚本是幂等的，会覆盖生成 fixture。fixture 文件与 sidecar 是只读输入；pipeline 不会修改它们。端到端测试使用仓库 fixture，并把输出定向到 pytest 的 `tmp_path`。

如果修改 fixture 的字节或声明，应同步更新本文件和测试中的预期决策。
