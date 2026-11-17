# 项目生成提示词：采文解码台

采文解码台（slug：`decodebench`）是一套**纯本地、完全离线**的采集响应编码证据诊断与 UTF-8 转码归档工具。它面向已经落盘的 HTML、XML、TXT、CSS 文件，回答四个问题：

1. 这些字节实际是什么编码？
2. BOM、HTTP 响应头、XML/HTML 声明之间是否冲突？
3. 正文是否已经出现替换字符或典型 mojibake？
4. 能否安全转成 UTF-8，并留下可审计的证据与 SQLite 台账？

## 定位与边界

**它是：**

- 本地响应目录的编码证据链、冲突诊断、可逆转码与审计工具；
- 一条命令跑通的批处理流水线；
- 配置驱动、结果确定、可 golden 回归的工程底座；
- 仅监听回环地址的只读本地复核台。

**它不是：**

- 爬虫、下载器、代理池、Cookie/登录/验证码或浏览器自动化工具；
- HTML 正文/表格抽取、链接巡检、WARC/CDX 归档、页面监测工具；
- 云服务、上传接口、账号权限系统或通用编码转换 GUI；
- 自动“反复猜编码直到看起来正常”的不可解释修复器；
- 任何需要真实外部站点、凭据或 API 的系统。

运行期不发起网络请求，不访问 CDN，不调用外部 API。样本中的外部占位地址只使用 `example.invalid`。

## 技术栈

- Python 3.10+
- Flask（本地只读复核台）
- PyYAML（配置）
- SQLite 标准库 `sqlite3`（幂等台账）
- pytest（离线测试）
- 编码检测只依赖 Python 标准库 `codecs`、`unicodedata` 与自实现规则，不使用 chardet

## 安装

```bash
python -m pip install -e ".[test]"
```

依赖安装完成后，运行期不需要网络。若环境中已具备 Flask、PyYAML、pytest，也可直接使用。仓库根目录的 `decodebench/` 是开发期路径 shim，因此在仓库根目录未安装时也能执行 `python -m decodebench`；正式安装的包来自 `src/decodebench`。

## 三条核心命令

```bash
# 1. 全量离线测试
pytest -q

# 2. 固定批次时间的端到端示例
python -m decodebench pipeline --config configs/demo.yml --now 2024-01-01T00:00:00Z

# 3. 只读本地复核台（默认 127.0.0.1:5017）
python -m decodebench serve --config configs/demo.yml
```

另有只读的事后人工抽样审计：

```bash
# 冻结抽样框、按风险层分层抽样并给出双口径估计
python -m decodebench audit --config configs/demo.yml --budget 4 --seed 7

# 提交人工标签（correct / wrong / undecidable）后重新估计
python -m decodebench audit --config configs/demo.yml --budget 4 --seed 7 \
  --labels labels.json
```

`audit` 不写台账、不改编码裁决、不改转码文件或自动交付门槛；它只读取
`manifest.json` 与只读 SQLite 查询结果。

也可以使用：

```bash
make test
make demo
make serve
make fixtures
make count
```

`--now` 会归一化为 UTC，并写入 manifest、SQLite 批次时间和报告。固定该值后，同一输入和配置生成的 manifest 与 JSON/Markdown/HTML 报告字节稳定。

## 事后人工抽样审计

审计回答两个不同问题，并分别给出整改结论：

1. **文件数口径**：这一批有多少交付文件存在真实文字错误。每个入样文件权重
   `1 / 入样概率`，分母是已交付文件总数。
2. **字节暴露口径**：错误文件占了多少已交付 UTF-8 输出字节。每个入样文件权重
   `output_bytes / 入样概率`，分母是已交付 UTF-8 输出字节总数。它衡量的是
   “错误文件中的输出字节暴露”，**不是**精确的错误字节数。

两者分母与权重不同，因此可能给出相反的整改优先级：11 份交付中 1 份 1 MiB
的确认错误加 10 份 100 B 的确认正确，文件数错误率为 `1/11 ≈ 9.1%`（低于 10%
文件告警线），而字节暴露率超过 99%（高于 10% 字节告警线）。

审计设计要点：

- **抽样框**：以 `rel_path` 对应的已交付文件为单位，冻结源 SHA、输出 SHA、
  输出字节数、风险层、批次身份与框摘要。转码失败的文件不进入交付框，单列
  在 `excluded_files`。
- **分层无放回抽样**：按既有风险层分层，给定预算与可注入种子，记录各层总体数、
  样本数与每文件入样概率。预算不足以让每个非空层都有正入样概率时，整体标记
  为**不可估**，而不是把未抽层当作安全。
- **标签绑定**：`correct` / `wrong` / `undecidable` 必须核对批次、源 SHA、
  输出 SHA 与抽样计划摘要。换版、重复或未入样标签直接拒绝，不会静默改写统计。
  未审核文件不当作 `correct`；风险等级高也不自动当作 `wrong`。
- **保守上界**：全审时给出无抽样方差的精确值；预算不足时点估计标为设计加权
  估计，并按分层无放回设计的超几何单侧界给出错误文件数上界，再在该层上界允许
  的未确认文件内按输出字节数从大到小分配，得到字节暴露上界——不会用文件数界
  乘平均文件大小。多层的联合置信度按 Bonferroni 等分到各非空层。
- **不可判场景**：单层只审一份、`undecidable`、未回应与输出丢失都会扩大上界并
  记录原因，不伪造零方差，也不事后缩小入样概率。
- 阈值落在上下界之间时，两个口径都答“不足以判定”。审计结果绑定原批次框摘要；
  人工标签只影响审计输出，不反馈训练或改动自动发布规则。


## 配置

`configs/demo.yml` 指定：

- 扫描根与扩展名；
- sidecar 后缀与可选 sidecar 根目录；
- 输出、manifest、报告、转码目录与 SQLite 路径；
- fallback 编码、候选编码、置信度阈值；
- 转码错误策略 `strict`/`replace` 与声明重写开关；
- mojibake 阈值；
- 复核台回环地址与端口。

配置中的相对路径**相对于配置文件所在目录**解析。输出目录、报告目录和清单不得位于扫描源目录内，避免污染源证据。

## 输出目录

```text
out/
  manifest.json                  # 稳定字段顺序的证据清单
  decodebench.sqlite3            # 批次/文件/证据/决策/警告台账
  reports/
    report.json
    report.md
    report.html                  # 自包含、零外链、零脚本
  transcoded/
    <保留相对目录结构的 UTF-8 输出>
```

源文件只读。转码输出独立写入 `output.transcode_dir`，每个输出记录源 SHA-256、输出 SHA-256、使用编码、错误策略和替换字符数量。HTML/XML 可把 charset 声明改写为 `utf-8`，重写会记录原文、新值与位置。

## 检测顺序

1. BOM；
2. 可信 HTTP sidecar 头；
3. 文档内声明（XML declaration，其次 HTML meta）；
4. 配置 fallback；
5. 标准库严格解码 + 确定性统计评分。

统计评分会识别“GB18030 字节却声明 UTF-8”这类冲突，并给出稳定错误码 `E_META_BYTE_CONFLICT`、`E_DECLARATION_UNDECODABLE` 与置信度。详细规则与错误码表见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 离线 fixture

仓库内置 10 个响应样本，覆盖 UTF-8 BOM、meta 声明、GB18030 无声明、GB18030 + 错误 UTF-8 声明、UTF-16LE BOM、UTF-16BE XML 声明、Big5 meta、混合换行 CSS、Windows-1252 拉丁文本、含 U+FFFD 的已知损坏样本，以及 2 个 sidecar 响应头文件。

fixture 可用以下命令幂等生成：

```bash
python scripts/gen_fixtures.py
```

预期决策与警告矩阵见 [docs/FIXTURES.md](docs/FIXTURES.md)。

## SQLite 幂等

文件幂等键为：

```text
<source_sha256>:<rule_version>:<config_fingerprint>
```

`files` 表使用 `(idempotency_key, rel_path)` 唯一约束。重复运行同一批输入时只有 1 个批次行、10 个文件行；批次 `run_count` 增加、状态标记为 `reprocessed`，证据/决策/警告按文件重建而不重复累积。只读查询通过 SQLite `mode=ro` URI 完成。

## 只读复核台

```bash
python -m decodebench serve --config configs/demo.yml
```

访问 `http://127.0.0.1:5017/`。页面只使用本地模板和本地 `style.css`，仅有 GET 路由；不存在上传、修改、删除、远程触发或代理接口。配置会拒绝非回环监听地址。

## 测试

```bash
pytest -q
```

当前测试覆盖：

- BOM、meta、XML declaration、HTTP sidecar 与 fallback 证据；
- 严格解码统计与评分、最终 resolver、冲突错误码；
- UTF-8 转码、BOM 去除、声明重写、strict/replace 错误策略；
- mojibake 定位、风险等级与警告；
- SQLite 幂等与只读查询；
- 固定 `--now` 的报告/manifest 字节稳定性；
- 事后人工抽样审计：11 文件反例、分层抽样概率、预算不足、未回应/undecidable、
  输出字节权重、联合上界、换版标签拒绝与两种整改口径；
- Flask 只读页面与不存在可变路由；
- 真实命令行子进程端到端测试。

测试全部使用仓库 fixture 和 `tmp_path`，不访问网络。

## 目录

```text
decodebench/
  README.md
  pyproject.toml
  Makefile
  .gitignore
  configs/
    demo.yml
  src/decodebench/
    __init__.py
    __main__.py
    cli.py
    config.py
    scanner.py
    evidence.py
    detectors.py
    scorer.py
    resolver.py
    transcoder.py
    mojibake.py
    manifest.py
    ledger.py
    ledger_schema.py
    ledger_queries.py
    models.py
    pipeline.py
    reporting.py
    report_html.py
    manifest.py
    audit.py
    audit_common.py
    audit_labels.py
    audit_estimate.py
    util.py
    web.py
    templates/
      index.html
      batch.html
      file.html
    static/
      style.css
  decodebench/
    __init__.py                 # 开发期路径 shim
  fixtures/
    responses/
    sidecars/
  scripts/
    gen_fixtures.py
    count_lines.py
  tests/
    conftest.py
    test_detectors.py
    test_scorer.py
    test_resolver.py
    test_transcoder.py
    test_mojibake.py
    test_ledger_idempotency.py
    test_reporting_stability.py
    test_postdelivery_audit.py
    test_postdelivery_audit_labels.py
    test_web_readonly.py
    test_cli_pipeline.py
  docs/
    ARCHITECTURE.md
    COMPLIANCE.md
    FIXTURES.md
    REPORT_SCHEMA.md
  out/                          # 运行后生成
```

## 代码规模

```bash
python scripts/count_lines.py
```

当前源码、脚本与测试合计约 5,200 行；所有 Python 文件均不超过 300 行。`count_lines.py` 会检查 2500–5600 行总量与单文件上限，任一条件不满足即返回非零。

## 合规

仅处理本人拥有或已获授权的本地文件；本项目不得用于未授权抓取、规避检测、凭据处理或目标探测。完整声明见 [docs/COMPLIANCE.md](docs/COMPLIANCE.md)。

## 文档索引

- [架构、检测顺序、错误码、幂等设计](docs/ARCHITECTURE.md)
- [合规声明](docs/COMPLIANCE.md)
- [fixture 编码矩阵与预期结果](docs/FIXTURES.md)
- [manifest / 报告 / SQLite Schema](docs/REPORT_SCHEMA.md)
