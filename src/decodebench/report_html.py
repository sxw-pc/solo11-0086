"""零外链、零脚本的自包含 HTML 报告渲染。"""

from __future__ import annotations

from html import escape
from typing import Any

STYLE = """
:root { color-scheme: light; --ink:#182026; --muted:#5d6b78; --line:#d8e0e7;
  --paper:#f5f7f9; --card:#ffffff; --accent:#1f6f5f; --warn:#9b4b16; }
* { box-sizing: border-box; }
body { margin:0; background:var(--paper); color:var(--ink);
  font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; line-height:1.55; }
main { max-width:1080px; margin:0 auto; padding:36px 24px 56px; }
h1 { font-size:30px; margin:0 0 8px; letter-spacing:.02em; }
h2 { font-size:19px; margin:32px 0 12px; border-bottom:1px solid var(--line); padding-bottom:7px; }
p.meta { color:var(--muted); margin:4px 0; overflow-wrap:anywhere; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:12px; margin-top:20px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
.card strong { display:block; font-size:25px; color:var(--accent); }
.card span { color:var(--muted); font-size:13px; }
table { width:100%; border-collapse:collapse; background:var(--card);
  border:1px solid var(--line); font-size:13px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line);
  vertical-align:top; overflow-wrap:anywhere; }
th { background:#edf2f5; font-weight:600; }
tr:last-child td { border-bottom:0; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
.tag { color:var(--warn); font-weight:600; }
footer { margin-top:30px; color:var(--muted); font-size:12px; }
"""


def _text(value: object) -> str:
    return escape("" if value is None else str(value))


def _summary_cards(summary: dict[str, Any]) -> str:
    cards = (
        ("文件总数", summary["files_total"]),
        ("冲突文件", summary["conflict_files"]),
        ("转码成功", summary["transcode_success"]),
        ("警告总数", summary["warnings_total"]),
    )
    return "".join(
        f'<div class="card"><strong>{_text(value)}</strong><span>{_text(label)}</span></div>'
        for label, value in cards
    )


def _warning_table(report: dict[str, Any]) -> str:
    rows = report["warning_distribution"]
    if not rows:
        return '<tr><td colspan="3">无警告</td></tr>'
    return "".join(
        "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td></tr>".format(
            _text(item["code"]), _text(item["severity"]), _text(item["count"])
        )
        for item in rows
    )


def _file_table(report: dict[str, Any]) -> str:
    if not report["files"]:
        return '<tr><td colspan="8">无文件</td></tr>'
    rows: list[str] = []
    for item in report["files"]:
        conflict = '<span class="tag">是</span>' if item["conflict"] else "否"
        rows.append(
            "<tr><td>{}</td><td>{}</td><td class=\"num\">{:.6f}</td><td>{}</td>"
            "<td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td></tr>".format(
                _text(item["rel_path"]),
                _text(item["encoding"]),
                float(item["confidence"]),
                _text(item["method"]),
                conflict,
                "成功" if item["transcode_success"] else "失败",
                _text(item["risk_level"]),
                _text(item["warning_count"]),
            )
        )
    return "".join(rows)


def _ledger_table(ledger: dict[str, Any]) -> str:
    labels = (
        ("批内文件", "files_in_batch"),
        ("批内冲突文件", "conflict_files"),
        ("批内转码文件", "transcoded_files"),
        ("证据行", "evidence_rows"),
        ("决策行", "decision_rows"),
        ("警告行", "warning_rows"),
        ("files 表总行数", "files_table_total"),
        ("batches 表总行数", "batches_table_total"),
    )
    return "".join(
        f"<tr><td>{_text(label)}</td><td class=\"num\">{_text(ledger[key])}</td></tr>"
        for label, key in labels
    )


def render_html(report: dict[str, Any]) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>采文解码台诊断报告</title>
<style>{STYLE}</style>
</head>
<body>
<main>
<h1>采文解码台诊断报告</h1>
<p class="meta">批次时间：{_text(report['generated_at'])}</p>
<p class="meta">批次 ID：{_text(report['batch_id'])}</p>
<p class="meta">扫描根：{_text(report['scan_root'])}</p>
<p class="meta">规则版本：{_text(report['rule_version'])}</p>
<p class="meta">配置指纹：{_text(report['config_fingerprint'])}</p>
<div class="cards">{_summary_cards(report['summary'])}</div>
<h2>警告分布</h2>
<table>
<thead><tr><th>错误码</th><th>级别</th><th class="num">数量</th></tr></thead>
<tbody>{_warning_table(report)}</tbody>
</table>
<h2>文件决策明细</h2>
<table>
<thead><tr><th>相对路径</th><th>编码</th><th class="num">置信度</th><th>方法</th>
<th>冲突</th><th>转码</th><th>风险</th><th class="num">警告</th></tr></thead>
<tbody>{_file_table(report)}</tbody>
</table>
<h2>SQLite 台账摘要</h2>
<table>
<thead><tr><th>指标</th><th class="num">数值</th></tr></thead>
<tbody>{_ledger_table(report['ledger'])}</tbody>
</table>
<footer>本报告由本地字节与 SQLite 台账生成；无外部资源，不自动进行二次编码修复。</footer>
</main>
</body>
</html>
"""
