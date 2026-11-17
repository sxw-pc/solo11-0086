"""受控共享导出与统一投影的合同测试。

覆盖：多格式字段一致、已知 SHA 字典识别、两文件补集反推、重复导出
不默认可关联、内部审计仍完整、空批次、不含敏感信息的正常批次、
Alice 双合同、两条共享路线、schema 机器检查与复核台共享预览。
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from decodebench.config import ConfigError, load_config
from decodebench.manifest import build_internal_rows
from decodebench.pipeline import run
from decodebench.projection import (
    CONTRACT_SHARE_REVIEW,
    SHARE_SCHEMA,
    SUPPRESSED_INTERNAL_FIELDS,
    SharePolicy,
    build_shared_view,
    summarize_internal,
)
from decodebench.reporting import build_report
from decodebench.sharing import build_export
from decodebench.web import _ledger_internal_rows, create_app

TOKEN_PATTERN = re.compile(r"F-[0-9a-f]{10}")
NOW = "2024-01-01T00:00:00Z"


def _write_utf8_html(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '<!doctype html>\n<html><head><meta charset="utf-8"><title>t</title></head>'
        f"<body><p>{body}</p></body></html>",
        encoding="utf-8",
    )


def _alice_root(tmp_path: Path) -> Path:
    """cases/alice.html 带 Alice-ID 正文与唯一 high 乱码；另两份干净响应。"""
    root = tmp_path / "responses"
    _write_utf8_html(
        root / "cases" / "alice.html", "员工编号 Alice-ID 的页面出现典型乱码 æ˜¯ 需要复核"
    )
    _write_utf8_html(root / "cases" / "bob.html", "完全正常的页面内容，没有乱码。")
    _write_utf8_html(root / "cases" / "carol.html", "另一份完全正常的页面内容。")
    return root


def _two_file_root(tmp_path: Path) -> Path:
    """一份可从公开编码特征识别为无乱码，另一份存在唯一 high 乱码。"""
    root = tmp_path / "responses"
    _write_utf8_html(root / "one.html", "干净页面，编码声明与字节一致。")
    _write_utf8_html(root / "two.html", "这一份含有典型乱码序列 æ˜¯ 需要复核。")
    return root


def _normal_root(tmp_path: Path) -> Path:
    """每个敏感画像组样本量都 >=2 的正常 常批次。"""
    root = tmp_path / "responses"
    _write_utf8_html(root / "clean_a.html", "完全正常的页面内容甲。")
    _write_utf8_html(root / "clean_b.html", "完全正常的页面内容乙。")
    _write_utf8_html(root / "q_a.html", "状态正常 ??? 结束甲")
    _write_utf8_html(root / "q_b.html", "状态正常 ??? 结束乙")
    return root


def _run_batch(make_config, root: Path, tmp_path: Path):
    config = make_config(scan_root=root)
    result = run(config, NOW)
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    return config, result, manifest


def _export(config, tmp_path: Path, name: str, **kwargs):
    kwargs.setdefault("contract", "share_review")
    kwargs.setdefault("now", NOW)
    kwargs["output_dir"] = str(tmp_path / name)
    result = build_export(config, **kwargs)
    package = Path(result["package_dir"])
    stem = "share" if kwargs["contract"] == "share_review" else "forensic"
    view = json.loads((package / f"{stem}.json").read_text(encoding="utf-8"))
    texts = {
        "json": (package / f"{stem}.json").read_text(encoding="utf-8"),
        "md": (package / f"{stem}.md").read_text(encoding="utf-8"),
        "html": (package / f"{stem}.html").read_text(encoding="utf-8"),
        "schema": (package / f"{stem}_schema.json").read_text(encoding="utf-8"),
    }
    return result, view, texts


def _all_text(texts: dict[str, str]) -> str:
    return "\n".join(texts.values())


# ---------------------------------------------------------------------------
# Alice：同一输入在两种合同下的可见性
# ---------------------------------------------------------------------------


def test_alice_local_forensic_can_locate_and_verify_bytes(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, result, manifest = _run_batch(make_config, root, tmp_path)
    exported, view, _ = _export(config, tmp_path, "forensic", contract="local_forensic")

    package = Path(exported["package_dir"])
    forensic = json.loads((package / "forensic.json").read_text(encoding="utf-8"))
    paths = [row["rel_path"] for row in forensic["files"]]
    assert "cases/alice.html" in paths
    # 取证包附完整 manifest，审计员可定位源文件并核对字节摘要
    bundled = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    alice = next(row for row in bundled["files"] if row["rel_path"] == "cases/alice.html")
    actual = hashlib.sha256((root / "cases" / "alice.html").read_bytes()).hexdigest()
    assert alice["source_sha256"] == actual
    assert alice["mojibake"]["level"] == "high"
    assert "Alice-ID" in json.dumps(alice["warnings"], ensure_ascii=False)
    # 精确计数保留
    risk = {d["level"]: d["count"] for d in forensic["summary"]["risk_distribution"]}
    assert risk["high"] == 1


def test_alice_share_review_hides_identity_and_unique_high(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, result, manifest = _run_batch(make_config, root, tmp_path)
    # 内部证据确实包含 Alice 与唯一 high（反证测试不是空断言）
    assert any("alice" in row["rel_path"] for row in manifest["files"])
    internal_risk = {d["level"]: d["count"] for d in manifest["summary"]["risk_distribution"]}
    assert internal_risk["high"] == 1

    _, view, texts = _export(config, tmp_path, "share", route="suppress")
    blob = _all_text(texts)
    data_blob = "\n".join(texts[key] for key in ("json", "md", "html"))
    # 无法从任何共享格式还原 Alice 的路径、正文片段
    assert "alice" not in blob.lower()
    assert "cases/" not in blob
    assert config.scan_root.as_posix() not in blob
    # suppress 路线下唯一 high 状态不可见：共享数据里没有任何 "high" 字样
    # （schema 文件是静态词汇说明，不含批次数据）
    assert "high" not in data_blob
    assert view["summary"]["risk_distribution"] == "suppressed"
    assert view["summary"]["warning_distribution"] == "suppressed"
    assert view["summary"]["conflict_files"] == "suppressed"
    assert view["disclosure"]["protected_files"] == 1
    # 受保护文件的全部敏感字段按同一发布决定处理
    protected = [row for row in view["files"] if row["risk_level"] == "suppressed"]
    assert len(protected) == 1
    for key in ("warning_count", "warning_codes", "conflict", "error_codes"):
        assert protected[0][key] == "suppressed"
    # 编码审计结论仍可读：每份响应的编码决策保留
    assert {row["encoding"] for row in view["files"]} == {"utf-8"}
    assert view["summary"]["files_total"] == 3
    # 披露说明解释了保留与无法判断的结论
    assert view["disclosure"]["retained_conclusions"]
    assert view["disclosure"]["undeterminable_conclusions"]


def test_alice_interval_route_gives_different_but_compliant_view(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, _, _ = _run_batch(make_config, root, tmp_path)
    _, suppress_view, _ = _export(config, tmp_path, "suppress", route="suppress")
    _, interval_view, _ = _export(config, tmp_path, "interval", route="interval")

    # 两条合规路线给出同一批次不同的可见审计结果
    assert suppress_view["summary"] != interval_view["summary"]
    risk = {d["level"]: d["count"] for d in interval_view["summary"]["risk_distribution"]}
    # high 的精确值 1 不可反算：区间包含 0 与 1
    assert risk["high"] == {"min": 0, "max": 2}
    assert risk["none"] == {"min": 1, "max": 3}
    # 受保护文件的风险被降为区间带，无法确认唯一 high
    bands = [row["risk_level"] for row in interval_view["files"]]
    assert "high" not in bands
    assert bands.count("medium_or_high") == 1
    assert bands.count("none") == 2
    alice_row = interval_view["files"][bands.index("medium_or_high")]
    assert alice_row["warning_count"] == {"min": 0, "max": 2}
    assert alice_row["warning_codes"] == "suppressed"
    # 区间路线下补集仍不成立：任何等级都无法推出精确计数
    for cell in interval_view["summary"]["risk_distribution"]:
        assert cell["count"]["min"] < cell["count"]["max"] or cell["count"]["max"] == 3


# ---------------------------------------------------------------------------
# 两文件补集反推（合成反例）
# ---------------------------------------------------------------------------


def test_two_file_complement_inference_is_blocked(make_config, tmp_path):
    root = _two_file_root(tmp_path)
    config, _, manifest = _run_batch(make_config, root, tmp_path)
    summary = manifest["summary"]
    internal_risk = {d["level"]: d["count"] for d in summary["risk_distribution"]}
    assert internal_risk["none"] == 1 and internal_risk["high"] == 1

    # 合成反例：朴素方案只隐藏行级标签、保留精确汇总时，
    # 复核者由 files_total=2 与 none=1 必然补集反推出另一份是 high。
    naive_complement = summary["files_total"] - internal_risk["none"]
    assert naive_complement == internal_risk["high"] == 1

    # 联合发布检查：两份文件的画像组都小于 k，行级与汇总一起受限。
    _, view, texts = _export(config, tmp_path, "share", route="suppress")
    assert view["disclosure"]["protected_files"] == 2
    assert view["summary"]["risk_distribution"] == "suppressed"
    assert all(row["risk_level"] == "suppressed" for row in view["files"])
    data_blob = "\n".join(texts[key] for key in ("json", "md", "html"))
    assert "high" not in data_blob
    # 保留不泄密的类别级结果：编码决策、方法分布、文件总数仍可见
    assert view["summary"]["files_total"] == 2
    assert view["summary"]["method_distribution"]
    assert {row["encoding"] for row in view["files"]} == {"utf-8"}

    # interval 路线同样无法反算 high=1
    _, interval_view, _ = _export(config, tmp_path, "interval2", route="interval")
    risk = {d["level"]: d["count"] for d in interval_view["summary"]["risk_distribution"]}
    assert risk["high"] == {"min": 0, "max": 2}
    assert {row["risk_level"] for row in interval_view["files"]} == {
        "none_or_low",
        "medium_or_high",
    }


# ---------------------------------------------------------------------------
# 多格式字段一致
# ---------------------------------------------------------------------------


def test_tokens_and_decisions_consistent_across_formats(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, _, _ = _run_batch(make_config, root, tmp_path)
    _, view, texts = _export(config, tmp_path, "share", route="suppress")

    json_tokens = [row["file_token"] for row in view["files"]]
    assert len(json_tokens) == 3
    assert TOKEN_PATTERN.fullmatch(json_tokens[0])
    md_tokens = TOKEN_PATTERN.findall(texts["md"])
    html_tokens = TOKEN_PATTERN.findall(texts["html"])
    # 同一代号序列在 JSON/Markdown/HTML 内一致，可把同一决定与告警对应起来
    assert json_tokens == md_tokens == html_tokens
    for row in view["files"]:
        assert f"{row['file_token']} | {row['encoding']}" in texts["md"]
        html_row = re.search(
            rf"<tr><td>{row['file_token']}</td>(.*?)</tr>", texts["html"], re.S
        )
        assert html_row and row["encoding"] in html_row.group(1)
        assert row["method"] in html_row.group(1)


# ---------------------------------------------------------------------------
# 已知 SHA 字典识别
# ---------------------------------------------------------------------------


def test_known_sha_dictionary_cannot_identify_files(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, result, manifest = _run_batch(make_config, root, tmp_path)
    _, view, texts = _export(config, tmp_path, "share", route="suppress")
    blob = _all_text(texts)

    # 复核者持有已知源响应的 SHA-256 字典
    dictionary = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }
    for digest in dictionary.values():
        assert digest not in blob
    # 内部 manifest 的源/输出哈希、配置指纹、批次 ID 同样不得出现
    for entry in manifest["files"]:
        assert entry["source_sha256"] not in blob
        output_sha = entry["transcode"]["output_sha256"]
        if output_sha:
            assert output_sha not in blob
    assert config.fingerprint not in blob
    assert result["batch_id"] not in blob
    # 代号不是对路径的普通哈希
    for entry, row in zip(manifest["files"], view["files"]):
        plain = hashlib.sha256(entry["rel_path"].encode("utf-8")).hexdigest()
        assert plain[:10] not in row["file_token"]
        assert plain[:16] not in view["export_id"]


# ---------------------------------------------------------------------------
# 重复导出不默认可关联
# ---------------------------------------------------------------------------


def test_repeated_exports_are_not_linkable_by_default(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, result, _ = _run_batch(make_config, root, tmp_path)
    first, view_first, _ = _export(config, tmp_path, "first")
    second, view_second, _ = _export(config, tmp_path, "second")

    assert first["export_id"] != second["export_id"]
    tokens_first = {row["file_token"] for row in view_first["files"]}
    tokens_second = {row["file_token"] for row in view_second["files"]}
    assert tokens_first.isdisjoint(tokens_second)
    # 包内也不携带可关联两批的稳定标识（批次 ID / 配置指纹的值）
    assert result["batch_id"] not in json.dumps(view_first)
    assert config.fingerprint not in json.dumps(view_first)

    # 显式固定密钥时可复现（golden 场景），字节稳定
    again_a, _, _ = _export(config, tmp_path, "fixed_a", secret="fixed-secret")
    again_b, _, _ = _export(config, tmp_path, "fixed_b", secret="fixed-secret")
    json_a = Path(again_a["files"]["json"]).read_bytes()
    json_b = Path(again_b["files"]["json"]).read_bytes()
    assert json_a == json_b
    assert again_a["export_id"] == again_b["export_id"]


# ---------------------------------------------------------------------------
# 内部审计仍完整
# ---------------------------------------------------------------------------


def test_internal_audit_trail_remains_complete_after_export(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, result, manifest = _run_batch(make_config, root, tmp_path)
    _export(config, tmp_path, "share", route="suppress")
    _export(config, tmp_path, "interval", route="interval")
    _export(config, tmp_path, "forensic", contract="local_forensic")

    # manifest 仍保留路径、哈希与片段
    manifest_text = config.manifest_path.read_text(encoding="utf-8")
    assert "cases/alice.html" in manifest_text
    assert "Alice-ID" in manifest_text
    alice = next(row for row in manifest["files"] if "alice" in row["rel_path"])
    actual = hashlib.sha256((root / "cases" / "alice.html").read_bytes()).hexdigest()
    assert alice["source_sha256"] == actual
    # report.json 仍保留输出哈希与精确分布
    report = json.loads((config.reports_dir / "report.json").read_text(encoding="utf-8"))
    assert report["files"][0]["output_sha256"]
    risk = {d["level"]: d["count"] for d in report["summary"]["risk_distribution"]}
    assert risk["high"] == 1
    # SQLite 台账仍保留字节摘要
    import sqlite3

    connection = sqlite3.connect(config.db_path)
    try:
        row = connection.execute(
            "SELECT source_sha256, risk_level FROM files WHERE rel_path = ?",
            ("cases/alice.html",),
        ).fetchone()
        assert row[0] == actual and row[1] == "high"
    finally:
        connection.close()
    # 本地只读复核台仍显示完整明细
    client = create_app(config).test_client()
    detail = client.get(f"/file/{result['batch_id']}/cases/alice.html")
    assert detail.status_code == 200
    assert b"cases/alice.html" in detail.data
    assert actual.encode() in detail.data


# ---------------------------------------------------------------------------
# 空批次与正常批次
# ---------------------------------------------------------------------------


def test_empty_batch_exports_cleanly(make_config, tmp_path):
    root = tmp_path / "responses"
    root.mkdir()
    config, result, manifest = _run_batch(make_config, root, tmp_path)
    assert manifest["summary"]["files_total"] == 0

    _, view, texts = _export(config, tmp_path, "share")
    assert view["files"] == []
    assert view["summary"]["files_total"] == 0
    assert view["disclosure"]["protected_files"] == 0
    # 空批次没有低样本组，分布按精确（全零）发布
    assert view["summary"]["risk_distribution"] == [
        {"level": level, "count": 0} for level in ("none", "low", "medium", "high")
    ]
    assert "无" in texts["md"]
    assert "无文件" in texts["html"]
    # 取证合同同样可用
    exported, _, _ = _export(config, tmp_path / "unused", "forensic", contract="local_forensic")
    forensic = json.loads(Path(exported["files"]["json"]).read_text(encoding="utf-8"))
    assert forensic["files"] == []
    # 复核台共享预览对空批次返回 200
    client = create_app(config).test_client()
    page = client.get(f"/batch/{result['batch_id']}/share")
    assert page.status_code == 200
    assert "本批次没有文件" in page.data.decode("utf-8")


def test_normal_batch_without_sensitive_groups_publishes_exact(make_config, tmp_path):
    root = _normal_root(tmp_path)
    config, _, _ = _run_batch(make_config, root, tmp_path)
    _, view, texts = _export(config, tmp_path, "share", route="suppress")

    # 没有低样本组：类别级精确结果全部保留，不做一律清零
    assert view["disclosure"]["protected_files"] == 0
    assert all(d["status"] == "exact" for d in view["disclosure"]["dimensions"].values())
    assert view["summary"]["risk_distribution"] == [
        {"level": "none", "count": 2},
        {"level": "low", "count": 2},
        {"level": "medium", "count": 0},
        {"level": "high", "count": 0},
    ]
    assert view["summary"]["warning_distribution"] == [
        {"code": "W_QUESTION_RUNS", "count": 2, "severity": "low"}
    ]
    assert view["summary"]["warnings_total"] == 2
    # 共享数据里没有任何被抑制的取值
    def values(node):
        if isinstance(node, dict):
            for value in node.values():
                yield from values(value)
        elif isinstance(node, list):
            for value in node:
                yield from values(value)
        else:
            yield node

    assert "suppressed" not in list(values(view["summary"]))
    assert "suppressed" not in list(values(view["files"]))
    for row in view["files"]:
        assert row["risk_level"] in {"none", "low"}
        assert isinstance(row["warning_count"], int)


# ---------------------------------------------------------------------------
# schema 机器检查
# ---------------------------------------------------------------------------


def test_shared_package_matches_machine_checkable_schema(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, _, _ = _run_batch(make_config, root, tmp_path)
    result, view, texts = _export(config, tmp_path, "share", route="suppress")

    schema = json.loads(texts["schema"])
    assert schema == SHARE_SCHEMA
    assert schema["contract"] == "share_review"
    # 顶层字段与声明一致
    assert list(view.keys()) == schema["top_level_fields"]
    # 逐文件字段恰好是允许清单
    for row in view["files"]:
        assert set(row.keys()) == set(schema["file_fields"].keys())
        assert re.fullmatch(r"F-[0-9a-f]{10}", row["file_token"])
    assert re.fullmatch(r"X-[0-9a-f]{12}", view["export_id"])
    # 抑制字段清单与投影模块同源
    assert schema["suppressed_internal_fields"] == list(SUPPRESSED_INTERNAL_FIELDS)

    forbidden = set(schema["suppressed_internal_fields"])

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                assert key not in forbidden
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(view)
    # 导出批次身份说明可机器读取
    identity = schema["export_identity"]
    assert "export_id" in identity and "file_token" in identity
    assert view["disclosure"]["mapping_note"]


# ---------------------------------------------------------------------------
# 统一投影：三个入口一致
# ---------------------------------------------------------------------------


def test_reporting_entry_matches_export_package(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, _, manifest = _run_batch(make_config, root, tmp_path)
    policy = SharePolicy(route="suppress", audit_contact=config.share_audit_contact)
    via_reporting = build_report(
        manifest,
        None,
        NOW,
        contract=CONTRACT_SHARE_REVIEW,
        policy=policy,
        export_secret="fixed-secret",
    )
    exported, _, _ = _export(config, tmp_path, "share", route="suppress", secret="fixed-secret")
    via_disk = json.loads(Path(exported["files"]["json"]).read_text(encoding="utf-8"))
    assert via_reporting == via_disk


def test_web_projection_matches_manifest_projection(run_demo):
    config, result = run_demo()
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    rows_manifest = build_internal_rows(manifest)
    rows_ledger = _ledger_internal_rows(config.db_path, result["batch_id"])
    policy = SharePolicy()
    view_manifest = build_shared_view(
        rows_manifest, manifest["summary"], policy, NOW, "fixed-secret"
    )
    view_ledger = build_shared_view(
        rows_ledger, summarize_internal(rows_ledger), policy, NOW, "fixed-secret"
    )
    assert view_manifest == view_ledger
    # 台账重建的汇总与 manifest 汇总一致
    assert summarize_internal(rows_manifest) == manifest["summary"]


def test_web_share_preview_is_readonly_and_anonymized(run_demo):
    config, result = run_demo()
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    client = create_app(config).test_client()

    page = client.get(f"/batch/{result['batch_id']}/share")
    assert page.status_code == 200
    text = page.data.decode("utf-8")
    assert TOKEN_PATTERN.search(text)
    assert "已抑制" in text  # demo 批次存在低样本组
    assert config.scan_root.as_posix() not in text
    for entry in manifest["files"]:
        assert entry["rel_path"] not in text
        assert entry["source_sha256"] not in text
    assert b"<form" not in page.data.lower()
    assert page.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'none'" in page.headers["Content-Security-Policy"]
    # 预览是只读的
    assert client.post(f"/batch/{result['batch_id']}/share").status_code == 405
    assert client.get("/batch/does-not-exist/share").status_code == 404
    # 内部批次页仍显示完整路径
    internal = client.get(f"/batch/{result['batch_id']}")
    assert "gb18030_with_utf8_meta.html" in internal.data.decode("utf-8")


# ---------------------------------------------------------------------------
# 配置与 CLI
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, root: Path, sharing: dict | None) -> Path:
    data = {
        "scan": {"root": str(root)},
        "output": {"dir": str((tmp_path / "out").resolve())},
    }
    if sharing is not None:
        data["sharing"] = sharing
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def test_sharing_config_defaults_and_validation(make_config, tmp_path):
    config = make_config()
    assert config.share_route == "suppress"
    assert config.share_min_group_size == 2
    assert config.share_audit_contact == "local-audit@example.invalid"
    assert config.export_dir == config.out_dir / "shared"

    root = tmp_path / "responses"
    root.mkdir()
    (root / "a.txt").write_text("ok", encoding="utf-8")
    for bad in (
        {"route": "wipe"},
        {"min_group_size": 1},
        {"min_group_size": "2"},
        {"audit_contact": ""},
    ):
        path = _write_config(tmp_path, root, bad)
        with pytest.raises(ConfigError):
            load_config(path)


def test_export_requires_pipeline_first(make_config, tmp_path):
    config = make_config()
    with pytest.raises(Exception, match="pipeline"):
        build_export(config, contract="share_review", now=NOW)


def test_export_refuses_output_inside_scan_root(make_config, tmp_path):
    root = _alice_root(tmp_path)
    config, _, _ = _run_batch(make_config, root, tmp_path)
    with pytest.raises(Exception, match="扫描源目录"):
        build_export(
            config,
            contract="share_review",
            now=NOW,
            output_dir=str(root / "shared"),
        )


def test_cli_export_end_to_end(make_config, now):
    config = make_config()
    env = {"PATH": "/usr/bin:/bin"}
    repo = Path(__file__).resolve().parents[1]

    def cli(*args):
        return subprocess.run(
            [sys.executable, "-m", "decodebench", *args],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )

    # 未运行 pipeline 时导出失败
    failed = cli("export", "--config", str(config.config_path))
    assert failed.returncode == 2

    ok = cli("pipeline", "--config", str(config.config_path), "--now", now)
    assert ok.returncode == 0, ok.stderr

    shared = cli(
        "export",
        "--config",
        str(config.config_path),
        "--contract",
        "share_review",
        "--route",
        "interval",
        "--now",
        now,
    )
    assert shared.returncode == 0, shared.stderr
    payload = json.loads(shared.stdout)
    assert payload["contract"] == "share_review"
    assert payload["route"] == "interval"
    assert payload["protected_files"] >= 1
    for path in payload["files"].values():
        assert Path(path).is_file()

    forensic = cli(
        "export",
        "--config",
        str(config.config_path),
        "--contract",
        "local_forensic",
        "--now",
        now,
    )
    assert forensic.returncode == 0, forensic.stderr
    payload = json.loads(forensic.stdout)
    assert payload["batch_id"]
    forensic_view = json.loads(Path(payload["files"]["json"]).read_text(encoding="utf-8"))
    assert forensic_view["files"][0]["rel_path"]
    assert forensic_view["files"][0]["output_sha256"]
