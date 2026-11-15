from __future__ import annotations

import hashlib
import json

from decodebench.pipeline import run


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_reports_are_byte_stable_with_fixed_now(run_demo, now):
    config, first = run_demo()
    paths = [
        config.manifest_path,
        config.reports_dir / "report.json",
        config.reports_dir / "report.md",
        config.reports_dir / "report.html",
    ]
    assert all(path.is_file() for path in paths)
    first_hashes = {path.name: _hash(path) for path in paths}
    second = run(config, now)
    second_hashes = {path.name: _hash(path) for path in paths}
    assert first_hashes == second_hashes
    assert first["batch_id"] == second["batch_id"]

    manifest_text = config.manifest_path.read_text(encoding="utf-8")
    assert manifest_text.index('"schema_version"') < manifest_text.index('"summary"')
    assert manifest_text.index('"summary"') < manifest_text.index('"files"')
    manifest = json.loads(manifest_text)
    assert manifest["project"] == "decodebench"
    assert manifest["generated_at"] == now
    assert manifest["summary"]["files_total"] == 10
    assert manifest["summary"]["conflict_files"] == 1
    assert manifest["summary"]["transcode_success"] == 10
    assert manifest["summary"]["warning_distribution"]
    assert [item["rel_path"] for item in manifest["files"]] == sorted(
        item["rel_path"] for item in manifest["files"]
    )

    report = json.loads((config.reports_dir / "report.json").read_text(encoding="utf-8"))
    assert report["generated_at"] == now
    assert report["batch_id"] == first["batch_id"]
    assert report["ledger"]["files_in_batch"] == 10
    assert report["files"] == sorted(report["files"], key=lambda item: item["rel_path"])
    assert all(row["warning_codes"] == sorted(row["warning_codes"]) for row in report["files"])
    conflict_row = next(row for row in report["files"] if row["conflict"])
    assert conflict_row["rel_path"] == "gb18030_with_utf8_meta.html"
    assert "E_META_BYTE_CONFLICT" in conflict_row["error_codes"]

    html = (config.reports_dir / "report.html").read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "<style>" in html
    assert "<script" not in html.lower()
    assert "http://" not in html.lower()
    assert "https://" not in html.lower()
    assert "<link " not in html.lower()
    assert "src=" not in html.lower()
    assert "采文解码台诊断报告" in html

    markdown = (config.reports_dir / "report.md").read_text(encoding="utf-8")
    assert "## 警告分布" in markdown
    assert "## SQLite 台账摘要" in markdown
    assert "gb18030_with_utf8_meta.html" in markdown
