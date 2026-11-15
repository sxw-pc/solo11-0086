from __future__ import annotations

from decodebench.mojibake import analyze, diagnose_bytes, to_warning_items


def test_mojibake_findings_are_localized_and_high_risk(make_config):
    config = make_config()
    text = (
        "line one\n"
        + "bad "
        + chr(0xFFFD)
        + " Ã© ??? "
        + chr(1)
        + " \\ud83d"
        + "\n"
    )
    report = analyze(text, config)
    assert report.level == "high"
    codes = {item["code"] for item in report.findings}
    assert {
        "W_REPLACEMENT_CHARS",
        "W_MOJIBAKE_SEQUENCE",
        "W_CONTROL_CHARS",
        "W_QUESTION_RUNS",
        "W_SURROGATE_TRACE",
    } <= codes
    replacement = next(
        item for item in report.findings if item["code"] == "W_REPLACEMENT_CHARS"
    )
    assert replacement["line"] == 2
    assert replacement["offset"] == len("line one\nbad ")
    assert replacement["snippet"]
    assert "不要自动" in report.recommendation
    warnings = to_warning_items(report)
    assert len(warnings) == len(report.findings)
    assert all(item.line == 2 for item in warnings)


def test_clean_text_has_no_findings(make_config):
    report = analyze("正常的中文正文与 ASCII text。\n", make_config())
    assert report.level == "none"
    assert report.findings == []
    assert "未发现" in report.recommendation


def test_question_run_only_is_low_risk(make_config):
    report = analyze("placeholder ???", make_config())
    assert report.level == "low"
    assert [item["code"] for item in report.findings] == ["W_QUESTION_RUNS"]


def test_diagnose_bytes_uses_replacement_without_writing(make_config):
    config = make_config()
    raw = "异常 " + chr(0xFFFD) + "\n"
    report = diagnose_bytes(raw.encode("utf-8"), "utf-8", config)
    assert report.level == "high"
    assert report.findings[0]["code"] == "W_REPLACEMENT_CHARS"
    assert not config.transcode_dir.exists()
