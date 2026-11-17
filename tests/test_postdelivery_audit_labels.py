"""事后审计：标签绑定、未回应/undecidable、输出缺失与报告集成。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from decodebench.audit import (
    AuditError,
    apply_labels,
    build_audit_plan,
    estimate_delivery_audit,
    make_label,
)
from decodebench.ledger import batch_identity_from_manifest
from decodebench.ledger_queries import list_delivered_files
from decodebench.manifest import build_audit_frame
from decodebench.report_html import render_html
from decodebench.reporting import build_report, render_markdown


def test_tampered_frame_and_plan_are_rejected(audit_inputs):
    from decodebench.audit_common import digest

    frame = audit_inputs(
        [{"rel": f"f{i}.txt", "out": 100, "risk": "none"} for i in range(4)]
    )
    tampered_frame = json.loads(json.dumps(frame))
    tampered_frame["delivered_files"][0]["output_bytes"] = 1
    with pytest.raises(AuditError):
        build_audit_plan(tampered_frame, budget=2, seed=0)
    plan = build_audit_plan(frame, budget=2, seed=0)
    body = {key: value for key, value in plan.items() if key != "plan_digest"}
    assert digest(body) == plan["plan_digest"]
    body["strata"][0]["inclusion_probability"] = 0.01
    assert digest(body) != plan["plan_digest"]


def test_undecidable_nonresponse_and_missing_output_are_not_correct(
    audit_frame_from_manifest, audit_writer, tmp_path
):
    manifest = audit_frame_from_manifest(
        [
            {"rel": "a.txt", "out": 100, "risk": "none"},
            {"rel": "b.txt", "out": 200, "risk": "none"},
            {"rel": "c.txt", "out": 300, "risk": "none"},
        ]
    )
    audit_writer(tmp_path, manifest)
    frame = build_audit_frame(manifest)
    plan = build_audit_plan(frame, budget=3, seed=0)
    (tmp_path / "c.txt").unlink()
    labels = [
        make_label(plan, "a.txt", "undecidable"),
        make_label(plan, "c.txt", "correct"),
    ]
    estimate = estimate_delivery_audit(plan, frame, labels, output_root=tmp_path)
    counts = estimate["unit_counts"]
    assert counts["undecidable_files"] == 1
    assert counts["no_response_files"] == 1
    assert counts["missing_output_files"] == 1
    assert counts["responded_files"] == 0
    assert counts["unreviewed_files_never_counted_correct"] is True
    assert estimate["complete_response"] is False
    assert estimate["file_lens"]["wrong_files_estimate"] == 0.0
    assert estimate["file_lens"]["upper_bound_95"] == 3
    status = {row["rel_path"]: row for row in estimate["label_status"]}
    assert status["b.txt"]["reason"] == "未收到人工标签"
    assert "缺失" in status["c.txt"]["reason"]


def test_labels_are_bound_to_plan_and_output_version(
    audit_frame_from_manifest, audit_writer, tmp_path
):
    manifest = audit_frame_from_manifest(
        [{"rel": f"f{i}.txt", "out": 100, "risk": "none"} for i in range(4)]
    )
    audit_writer(tmp_path, manifest)
    frame = build_audit_frame(manifest)
    plan = build_audit_plan(frame, budget=2, seed=3)
    sampled = plan["sample"][0]["rel_path"]
    label = make_label(plan, sampled, "correct")
    with pytest.raises(AuditError):
        apply_labels(plan, [dict(label, source_sha256="other")])
    with pytest.raises(AuditError):
        apply_labels(plan, [label, dict(label)])
    other_plan = build_audit_plan(frame, budget=2, seed=99)
    with pytest.raises(AuditError):
        apply_labels(other_plan, [label])
    unsampled = [u["rel_path"] for u in plan["units"] if not u["sampled"]][0]
    with pytest.raises(AuditError):
        make_label(plan, unsampled, "correct")
    (tmp_path / sampled).write_bytes(b"changed")
    with pytest.raises(AuditError):
        estimate_delivery_audit(plan, frame, [label], output_root=tmp_path)
    tampered = dict(plan)
    tampered["strata"] = [dict(row) for row in plan["strata"]]
    tampered["strata"][0]["inclusion_probability"] = 0.99
    with pytest.raises(AuditError):
        apply_labels(tampered, [label])


def test_audit_cli_is_read_only_and_reports_estimability(run_demo, now):
    config, result = run_demo()
    before = config.manifest_path.read_bytes()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "decodebench",
            "audit",
            "--config",
            str(config.config_path),
            "--budget",
            "3",
            "--seed",
            "7",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert process.returncode == 0, process.stderr
    payload = json.loads(process.stdout)
    assert payload["frame"]["batch_id"] == result["batch_id"]
    assert payload["plan"]["estimable"] is True
    assert payload["estimate"]["estimate_type"] == "design_weighted_estimate"
    assert config.manifest_path.read_bytes() == before


def test_audit_binds_real_batch_and_never_feeds_back(run_demo, now):
    config, result = run_demo()
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    frame = build_audit_frame(manifest)
    assert frame["batch_id"] == result["batch_id"]
    assert frame["batch_key"] == batch_identity_from_manifest(manifest)[0]
    ledger_paths = {
        row["rel_path"]
        for row in list_delivered_files(config.db_path, result["batch_id"])
    }
    assert ledger_paths == {unit["rel_path"] for unit in frame["delivered_files"]}
    plan = build_audit_plan(frame, budget=len(frame["delivered_files"]), seed=0)
    labels = [
        make_label(plan, unit["rel_path"], "correct") for unit in plan["sample"]
    ]
    estimate = estimate_delivery_audit(plan, frame, labels)
    assert estimate["frame_digest"] == frame["frame_digest"]
    plain = build_report(manifest, result["ledger"], now)
    audited = build_report(manifest, result["ledger"], now, estimate)
    assert audited["files"] == plain["files"]
    assert audited["summary"] == plain["summary"]
    assert "postdelivery_audit" not in plain
    assert audited["postdelivery_audit"]["frame_digest"] == frame["frame_digest"]
    markdown = render_markdown(audited)
    html = render_html(audited)
    assert "## 事后人工抽样审计" in markdown
    assert "错误文件数" in html and "事后人工抽样审计" in html
    assert "http://" not in html.lower() and "<script" not in html.lower()
    assert manifest == json.loads(config.manifest_path.read_text(encoding="utf-8"))
