"""事后人工抽样审计：抽样框、分层抽样、双口径与保守上界。"""

from __future__ import annotations

import json

import pytest

from decodebench.audit import (
    build_audit_plan,
    estimate_delivery_audit,
    make_label,
)
from decodebench.manifest import build_audit_frame


def _labels(plan, verdicts=None):
    verdicts = verdicts or {}
    return [
        make_label(plan, unit["rel_path"], verdicts.get(unit["rel_path"], "correct"))
        for unit in plan["sample"]
    ]


def test_frame_freezes_delivered_units_and_batch_identity(audit_frame_from_manifest):
    from decodebench.ledger import batch_identity_from_manifest

    manifest = audit_frame_from_manifest(
        [
            {"rel": "b.txt", "out": 200, "risk": "high"},
            {"rel": "a.txt", "out": 100, "risk": "none"},
            {"rel": "broken.txt", "risk": "high", "ok": False},
        ]
    )
    frame = build_audit_frame(manifest)
    assert [unit["rel_path"] for unit in frame["delivered_files"]] == ["a.txt", "b.txt"]
    assert [row["rel_path"] for row in frame["excluded_files"]] == ["broken.txt"]
    assert frame["population"]["delivered_files"] == 2
    assert frame["population"]["delivered_output_bytes"] == 300
    unit = frame["delivered_files"][1]
    assert unit["source_sha256"] == "src-b.txt"
    assert unit["output_bytes"] == 200
    assert unit["risk_level"] == "high"
    assert frame["batch_id"] == batch_identity_from_manifest(manifest)[1]
    frozen = json.loads(json.dumps(frame))
    assert frozen == frame
    manifest["files"][0]["transcode"]["bytes_written"] = 999999
    assert build_audit_frame(manifest)["frame_digest"] != frame["frame_digest"]


def test_stratified_plan_records_design_and_is_seed_deterministic(audit_inputs):
    frame = audit_inputs(
        [{"rel": f"high_{i}.txt", "out": 100, "risk": "high"} for i in range(5)]
        + [{"rel": f"none_{i}.txt", "out": 100, "risk": "none"} for i in range(3)]
        + [{"rel": f"low_{i}.txt", "out": 100, "risk": "low"} for i in range(2)]
    )
    first = build_audit_plan(frame, budget=5, seed=11)
    second = build_audit_plan(frame, budget=5, seed=11)
    assert first == second
    assert first["design"] == "stratified_srs_without_replacement"
    assert first["estimable"] is True
    assert sum(row["sample_size"] for row in first["strata"]) == 5
    assert all(row["sample_size"] >= 1 for row in first["strata"])
    for row in first["strata"]:
        assert row["sample_size"] <= row["population"]
        assert row["inclusion_probability"] == row["sample_size"] / row["population"]
        assert row["inclusion_probability"] > 0
        assert len(row["sampled_paths"]) == row["sample_size"]
    sampled = [unit["rel_path"] for unit in first["sample"]]
    assert len(sampled) == len(set(sampled)) == 5
    assert {unit["stratum_population"] for unit in first["units"]} == {5, 3, 2}
    assert build_audit_plan(frame, budget=5, seed=12)["sample"] != first["sample"]


def test_budget_below_nonempty_strata_is_not_estimable(audit_inputs):
    frame = audit_inputs(
        [
            {"rel": "a.txt", "out": 100, "risk": "high"},
            {"rel": "b.txt", "out": 100, "risk": "high"},
            {"rel": "c.txt", "out": 100, "risk": "none"},
        ]
    )
    plan = build_audit_plan(frame, budget=1, seed=1)
    assert plan["estimable"] is False
    assert "budget" in plan["blocking_reason"]
    assert any(row["sample_size"] == 0 and row["population"] > 0 for row in plan["strata"])
    estimate = estimate_delivery_audit(plan, frame, [])
    assert estimate["estimable"] is False
    assert estimate["file_lens"]["wrong_files_estimate"] is None
    assert estimate["byte_lens"]["upper_bound_95"] is None
    assert estimate["thresholds"]["file_verdict"] == "insufficient"
    assert estimate["thresholds"]["byte_verdict"] == "insufficient"


def test_full_census_eleven_file_reverse_case_yields_two_verdicts(audit_inputs):
    frame = audit_inputs(
        [{"rel": "big_wrong.txt", "out": 1024 * 1024, "risk": "none"}]
        + [{"rel": f"small_{i}.txt", "out": 100, "risk": "none"} for i in range(10)]
    )
    plan = build_audit_plan(frame, budget=11, seed=7)
    assert plan["estimable"] and len(plan["sample"]) == 11
    estimate = estimate_delivery_audit(plan, frame, _labels(plan, {"big_wrong.txt": "wrong"}))
    assert estimate["estimate_type"] == "census"
    assert estimate["file_lens"]["wrong_files_estimate"] == 1.0
    assert estimate["file_lens"]["wrong_file_ratio_estimate"] == pytest.approx(1 / 11)
    assert estimate["file_lens"]["wrong_file_ratio_estimate"] < 0.10
    assert estimate["byte_lens"]["exposed_wrong_output_byte_ratio_estimate"] > 0.99
    assert estimate["byte_lens"]["exposed_wrong_output_bytes_estimate"] == 1024 * 1024
    assert estimate["thresholds"]["file_verdict"] == "within"
    assert estimate["thresholds"]["byte_verdict"] == "exceeds"
    assert estimate["byte_lens"]["not_exact_error_bytes"] is True


def test_byte_lens_weights_output_bytes_not_counts_or_source_bytes(audit_inputs):
    frame = audit_inputs(
        [
            {"rel": "big.txt", "out": 9900, "src": 1, "risk": "none", "warnings": 9},
            {"rel": "tiny_0.txt", "out": 100, "src": 10**6, "risk": "none"},
            {"rel": "tiny_1.txt", "out": 100, "src": 10**6, "risk": "none"},
            {"rel": "tiny_2.txt", "out": 100, "src": 10**6, "risk": "none"},
        ]
    )
    plan = build_audit_plan(frame, budget=4, seed=0)
    estimate = estimate_delivery_audit(plan, frame, _labels(plan, {"big.txt": "wrong"}))
    byte_lens = estimate["byte_lens"]
    assert byte_lens["denominator_output_bytes"] == 9900 + 300
    assert byte_lens["exposed_wrong_output_byte_ratio_estimate"] == pytest.approx(9900 / 10200)
    assert estimate["file_lens"]["wrong_file_ratio_estimate"] == pytest.approx(0.25)
    assert estimate["weights"]["bytes"] == "output_bytes / inclusion_probability"
    assert "source_size" not in byte_lens
    assert estimate["total_output_bytes"] == 9900 + 300


def test_short_budget_uses_design_bound_not_mean_file_size(audit_inputs):
    frame = audit_inputs(
        [{"rel": "huge.txt", "out": 1024 * 1024, "risk": "none"}]
        + [{"rel": f"tiny_{i:02d}.txt", "out": 100, "risk": "none"} for i in range(99)]
    )
    plan = next(
        build_audit_plan(frame, budget=1, seed=seed)
        for seed in range(200)
        if build_audit_plan(frame, budget=1, seed=seed)["sample"][0]["rel_path"] != "huge.txt"
    )
    estimate = estimate_delivery_audit(plan, frame, _labels(plan))
    assert estimate["estimable"] is True
    assert estimate["estimate_type"] == "design_weighted_estimate"
    assert estimate["file_lens"]["wrong_files_estimate"] == 0.0
    count_upper = estimate["file_lens"]["upper_bound_95"]
    byte_upper = estimate["byte_lens"]["upper_bound_95"]
    assert 0 < count_upper < 100
    assert byte_upper >= 1024 * 1024
    mean_size = estimate["total_output_bytes"] / 100
    assert byte_upper > count_upper * mean_size
    assert byte_upper <= estimate["total_output_bytes"]
    none_row = estimate["strata"][0]
    assert none_row["upper_exposed_bytes_95"] == byte_upper
    assert none_row["byte_upper_method"] == "largest_output_bytes_within_file_count_bound"


def test_joint_confidence_is_split_across_strata(audit_inputs):
    frame = audit_inputs(
        [
            {"rel": "h1.txt", "out": 100, "risk": "high"},
            {"rel": "h2.txt", "out": 100, "risk": "high"},
            {"rel": "n1.txt", "out": 100, "risk": "none"},
            {"rel": "n2.txt", "out": 100, "risk": "none"},
        ]
    )
    plan = build_audit_plan(frame, budget=2, seed=2)
    estimate = estimate_delivery_audit(plan, frame, _labels(plan))
    assert estimate["confidence_allocation"] == "bonferroni_equal_split_across_nonempty_strata"
    assert estimate["per_stratum_alpha"] == pytest.approx(0.05 / 2)
    per_stratum = sum(row["upper_wrong_files_95"] for row in estimate["strata"])
    assert estimate["file_lens"]["upper_bound_95"] == pytest.approx(min(per_stratum, 4))
    assert estimate["thresholds"]["file_verdict"] == "insufficient"


def test_threshold_between_bounds_is_insufficient_for_both_lenses(audit_inputs):
    frame = audit_inputs(
        [{"rel": f"f{i}.txt", "out": 100, "risk": "none"} for i in range(10)]
    )
    plan = build_audit_plan(frame, budget=1, seed=4)
    estimate = estimate_delivery_audit(plan, frame, [])
    assert estimate["file_lens"]["lower_ratio"] <= 0.10 < estimate["file_lens"]["upper_ratio_95"]
    assert estimate["byte_lens"]["lower_ratio"] <= 0.10 < estimate["byte_lens"]["upper_ratio_95"]
    assert estimate["thresholds"]["file_verdict"] == "insufficient"
    assert estimate["thresholds"]["byte_verdict"] == "insufficient"
