from __future__ import annotations

from pathlib import Path

from decodebench.models import CandidateResult
from decodebench.scorer import analyze_candidates, choose_best, ranking, score_sample
from decodebench.detectors import decode_sample

RESPONSES = Path(__file__).resolve().parents[1] / "fixtures" / "responses"


def test_gb18030_wins_statistical_ranking(make_config):
    config = make_config()
    raw = (RESPONSES / "gb18030_no_meta.html").read_bytes()
    candidates = analyze_candidates(raw, config.candidate_encodings)
    winner, confidence = choose_best(candidates)
    assert winner is not None
    assert winner.encoding == "gb18030"
    assert winner.score >= 0.9
    assert winner.cjk_ratio > 0.1
    assert confidence > config.minimum_confidence
    failed_utf8 = next(item for item in candidates if item.encoding == "utf-8")
    assert failed_utf8.success is False
    assert failed_utf8.score == 0.0


def test_windows_1252_wins_for_latin_capture(make_config):
    config = make_config()
    raw = (RESPONSES / "plain_latin.txt").read_bytes()
    candidates = analyze_candidates(raw, config.candidate_encodings)
    winner, _ = choose_best(candidates)
    assert winner is not None
    assert winner.encoding == "windows-1252"
    assert "latin-1" in {item.encoding for item in candidates}


def test_candidate_analysis_is_deterministic(make_config):
    config = make_config()
    raw = (RESPONSES / "utf8_meta.html").read_bytes()
    first = [item.to_dict() for item in analyze_candidates(raw, config.candidate_encodings)]
    second = [item.to_dict() for item in analyze_candidates(raw, config.candidate_encodings)]
    assert first == second
    utf8 = next(item for item in first if item["encoding"] == "utf-8")
    assert utf8["success"] is True
    assert utf8["score"] >= 0.95


def test_empty_and_invalid_candidates_have_low_scores():
    assert choose_best([]) == (None, 0.0)
    failed = CandidateResult(
        encoding="utf-8",
        success=False,
        score=0.0,
        decoded_chars=0,
        replacement_count=0,
        control_ratio=0,
        printable_ratio=0,
        cjk_ratio=0,
        latin_ratio=0,
        unassigned_ratio=0,
        private_ratio=0,
        ascii_ratio=0,
        error="invalid",
    )
    assert choose_best([failed]) == (None, 0.0)
    assert ranking([failed]) == [{"encoding": "utf-8", "score": 0.0}]


def test_control_characters_reduce_score():
    clean = decode_sample("plain ASCII".encode("utf-8"), "utf-8")
    noisy = decode_sample(b"abc\x01\x02\x03def", "latin-1")
    assert score_sample(clean, clean.text.encode("utf-8")) > score_sample(noisy, b"abc\x01\x02\x03def")
