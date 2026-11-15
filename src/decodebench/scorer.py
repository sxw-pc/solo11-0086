"""候选编码的确定性评分与统计胜出选择。"""

from __future__ import annotations

from .detectors import canonical_encoding, decode_sample, looks_utf16
from .models import CandidateResult, DecodedSample


def score_sample(sample: DecodedSample, raw: bytes) -> float:
    """把严格解码后的字符统计折算为 0..1 的稳定分数。"""
    if not sample.success:
        return 0.0
    total = max(1, sample.decoded_chars)
    replacement_ratio = sample.replacement_count / total
    penalty = (
        sample.control_ratio * 3.0
        + sample.private_ratio * 4.0
        + sample.unassigned_ratio * 2.5
        + replacement_ratio * 3.0
        + (1.0 - sample.printable_ratio) * 2.0
    )
    score = 1.0 - penalty
    encoding = sample.encoding

    if encoding == "utf-8":
        score += 0.04
    if encoding in {"gb18030", "big5", "big5-hkscs"}:
        if sample.high_byte_ratio >= 0.12:
            if sample.cjk_ratio >= 0.10:
                score += min(0.16, 0.06 + sample.cjk_ratio * 0.25)
            else:
                score -= 0.12
        else:
            score -= 0.18
    if encoding in {"windows-1252", "latin-1"}:
        if sample.high_byte_ratio > 0.25:
            score -= 0.06
        if sample.ascii_ratio > 0.9:
            score += 0.03
    if encoding in {"utf-16-le", "utf-16-be", "utf-16"}:
        if looks_utf16(raw):
            score += 0.05
        else:
            score -= 0.75
    if encoding == "ascii" and sample.high_byte_ratio > 0:
        score -= 0.5
    return max(0.0, min(1.0, score))


def analyze_candidates(raw: bytes, encodings: tuple[str, ...]) -> list[CandidateResult]:
    """按配置顺序解码并评分；重复的规范编码只保留首个。"""
    results: list[CandidateResult] = []
    seen: set[str] = set()
    for requested in encodings:
        encoding = canonical_encoding(requested)
        if not encoding or encoding in seen:
            continue
        seen.add(encoding)
        sample = decode_sample(raw, encoding)
        results.append(
            CandidateResult(
                encoding=encoding,
                success=sample.success,
                score=score_sample(sample, raw),
                decoded_chars=sample.decoded_chars,
                replacement_count=sample.replacement_count,
                control_ratio=sample.control_ratio,
                printable_ratio=sample.printable_ratio,
                cjk_ratio=sample.cjk_ratio,
                latin_ratio=sample.latin_ratio,
                unassigned_ratio=sample.unassigned_ratio,
                private_ratio=sample.private_ratio,
                ascii_ratio=sample.ascii_ratio,
                error=sample.error,
            )
        )
    return results


def choose_best(candidates: list[CandidateResult]) -> tuple[CandidateResult | None, float]:
    """按分数降序、配置顺序升序选出统计获胜者及置信度。"""
    indexed = [
        (index, candidate)
        for index, candidate in enumerate(candidates)
        if candidate.success
    ]
    if not indexed:
        return None, 0.0
    indexed.sort(key=lambda item: (-item[1].score, item[0]))
    winner = indexed[0][1]
    runner_up = indexed[1][1].score if len(indexed) > 1 else 0.0
    margin = max(0.0, winner.score - runner_up)
    confidence = min(0.95, 0.55 + winner.score * 0.25 + margin * 0.15)
    return winner, confidence


def ranking(candidates: list[CandidateResult]) -> list[dict[str, object]]:
    """用于证据说明的紧凑排名。"""
    ordered = sorted(
        enumerate(candidates),
        key=lambda item: (not item[1].success, -item[1].score, item[0]),
    )
    return [
        {"encoding": candidate.encoding, "score": round(candidate.score, 6)}
        for _, candidate in ordered
    ]
