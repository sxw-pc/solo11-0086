"""在带旁证的片段集合上枚举一致的完整组合。

枚举是确定性的：片段按 (byte_start, byte_end_inclusive, rel_path) 排序，
结果按 (sha256, rel_paths) 排序。预算不足只报预算不足，不声称唯一。
"""

from __future__ import annotations

import hashlib
from typing import Any

from .fragments import union_gaps
from .models import Combination, GroupResult, LoadedFragment

BUDGET_STATUS = "budget_exhausted"


def first_overlap_conflict(
    left: LoadedFragment, right: LoadedFragment
) -> dict[str, Any] | None:
    low = max(left.decl.byte_start, right.decl.byte_start)
    high = min(left.decl.byte_end_inclusive, right.decl.byte_end_inclusive)
    if low > high:
        return None
    left_data = left.raw or b""
    right_data = right.raw or b""
    for offset in range(low, high + 1):
        value_left = left_data[offset - left.decl.byte_start]
        value_right = right_data[offset - right.decl.byte_start]
        if value_left != value_right:
            return {
                "kind": "overlap_conflict",
                "byte_offset": offset,
                "left": {
                    "rel_path": left.rel_path,
                    "capture_id": left.decl.capture_id,
                    "byte": bytes([value_left]).hex(),
                    "sha256": left.sha256,
                },
                "right": {
                    "rel_path": right.rel_path,
                    "capture_id": right.decl.capture_id,
                    "byte": bytes([value_right]).hex(),
                    "sha256": right.sha256,
                },
            }
    return None


def overlap_conflicts(fragments: list[LoadedFragment]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    usable = [item for item in fragments if item.raw is not None]
    for index, left in enumerate(usable):
        for right in usable[index + 1 :]:
            conflict = first_overlap_conflict(left, right)
            if conflict is not None:
                findings.append(conflict)
    return findings


def _compatible(chosen: list[LoadedFragment], fragment: LoadedFragment) -> bool:
    return all(first_overlap_conflict(item, fragment) is None for item in chosen)


def assemble_bytes(chosen: list[LoadedFragment], entity_size: int) -> bytes:
    buffer = bytearray(entity_size)
    filled = bytearray(entity_size)
    ordered = sorted(
        chosen,
        key=lambda item: (item.decl.byte_start, item.decl.byte_end_inclusive, item.rel_path),
    )
    for fragment in ordered:
        for offset, value in enumerate(fragment.raw or b""):
            index = fragment.decl.byte_start + offset
            if filled[index] and buffer[index] != value:
                raise ValueError(f"字节 {index} 在重叠区间内容冲突")
            buffer[index] = value
            filled[index] = 1
    if not all(filled):
        raise ValueError("片段未覆盖完整实体区间")
    return bytes(buffer)


class _BudgetExceeded(Exception):
    pass


def _combination(chosen: list[LoadedFragment], entity_size: int) -> Combination:
    data = assemble_bytes(chosen, entity_size)
    ordered = sorted(
        chosen, key=lambda item: (item.decl.byte_start, item.rel_path)
    )
    return Combination(
        fragments=tuple(ordered),
        coverage=tuple(
            (item.decl.byte_start, item.decl.byte_end_inclusive) for item in ordered
        ),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def explore_combinations(
    fragments: list[LoadedFragment], entity_size: int, budget: int
) -> tuple[list[Combination], int, bool]:
    """枚举覆盖全长的组合；超过预算时返回已找到组合并标记 exhausted。"""
    ordered = sorted(
        fragments,
        key=lambda item: (item.decl.byte_start, item.decl.byte_end_inclusive, item.rel_path),
    )
    results: list[Combination] = []
    seen: set[tuple[str, ...]] = set()
    found = 0
    steps = 0
    step_limit = max(4096, budget * 64)

    def walk(cursor: int, chosen: list[LoadedFragment], end: int) -> None:
        nonlocal found, steps
        if cursor >= entity_size:
            key = tuple(sorted(item.rel_path for item in chosen))
            if key in seen:
                return
            seen.add(key)
            found += 1
            if found > budget:
                raise _BudgetExceeded
            results.append(_combination(chosen, entity_size))
            return
        for fragment in ordered:
            start = fragment.decl.byte_start
            finish = fragment.decl.byte_end_inclusive
            if start > cursor or finish < cursor or finish < end:
                continue
            if not _compatible(chosen, fragment):
                continue
            steps += 1
            if steps > step_limit:
                raise _BudgetExceeded
            walk(finish + 1, [*chosen, fragment], max(end, finish))

    try:
        walk(0, [], -1)
    except _BudgetExceeded:
        results.sort(key=lambda item: (item.sha256, item.rel_paths))
        return results, found, True
    results.sort(key=lambda item: (item.sha256, item.rel_paths))
    return results, found, False


def group_result(
    capture_id: str,
    fragments: list[LoadedFragment],
    entity_size: int,
    budget: int,
) -> GroupResult:
    """校验单个捕获组内部的覆盖与一致性，并枚举完整组合。"""
    usable = [item for item in fragments if item.raw is not None and item.status == "ok"]
    excluded = [item for item in fragments if item not in usable]
    reasons = [
        f"{item.rel_path}: {item.status}: {'；'.join(item.reasons)}" for item in excluded
    ]
    validators = sorted({item.decl.validator for item in usable})
    if len(validators) > 1:
        reasons.append("同一捕获组内 validator 声明互相矛盾: " + ", ".join(validators))
        return GroupResult(
            capture_id, "validator_mismatch", reasons, fragments, [], [], 0, entity_size
        )
    overlaps = overlap_conflicts(usable)
    gaps = union_gaps(
        [(item.decl.byte_start, item.decl.byte_end_inclusive) for item in usable],
        entity_size,
    )
    if gaps:
        reasons.append(
            "存在未覆盖区间: "
            + ", ".join(f"{item['start']}..{item['end']}" for item in gaps)
        )
        return GroupResult(
            capture_id, "incomplete", reasons, fragments, [], overlaps, 0, entity_size
        )
    # 重叠不一致并不必然使整组失效：两个各自覆盖长全的候选片段可以互斥。
    # 真正的组合冲突由 `explore_combinations` 只在实际同选时排除。
    combinations, found, exhausted = explore_combinations(usable, entity_size, budget)
    if exhausted:
        reasons.append(f"候选组合超过预算 {budget}，不声称找到唯一完整组合")
        return GroupResult(
            capture_id,
            BUDGET_STATUS,
            reasons,
            fragments,
            combinations,
            overlaps,
            found,
            entity_size,
        )
    if not combinations:
        reasons.append("没有能覆盖全长且一致的完整组合")
        return GroupResult(
            capture_id,
            "conflict",
            reasons,
            fragments,
            [],
            overlaps,
            found,
            entity_size,
        )
    return GroupResult(
        capture_id,
        "complete",
        reasons,
        fragments,
        combinations,
        overlaps,
        found,
        entity_size,
    )
