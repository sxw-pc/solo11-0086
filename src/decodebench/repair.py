"""可逆乱码修复候选：严格路径验证、人工批准与独立修复副本。

本模块只提供“可解释、可逆、须人工批准”的离线修复流程：

1. 候选必须通过一条声明清楚的严格路径——
   原片段按错误字符集重新编码（strict）→ 按目标字符集解码（strict），
   并且逆向还原（候选文本按目标字符集编码 → 按错误字符集解码）
   逐字符等于原片段，才允许进入候选清单；典型字串命中本身不构成修复依据。
2. 程序无法仅凭字符区分真实字面量与误码形成的同形片段，因此每一处都按
   字节/字符偏移分别列出；未经人工批准一律保留原文。
3. 含 U+FFFD、不可逆字符或相互重叠的候选只能标记为 blocked，不能发布。
4. 批准文件绑定源 SHA-256、当前裁决编码、精确片段位置、候选路径与目标片段
   摘要；摘要变化或位置漂移一律拒绝。
5. 批准执行只写独立修复副本，源文件与原转码产物及其摘要保持不变；
   重复执行同一批准幂等。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detectors import canonical_encoding
from .util import atomic_write_bytes, json_text

REPLACEMENT_CHAR = "�"
REPAIR_SCHEMA_VERSION = "1.0"

# 典型 mojibake 序列：仅作为候选枚举入口，命中本身不证明修复正确。
TYPICAL_MOJIBAKE: tuple[str, ...] = (
    "Ã©",
    "Ã¨",
    "Ã¤",
    "Ã¶",
    "Ã¼",
    "ÃŸ",
    "Â©",
    "Â®",
    "â€™",
    "â€œ",
    "â€\x9d",
    "â€“",
    "â€”",
    "ï»¿",
    "æ˜¯",
    "ä¸€",
    "çš„",
    "è¿™",
    "ã€‚",
)

# 单个非 ASCII 连续段参与子窗口枚举的最大字符数，防止长文本下组合爆炸。
MAX_RUN_LENGTH = 64

# 声明清楚的修复路径集合：目标字符集（原始真实编码）→ 误判字符集。
# 含义：原本以 target 编码的字节，被按 wrong 字符集误读成文本并以 UTF-8 保存。
REPAIR_ROUTES: tuple[tuple[str, str], ...] = (
    ("utf-8", "windows-1252"),
    ("utf-8", "latin-1"),
    ("utf-8", "gb18030"),
    ("utf-8", "big5"),
)


class RepairError(ValueError):
    """修复候选生成或批准执行无法继续。"""


@dataclass(frozen=True)
class RepairRoute:
    target_encoding: str
    wrong_encoding: str

    @property
    def route_id(self) -> str:
        return f"{self.target_encoding}<-{self.wrong_encoding}"

    def to_dict(self) -> dict[str, str]:
        return {
            "route_id": self.route_id,
            "target_encoding": self.target_encoding,
            "wrong_encoding": self.wrong_encoding,
            "description": (
                f"原片段按 {self.wrong_encoding} 严格重新编码，"
                f"再按 {self.target_encoding} 严格解码"
            ),
        }


@dataclass
class RepairCandidate:
    candidate_id: str
    rel_path: str
    source_sha256: str
    encoding: str
    start_char: int
    end_char: int
    start_byte: int
    end_byte: int
    line: int
    column: int
    fragment: str
    fragment_sha256: str
    repaired: str
    repaired_sha256: str
    route: RepairRoute
    reversible: bool
    status: str
    blocked_reasons: list[str] = field(default_factory=list)
    overlap_with: list[str] = field(default_factory=list)
    route_ids: list[str] = field(default_factory=list)
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "rel_path": self.rel_path,
            "source_sha256": self.source_sha256,
            "encoding": self.encoding,
            "position": {
                "start_char": self.start_char,
                "end_char": self.end_char,
                "start_byte": self.start_byte,
                "end_byte": self.end_byte,
                "line": self.line,
                "column": self.column,
                "position_basis": "transcoded_utf8_characters",
            },
            "fragment": self.fragment,
            "fragment_sha256": self.fragment_sha256,
            "repaired": self.repaired,
            "repaired_sha256": self.repaired_sha256,
            "route": self.route.to_dict(),
            "alternative_routes": list(self.route_ids),
            "reversible": self.reversible,
            "status": self.status,
            "blocked_reasons": list(self.blocked_reasons),
            "overlap_with": list(self.overlap_with),
            "snippet": self.snippet,
        }


@dataclass
class IneligibleSpan:
    rel_path: str
    start_char: int
    end_char: int
    start_byte: int
    end_byte: int
    line: int
    column: int
    fragment: str
    reason: str
    route_id: str | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "position": {
                "start_char": self.start_char,
                "end_char": self.end_char,
                "start_byte": self.start_byte,
                "end_byte": self.end_byte,
                "line": self.line,
                "column": self.column,
                "position_basis": "transcoded_utf8_characters",
            },
            "fragment": self.fragment,
            "reason": self.reason,
            "route_id": self.route_id,
            "detail": self.detail,
        }


@dataclass
class FileRepairFindings:
    rel_path: str
    source_sha256: str
    encoding: str
    transcode_output_rel_path: str | None
    transcode_output_sha256: str | None
    candidates: list[RepairCandidate] = field(default_factory=list)
    ineligible: list[IneligibleSpan] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "source_sha256": self.source_sha256,
            "encoding": self.encoding,
            "transcode_output_rel_path": self.transcode_output_rel_path,
            "transcode_output_sha256": self.transcode_output_sha256,
            "candidate_count": len(self.candidates),
            "blocked_count": sum(1 for item in self.candidates if item.status == "blocked"),
            "ineligible_count": len(self.ineligible),
            "candidates": [item.to_dict() for item in self.candidates],
            "ineligible_spans": [item.to_dict() for item in self.ineligible],
        }


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def candidate_identity(
    source_sha256: str,
    encoding: str,
    start_char: int,
    end_char: int,
    route_id: str,
    repaired_sha256: str,
) -> str:
    """候选身份完全绑定源摘要、裁决编码、精确位置、路径与目标片段摘要。"""
    material = "|".join(
        (
            source_sha256,
            canonical_encoding(encoding),
            str(start_char),
            str(end_char),
            route_id,
            repaired_sha256,
        )
    )
    return "rc_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _line_column(text: str, offset: int) -> tuple[int, int]:
    before = text[:offset]
    line = before.count("\n") + 1
    column = offset - before.rfind("\n")
    return line, column


def _snippet(text: str, start: int, end: int, radius: int = 30) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    value = text[left:right].replace("\r", "\\r").replace("\n", "\\n")
    return value[:120]


def _utf8_byte_offsets(text: str, start_char: int, end_char: int) -> tuple[int, int]:
    start_byte = len(text[:start_char].encode("utf-8"))
    end_byte = len(text[:end_char].encode("utf-8"))
    return start_byte, end_byte


def _strict_roundtrip(fragment: str, route: RepairRoute) -> tuple[bool, str | None, str | None]:
    """验证严格修复路径及其逐字符可逆性。

    返回 (是否可逆, 修复文本, 失败原因)。任一步使用 errors='strict'，
    出现 U+FFFD、不可编码字符或解码失败均判失败。
    """
    wrong = canonical_encoding(route.wrong_encoding)
    target = canonical_encoding(route.target_encoding)
    if REPLACEMENT_CHAR in fragment:
        return False, None, "片段包含 U+FFFD 替换字符，原始字节已丢失，不可逆"
    try:
        raw = fragment.encode(wrong, errors="strict")
    except (UnicodeError, LookupError) as exc:
        return False, None, f"按 {wrong} 重新编码失败: {type(exc).__name__}: {exc}"
    try:
        repaired = raw.decode(target, errors="strict")
    except (UnicodeError, LookupError) as exc:
        return False, None, f"按 {target} 解码失败: {type(exc).__name__}: {exc}"
    if REPLACEMENT_CHAR in repaired:
        return False, None, "解码结果出现 U+FFFD，路径不可逆"
    if repaired == fragment:
        return False, None, "路径输出与原片段逐字符相同，不构成修复"
    try:
        restored = repaired.encode(target, errors="strict").decode(
            wrong, errors="strict"
        )
    except (UnicodeError, LookupError) as exc:
        return False, None, f"逆向还原失败: {type(exc).__name__}: {exc}"
    if restored != fragment:
        return False, None, "逆向还原与原片段不一致，路径不具备逐字符可逆性"
    return True, repaired, None


def _non_ascii_runs(text: str) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    start: int | None = None
    for index, char in enumerate(text):
        if ord(char) >= 0x80:
            if start is None:
                start = index
        elif start is not None:
            runs.append((start, index))
            start = None
    if start is not None:
        runs.append((start, len(text)))
    return runs


def _repair_windows(text: str, run_start: int, run_end: int) -> list[tuple[int, int]]:
    """枚举一个非 ASCII 连续段内的修复候选窗口。

    真实字面量与误码片段可能相邻并形成同一个连续段，因此不能只尝试整段。
    枚举入口是段内出现的典型 mojibake 序列：命中只用于缩小窗口范围，
    不证明修复正确，每个窗口仍须通过严格路径与逐字符逆向校验。
    窗口集合为：整段、以及每个典型序列自身与其向段边界扩展出的全部
    连续子窗口。超过安全上限的长段只按整段评估，避免组合爆炸。
    """
    length = run_end - run_start
    if length > MAX_RUN_LENGTH:
        return [(run_start, run_end)]
    windows: set[tuple[int, int]] = {(run_start, run_end)}
    segment = text[run_start:run_end]
    for sequence in TYPICAL_MOJIBAKE:
        cursor = 0
        while True:
            found = segment.find(sequence, cursor)
            if found < 0:
                break
            anchor_start = run_start + found
            anchor_end = anchor_start + len(sequence)
            for start in range(run_start, anchor_start + 1):
                for end in range(anchor_end, run_end + 1):
                    windows.add((start, end))
            cursor = found + len(sequence)
    return sorted(windows, key=lambda item: (item[0], item[1]))


def build_repair_findings(
    rel_path: str,
    source_sha256: str,
    encoding: str,
    text: str,
    transcode_output_rel_path: str | None,
    transcode_output_sha256: str | None,
) -> FileRepairFindings:
    """对转码后的 UTF-8 文本枚举所有严格可逆的修复候选与不可行片段。

    典型字串命中只是枚举入口；每个窗口仍须通过严格路径与逐字符逆向校验。
    同一窗口经多条路径得到同一目标文本时合并为一个候选并保留全部路径证据；
    位置相互重叠的候选一律标记 blocked，不自动发布。
    """
    findings = FileRepairFindings(
        rel_path=rel_path,
        source_sha256=source_sha256,
        encoding=canonical_encoding(encoding),
        transcode_output_rel_path=transcode_output_rel_path,
        transcode_output_sha256=transcode_output_sha256,
    )
    routes = [
        RepairRoute(target, wrong)
        for target, wrong in REPAIR_ROUTES
    ]
    runs = _non_ascii_runs(text)
    # key: (start, end, repaired_sha256) -> 合并后的候选
    merged: dict[tuple[int, int, str], RepairCandidate] = {}
    seen_ineligible: set[tuple[int, int, str, str]] = set()

    for run_start, run_end in runs:
        for start, end in _repair_windows(text, run_start, run_end):
            fragment = text[start:end]
            line, column = _line_column(text, start)
            start_byte, end_byte = _utf8_byte_offsets(text, start, end)
            for route in routes:
                ok, repaired, detail = _strict_roundtrip(fragment, route)
                if not ok:
                    assert detail is not None
                    reason = (
                        "irreversible_replacement"
                        if "U+FFFD" in detail
                        else "irreversible_encoding"
                    )
                    key = (start, end, route.route_id, reason)
                    if key not in seen_ineligible:
                        seen_ineligible.add(key)
                        findings.ineligible.append(
                            IneligibleSpan(
                                rel_path=rel_path,
                                start_char=start,
                                end_char=end,
                                start_byte=start_byte,
                                end_byte=end_byte,
                                line=line,
                                column=column,
                                fragment=fragment,
                                reason=reason,
                                route_id=route.route_id,
                                detail=detail,
                            )
                        )
                    continue
                assert repaired is not None
                repaired_digest = sha256_text(repaired)
                merge_key = (start, end, repaired_digest)
                if merge_key in merged:
                    existing = merged[merge_key]
                    if route.route_id not in existing.route_ids:
                        existing.route_ids.append(route.route_id)
                    continue
                candidate = RepairCandidate(
                    candidate_id=candidate_identity(
                        source_sha256,
                        findings.encoding,
                        start,
                        end,
                        route.route_id,
                        repaired_digest,
                    ),
                    rel_path=rel_path,
                    source_sha256=source_sha256,
                    encoding=findings.encoding,
                    start_char=start,
                    end_char=end,
                    start_byte=start_byte,
                    end_byte=end_byte,
                    line=line,
                    column=column,
                    fragment=fragment,
                    fragment_sha256=sha256_text(fragment),
                    repaired=repaired,
                    repaired_sha256=repaired_digest,
                    route=route,
                    reversible=True,
                    status="candidate",
                    route_ids=[route.route_id],
                    snippet=_snippet(text, start, end),
                )
                merged[merge_key] = candidate

    candidates = sorted(merged.values(), key=lambda item: (item.start_char, item.end_char))
    _mark_overlaps(candidates)
    findings.candidates = candidates
    return findings


def _mark_overlaps(candidates: list[RepairCandidate]) -> None:
    for index, candidate in enumerate(candidates):
        for other in candidates[index + 1 :]:
            if other.start_char >= candidate.end_char:
                break
            candidate.status = "blocked"
            other.status = "blocked"
            reason = "overlapping_candidates"
            if reason not in candidate.blocked_reasons:
                candidate.blocked_reasons.append(reason)
            if reason not in other.blocked_reasons:
                other.blocked_reasons.append(reason)
            if other.candidate_id not in candidate.overlap_with:
                candidate.overlap_with.append(other.candidate_id)
            if candidate.candidate_id not in other.overlap_with:
                other.overlap_with.append(candidate.candidate_id)


def build_candidates_document(
    findings_per_file: list[FileRepairFindings],
    config_fingerprint: str,
    rule_version: str,
) -> dict[str, Any]:
    ordered = sorted(findings_per_file, key=lambda item: item.rel_path)
    total_candidates = sum(len(item.candidates) for item in ordered)
    total_blocked = sum(
        1 for item in ordered for row in item.candidates if row.status == "blocked"
    )
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "project": "decodebench",
        "rule_version": rule_version,
        "config_fingerprint": config_fingerprint,
        "notice": (
            "候选仅为证据，不构成自动修复。含 U+FFFD、不可逆字符或相互重叠的"
            "候选已标记 blocked；批准前须结合上下文人工区分真实字面量与误码。"
        ),
        "routes": [RepairRoute(target, wrong).to_dict() for target, wrong in REPAIR_ROUTES],
        "summary": {
            "files": len(ordered),
            "candidates_total": total_candidates,
            "candidates_blocked": total_blocked,
            "candidates_pending": total_candidates - total_blocked,
        },
        "files": [item.to_dict() for item in ordered],
    }


# ---------------------------------------------------------------------------
# 批准文件
# ---------------------------------------------------------------------------


def make_approval_template(document: dict[str, Any]) -> dict[str, Any]:
    """生成供复核者填写的批准模板：默认全部 keep_original。"""
    entries: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    for row in document["files"]:
        if not row["candidates"]:
            continue
        bindings.append(
            {
                "rel_path": row["rel_path"],
                "source_sha256": row["source_sha256"],
                "encoding": row["encoding"],
                "transcode_output_sha256": row["transcode_output_sha256"],
            }
        )
        for candidate in row["candidates"]:
            entries.append(
                {
                    "rel_path": row["rel_path"],
                    "candidate_id": candidate["candidate_id"],
                    "decision": "keep_original",
                    "target_fragment_sha256": candidate["repaired_sha256"],
                    "note": "",
                }
            )
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "approval_kind": "mojibake_repair",
        "approver": "",
        "approved_at": "",
        "note": "",
        "bindings": bindings,
        "entries": entries,
    }


def _require(mapping: dict[str, Any], key: str, kind: type, label: str) -> Any:
    value = mapping.get(key)
    if not isinstance(value, kind) or (kind is str and not value.strip()):
        raise RepairError(f"{label} 缺少或类型错误: {key}")
    return value


def load_approval(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RepairError(f"批准文件无法读取: {exc}") from exc
    if not isinstance(data, dict):
        raise RepairError("批准文件根节点必须是 JSON 对象")
    if data.get("schema_version") != REPAIR_SCHEMA_VERSION:
        raise RepairError(f"批准文件 schema_version 必须为 {REPAIR_SCHEMA_VERSION}")
    if data.get("approval_kind") != "mojibake_repair":
        raise RepairError("批准文件 approval_kind 必须为 mojibake_repair")
    _require(data, "approver", str, "批准文件")
    _require(data, "approved_at", str, "批准文件")
    bindings = data.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        raise RepairError("批准文件 bindings 必须是非空列表")
    binding_index: dict[str, dict[str, Any]] = {}
    for index, binding in enumerate(bindings):
        label = f"bindings[{index}]"
        if not isinstance(binding, dict):
            raise RepairError(f"{label} 必须是对象")
        rel_path = _require(binding, "rel_path", str, label)
        _require(binding, "source_sha256", str, label)
        _require(binding, "encoding", str, label)
        if rel_path in binding_index:
            raise RepairError(f"{label} 路径重复: {rel_path}")
        binding_index[rel_path] = binding
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RepairError("批准文件 entries 必须是非空列表")
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        label = f"entries[{index}]"
        if not isinstance(entry, dict):
            raise RepairError(f"{label} 必须是对象")
        rel_path = _require(entry, "rel_path", str, label)
        candidate_id = _require(entry, "candidate_id", str, label)
        decision = _require(entry, "decision", str, label)
        if decision not in {"approve_candidate", "keep_original"}:
            raise RepairError(f"{label}.decision 取值非法: {decision}")
        _require(entry, "target_fragment_sha256", str, label)
        if rel_path not in binding_index:
            raise RepairError(f"{label} 的 rel_path 缺少对应 bindings 绑定")
        key = (rel_path, candidate_id)
        if key in seen:
            raise RepairError(f"{label} 与其他条目重复: {key}")
        seen.add(key)
    return data


# ---------------------------------------------------------------------------
# 批准执行
# ---------------------------------------------------------------------------


@dataclass
class AppliedRepair:
    rel_path: str
    disposition: str
    repair_rel_path: str
    source_sha256: str
    transcode_output_sha256: str
    repair_sha256: str
    approved_candidate_ids: list[str]
    kept_candidate_ids: list[str]
    approver: str
    approval_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "disposition": self.disposition,
            "repair_rel_path": self.repair_rel_path,
            "source_sha256": self.source_sha256,
            "transcode_output_sha256": self.transcode_output_sha256,
            "repair_sha256": self.repair_sha256,
            "approved_candidate_ids": list(self.approved_candidate_ids),
            "kept_candidate_ids": list(self.kept_candidate_ids),
            "approver": self.approver,
            "approval_sha256": self.approval_sha256,
        }


def _index_candidates(
    findings_per_file: list[FileRepairFindings],
) -> dict[tuple[str, str], RepairCandidate]:
    index: dict[tuple[str, str], RepairCandidate] = {}
    for findings in findings_per_file:
        for candidate in findings.candidates:
            index[(findings.rel_path, candidate.candidate_id)] = candidate
    return index


def validate_approval(
    approval: dict[str, Any],
    findings_per_file: list[FileRepairFindings],
) -> dict[str, list[dict[str, Any]]]:
    """全部条目先校验，任何一条不合法都整体拒绝、不产生任何写入。"""
    by_file: dict[str, list[dict[str, Any]]] = {}
    index = _index_candidates(findings_per_file)
    findings_index = {item.rel_path: item for item in findings_per_file}
    bindings = {
        str(row["rel_path"]): row for row in approval.get("bindings", []) if isinstance(row, dict)
    }
    for entry in approval["entries"]:
        key = (entry["rel_path"], entry["candidate_id"])
        binding = bindings.get(entry["rel_path"])
        if binding is None:
            raise RepairError(f"批准条目缺少源绑定: {entry['rel_path']}")
        findings = findings_index.get(entry["rel_path"])
        if findings is None or binding["source_sha256"] != findings.source_sha256:
            raise RepairError(
                f"源 SHA-256 已变化，旧批准对 {entry['rel_path']} 失效，拒绝执行"
            )
        if canonical_encoding(str(binding["encoding"])) != (
            findings.encoding if findings is not None else binding["encoding"]
        ):
            raise RepairError(
                f"裁决编码已变化，旧批准对 {entry['rel_path']} 失效，拒绝执行"
            )
        candidate = index.get(key)
        if candidate is None:
            raise RepairError(
                f"批准条目在当前候选集中不存在（位置可能已漂移）: {key}"
            )
        if candidate.status == "blocked":
            raise RepairError(
                f"候选 {candidate.candidate_id} 处于 blocked 状态"
                f"（{'; '.join(candidate.blocked_reasons)}），不能批准"
            )
        if entry["target_fragment_sha256"] != candidate.repaired_sha256:
            raise RepairError(
                f"候选 {candidate.candidate_id} 的目标片段摘要不匹配："
                "目标片段已变化，拒绝执行"
            )
        by_file.setdefault(entry["rel_path"], []).append(entry)
    return by_file


def apply_approval(
    approval_path: Path,
    findings_per_file: list[FileRepairFindings],
    transcode_dir: Path,
    repair_dir: Path,
    *,
    now: str,
) -> list[AppliedRepair]:
    """按批准文件在独立修复副本中替换获批片段；重复执行幂等。

    源目录与 transcode_dir 全程只读；所有输出只落在 repair_dir 内。
    """
    approval = load_approval(approval_path)
    approval_bytes = approval_path.read_bytes()
    approval_sha = hashlib.sha256(approval_bytes).hexdigest()
    entries_by_file = validate_approval(approval, findings_per_file)
    findings_index = {item.rel_path: item for item in findings_per_file}
    applied: list[AppliedRepair] = []

    for rel_path in sorted(entries_by_file):
        findings = findings_index[rel_path]
        source_path = transcode_dir / rel_path
        try:
            source_path.resolve().relative_to(transcode_dir.resolve())
        except (OSError, ValueError) as exc:
            raise RepairError(f"转码产物路径越界: {rel_path}") from exc
        if not source_path.is_file():
            raise RepairError(f"转码产物不存在，无法生成修复副本: {rel_path}")
        payload = source_path.read_bytes()
        if findings.transcode_output_sha256 is not None and hashlib.sha256(
            payload
        ).hexdigest() != findings.transcode_output_sha256:
            raise RepairError(
                f"转码产物摘要与清单不一致，原转码产物可能已被改动: {rel_path}"
            )
        text = payload.decode("utf-8", errors="strict")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != (
            findings.transcode_output_sha256
            or hashlib.sha256(payload).hexdigest()
        ):
            raise RepairError(
                f"转码文本重建校验失败，片段位置可能已漂移: {rel_path}"
            )

        approved: list[RepairCandidate] = []
        kept: list[RepairCandidate] = []
        for entry in entries_by_file[rel_path]:
            candidate = next(
                item
                for item in findings.candidates
                if item.candidate_id == entry["candidate_id"]
            )
            if text[candidate.start_char : candidate.end_char] != candidate.fragment:
                raise RepairError(
                    f"片段位置漂移，{rel_path}@{candidate.start_char}:"
                    f"{candidate.end_char} 与候选原文不一致，拒绝执行"
                )
            if entry["decision"] == "approve_candidate":
                approved.append(candidate)
            else:
                kept.append(candidate)

        repaired_text = text
        for candidate in sorted(approved, key=lambda item: item.start_char, reverse=True):
            repaired_text = (
                repaired_text[: candidate.start_char]
                + candidate.repaired
                + repaired_text[candidate.end_char :]
            )
        repaired_payload = repaired_text.encode("utf-8")
        repair_path = repair_dir / rel_path
        try:
            repair_path.resolve().relative_to(repair_dir.resolve())
        except (OSError, ValueError) as exc:
            raise RepairError(f"修复副本路径越界: {rel_path}") from exc
        atomic_write_bytes(repair_path, repaired_payload)

        disposition = "approved_repair" if approved else "kept_original"
        applied.append(
            AppliedRepair(
                rel_path=rel_path,
                disposition=disposition,
                repair_rel_path=rel_path,
                source_sha256=findings.source_sha256,
                transcode_output_sha256=findings.transcode_output_sha256
                or hashlib.sha256(payload).hexdigest(),
                repair_sha256=hashlib.sha256(repaired_payload).hexdigest(),
                approved_candidate_ids=[item.candidate_id for item in approved],
                kept_candidate_ids=[item.candidate_id for item in kept],
                approver=str(approval["approver"]),
                approval_sha256=approval_sha,
            )
        )

    manifest_path = repair_dir / "applied_repairs.json"
    document = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "generated_at": now,
        "approval_file": approval_path.name,
        "approval_sha256": approval_sha,
        "approver": approval["approver"],
        "approved_at": approval["approved_at"],
        "repairs": [item.to_dict() for item in applied],
    }
    atomic_write_bytes(manifest_path, json_text(document).encode("utf-8"))
    return applied
