"""贯穿扫描、诊断、转码与存档的数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _ratio(value: float) -> float:
    return round(float(value), 6)


@dataclass(frozen=True)
class SourceFile:
    rel_path: str
    path: Path
    size: int
    sha256: str
    mtime: str
    sidecar_path: Path | None = None
    sidecar_rel: str | None = None
    sidecar: dict[str, Any] = field(default_factory=dict)
    sidecar_error: str | None = None


@dataclass
class Evidence:
    source: str
    declared: str | None
    offset: int | None = None
    line: int | None = None
    matches_decision: bool | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "declared": self.declared,
            "offset": self.offset,
            "line": self.line,
            "matches_decision": self.matches_decision,
            "note": self.note,
        }


@dataclass
class DecodedSample:
    encoding: str
    success: bool
    text: str
    error: str | None
    decoded_chars: int
    replacement_count: int
    control_ratio: float
    printable_ratio: float
    cjk_ratio: float
    latin_ratio: float
    unassigned_ratio: float
    private_ratio: float
    ascii_ratio: float
    high_byte_ratio: float


@dataclass
class CandidateResult:
    encoding: str
    success: bool
    score: float
    decoded_chars: int
    replacement_count: int
    control_ratio: float
    printable_ratio: float
    cjk_ratio: float
    latin_ratio: float
    unassigned_ratio: float
    private_ratio: float
    ascii_ratio: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "encoding": self.encoding,
            "success": self.success,
            "score": _ratio(self.score),
            "decoded_chars": self.decoded_chars,
            "replacement_count": self.replacement_count,
            "control_ratio": _ratio(self.control_ratio),
            "printable_ratio": _ratio(self.printable_ratio),
            "cjk_ratio": _ratio(self.cjk_ratio),
            "latin_ratio": _ratio(self.latin_ratio),
            "unassigned_ratio": _ratio(self.unassigned_ratio),
            "private_ratio": _ratio(self.private_ratio),
            "ascii_ratio": _ratio(self.ascii_ratio),
            "error": self.error,
        }


@dataclass
class Decision:
    encoding: str
    confidence: float
    method: str
    reason: str
    error_codes: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "encoding": self.encoding,
            "confidence": _ratio(self.confidence),
            "method": self.method,
            "reason": self.reason,
            "error_codes": list(self.error_codes),
            "conflicts": list(self.conflicts),
        }


@dataclass
class WarningItem:
    code: str
    severity: str
    message: str
    line: int | None = None
    offset: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "offset": self.offset,
            "snippet": self.snippet,
        }


@dataclass
class MojibakeReport:
    level: str
    findings: list[dict[str, Any]]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "findings": self.findings,
            "recommendation": self.recommendation,
        }


@dataclass
class TranscodeResult:
    success: bool
    encoding: str
    errors: str
    output_rel_path: str | None
    source_sha256: str | None
    output_sha256: str | None
    bytes_written: int
    decoded_chars: int
    replacement_count: int
    replacement_used: bool
    bom_removed: bool
    rewrites: list[dict[str, Any]]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "encoding": self.encoding,
            "errors": self.errors,
            "output_rel_path": self.output_rel_path,
            "source_sha256": self.source_sha256,
            "output_sha256": self.output_sha256,
            "bytes_written": self.bytes_written,
            "decoded_chars": self.decoded_chars,
            "replacement_count": self.replacement_count,
            "replacement_used": self.replacement_used,
            "bom_removed": self.bom_removed,
            "rewrites": self.rewrites,
            "error": self.error,
        }
