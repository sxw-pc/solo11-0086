"""共享测试夹具：临时配置、只读 fixture 与固定时钟。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from decodebench.config import Config, load_config  # noqa: E402
from decodebench.pipeline import run  # noqa: E402

NOW = "2024-01-01T00:00:00Z"
RESPONSES = ROOT / "fixtures" / "responses"
SIDECARS = ROOT / "fixtures" / "sidecars"


def build_config(
    tmp_path: Path,
    scan_root: Path | None = None,
    sidecar_root: Path | None = None,
    out_dir: Path | None = None,
    *,
    fallback: str = "utf-8",
    candidates: list[str] | None = None,
    transcode_errors: str = "strict",
    rewrite: bool = True,
    host: str = "127.0.0.1",
    port: int = 5017,
) -> Config:
    config_dir = tmp_path / "configs"
    config_dir.mkdir(parents=True, exist_ok=True)
    source = (scan_root or RESPONSES).resolve()
    sidecars = sidecar_root
    if sidecars is None and source == RESPONSES.resolve():
        sidecars = SIDECARS
    data: dict[str, Any] = {
        "scan": {
            "root": str(source),
            "extensions": [".html", ".htm", ".xml", ".txt", ".css"],
            "sidecar_suffix": ".headers.json",
            "sidecar_root": str(sidecars.resolve()) if sidecars else None,
        },
        "output": {
            "dir": str((out_dir or (tmp_path / "out")).resolve()),
            "manifest": "manifest.json",
            "reports_dir": "reports",
            "transcode_dir": "transcoded",
            "database": "decodebench.sqlite3",
        },
        "detection": {
            "fallback_encoding": fallback,
            "candidate_encodings": candidates
            or [
                "utf-8",
                "gb18030",
                "big5",
                "utf-16-le",
                "utf-16-be",
                "windows-1252",
                "latin-1",
            ],
            "trusted_http_headers": True,
            "minimum_confidence": 0.55,
        },
        "transcode": {"rewrite_declarations": rewrite, "errors": transcode_errors},
        "mojibake": {"question_run_threshold": 3, "control_ratio_threshold": 0.01},
        "web": {"host": host, "port": port},
    }
    path = config_dir / "demo.yml"
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return load_config(path)


@pytest.fixture
def make_config(tmp_path):
    return lambda **kwargs: build_config(tmp_path, **kwargs)


@pytest.fixture
def run_demo(make_config):
    def execute(now: str = NOW):
        config = make_config()
        result = run(config, now)
        return config, result

    return execute


def fixture_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(list(RESPONSES.iterdir()) + list(SIDECARS.iterdir())):
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def load_json_manifest(config: Config) -> dict[str, Any]:
    import json

    return json.loads(config.manifest_path.read_text(encoding="utf-8"))


@pytest.fixture
def now() -> str:
    return NOW


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def fixture_hashes_map():
    return fixture_hashes


@pytest.fixture
def manifest_reader():
    return load_json_manifest


# --- 事后审计测试共用构造器 -------------------------------------------------


def audit_content(rel: str, size: int) -> bytes:
    head = rel.encode("utf-8")
    return (head * (size // len(head) + 1))[:size]


def audit_manifest(specs: list[dict[str, Any]]) -> dict[str, Any]:
    """用最小交付清单构造抽样框输入；源/输出 SHA 与输出字节均可复现。"""
    files = []
    for spec in specs:
        rel = str(spec["rel"])
        ok = bool(spec.get("ok", True))
        out_bytes = int(spec.get("out", 0))
        payload = audit_content(rel, out_bytes)
        files.append(
            {
                "rel_path": rel,
                "source_size": int(spec.get("src", out_bytes)),
                "source_sha256": "src-" + rel,
                "source_mtime": NOW,
                "sidecar": {"path": None, "present": False, "error": None},
                "bom": None,
                "evidence": [],
                "statistical_candidates": [],
                "decision": {
                    "encoding": "utf-8",
                    "confidence": 1.0,
                    "method": "fallback",
                    "reason": "test",
                    "error_codes": [],
                    "conflicts": [],
                },
                "transcode": {
                    "success": ok,
                    "encoding": "utf-8",
                    "errors": "strict",
                    "output_rel_path": rel if ok else None,
                    "source_sha256": "src-" + rel,
                    "output_sha256": hashlib.sha256(payload).hexdigest() if ok else None,
                    "bytes_written": out_bytes if ok else 0,
                    "decoded_chars": out_bytes,
                    "replacement_count": 0,
                    "replacement_used": False,
                    "bom_removed": False,
                    "rewrites": [],
                    "error": None if ok else "decode failed",
                },
                "mojibake": {
                    "level": str(spec.get("risk", "none")),
                    "findings": [],
                    "recommendation": "",
                },
                "warnings": [],
                "warning_count": int(spec.get("warnings", 0)),
            }
        )
    return {
        "schema_version": "1.0",
        "project": "decodebench",
        "rule_version": "test-rule",
        "generated_at": NOW,
        "config_fingerprint": "test-fingerprint",
        "scan_root": "/scan",
        "config_snapshot": {},
        "summary": {"files_total": len(files)},
        "files": files,
    }


def audit_write_outputs(root: Path, manifest: dict[str, Any]) -> None:
    for item in manifest["files"]:
        transcode = item["transcode"]
        if transcode["success"]:
            path = root / str(transcode["output_rel_path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(audit_content(item["rel_path"], transcode["bytes_written"]))


@pytest.fixture
def audit_inputs():
    from decodebench.manifest import build_audit_frame

    def build(specs: list[dict[str, Any]]):
        return build_audit_frame(audit_manifest(specs))

    return build


@pytest.fixture
def audit_frame_from_manifest():
    return audit_manifest


@pytest.fixture
def audit_writer():
    return audit_write_outputs
