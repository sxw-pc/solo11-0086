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
    content_encoding: dict[str, Any] | None = None,
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
            "partial_dir": "partial",
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
        "content_encoding": {
            "enabled": True,
            "failure_route": "strict",
            "max_members": 64,
            "entity_max_bytes": 8388608,
            "inflate_max_bytes": 33554432,
            "max_expansion_ratio": 200.0,
            **(content_encoding or {}),
        },
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
