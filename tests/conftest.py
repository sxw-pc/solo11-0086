"""共享测试夹具：临时配置、只读 fixture 与固定时钟。"""

from __future__ import annotations

import hashlib
import json
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
    extensions: list[str] | None = None,
    assembly: dict[str, Any] | None = None,
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
            "extensions": extensions
            or [".html", ".htm", ".xml", ".txt", ".css"],
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
    if assembly is not None:
        data["assembly"] = assembly
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
def fragment_dir(tmp_path):
    """返回按名字写入响应与 sidecar 的工厂；sidecar 位于独立目录。"""
    responses = tmp_path / "responses"
    sidecars = tmp_path / "sidecars"
    responses.mkdir()
    sidecars.mkdir()

    def write(
        name: str,
        data: bytes,
        fragment: dict[str, Any] | None = None,
        *,
        headers: dict[str, Any] | None = None,
        sidecar_extra: dict[str, Any] | None = None,
    ) -> Path:
        payload = data
        (responses / name).write_bytes(payload)
        sidecar: dict[str, Any] = {"headers": headers or {}}
        if fragment is not None:
            sidecar.update(fragment)
        if sidecar_extra is not None:
            sidecar.update(sidecar_extra)
        (sidecars / (name + ".headers.json")).write_text(
            json.dumps(sidecar, ensure_ascii=False), encoding="utf-8"
        )
        return responses / name

    write.responses = responses  # type: ignore[attr-defined]
    write.sidecars = sidecars  # type: ignore[attr-defined]
    return write


@pytest.fixture
def assemble_config(tmp_path, make_config):
    def build(
        responses: Path,
        sidecars: Path,
        *,
        contract: str = "consensus",
        priority: list[str] | None = None,
        extensions: list[str] | None = None,
        max_combinations: int = 256,
    ) -> Config:
        return make_config(
            scan_root=responses,
            sidecar_root=sidecars,
            extensions=extensions or [".bin", ".txt", ".html", ".part"],
            assembly={
                "contract": contract,
                "priority_capture_ids": priority or [],
                "max_combinations_per_entity": max_combinations,
            },
        )

    return build


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
