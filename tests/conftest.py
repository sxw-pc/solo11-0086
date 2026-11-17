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


# ---------------------------------------------------------------------------
# 共享导出测试的合成输入与读取助手
# ---------------------------------------------------------------------------


def write_utf8_html(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '<!doctype html>\n<html><head><meta charset="utf-8"><title>t</title></head>'
        f"<body><p>{body}</p></body></html>",
        encoding="utf-8",
    )


def alice_root(tmp_path: Path) -> Path:
    """cases/alice.html 带 Alice-ID 正文与唯一 high 乱码；另两份干净响应。"""
    root = tmp_path / "responses"
    write_utf8_html(
        root / "cases" / "alice.html", "员工编号 Alice-ID 的页面出现典型乱码 æ˜¯ 需要复核"
    )
    write_utf8_html(root / "cases" / "bob.html", "完全正常的页面内容，没有乱码。")
    write_utf8_html(root / "cases" / "carol.html", "另一份完全正常的页面内容。")
    return root


def two_file_root(tmp_path: Path) -> Path:
    """一份可从公开编码特征识别为无乱码，另一份存在唯一 high 乱码。"""
    root = tmp_path / "responses"
    write_utf8_html(root / "one.html", "干净页面，编码声明与字节一致。")
    write_utf8_html(root / "two.html", "这一份含有典型乱码序列 æ˜¯ 需要复核。")
    return root


def normal_root(tmp_path: Path) -> Path:
    """每个敏感画像组样本量都 >=2 的正常批次。"""
    root = tmp_path / "responses"
    write_utf8_html(root / "clean_a.html", "完全正常的页面内容甲。")
    write_utf8_html(root / "clean_b.html", "完全正常的页面内容乙。")
    write_utf8_html(root / "q_a.html", "状态正常 ??? 结束甲")
    write_utf8_html(root / "q_b.html", "状态正常 ??? 结束乙")
    return root


def run_batch(make_config, root: Path):
    import json as _json

    from decodebench.pipeline import run

    config = make_config(scan_root=root)
    result = run(config, NOW)
    manifest = _json.loads(config.manifest_path.read_text(encoding="utf-8"))
    return config, result, manifest


def export_package(config, directory: Path, **kwargs):
    """调用 build_export 并读回四种格式的文本与 JSON 视图。"""
    import json as _json

    from decodebench.sharing import build_export

    kwargs.setdefault("contract", "share_review")
    kwargs.setdefault("now", NOW)
    kwargs["output_dir"] = str(directory)
    result = build_export(config, **kwargs)
    package = Path(result["package_dir"])
    stem = "share" if kwargs["contract"] == "share_review" else "forensic"
    texts = {
        name: (package / f"{stem}{suffix}").read_text(encoding="utf-8")
        for name, suffix in (
            ("json", ".json"), ("md", ".md"), ("html", ".html"),
            ("schema", "_schema.json"),
        )
    }
    return result, _json.loads(texts["json"]), texts
