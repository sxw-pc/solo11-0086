from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from decodebench.cli import parse_now
from decodebench.config import ConfigError


def test_cli_pipeline_end_to_end(tmp_path, make_config, now, fixture_hashes_map):
    before = fixture_hashes_map()
    config = make_config()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "decodebench",
            "pipeline",
            "--config",
            str(config.config_path),
            "--now",
            now,
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["summary"]["files_total"] == 10
    assert result["summary"]["conflict_files"] == 1
    assert result["summary"]["transcode_success"] == 10
    assert Path(result["manifest"]).is_file()
    assert Path(result["database"]).is_file()
    for path in result["reports"].values():
        assert Path(path).is_file()

    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    assert manifest["generated_at"] == now
    assert len(manifest["files"]) == 10
    assert [item["rel_path"] for item in manifest["files"]] == sorted(
        item["rel_path"] for item in manifest["files"]
    )
    assert (config.transcode_dir / "gb18030_no_meta.html").is_file()
    assert fixture_hashes_map() == before


def test_parse_now_normalizes_offsets_and_rejects_invalid_values():
    assert parse_now("2024-01-01T08:00:00+08:00") == "2024-01-01T00:00:00Z"
    assert parse_now("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"
    assert parse_now("2024-01-01T00:00:00") == "2024-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        parse_now("not-a-date")


def test_config_rejects_output_inside_source(tmp_path, make_config):
    responses = tmp_path / "responses"
    responses.mkdir()
    (responses / "sample.txt").write_text("ok", encoding="utf-8")
    with pytest.raises(ConfigError):
        make_config(scan_root=responses, out_dir=responses / "out")
