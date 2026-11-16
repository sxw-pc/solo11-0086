"""离线 gzip 解封装：成员验收、两条归档路线、上限与确定性。"""

from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path

from decodebench.decompress import decompress
from decodebench.pipeline import run
from decodebench.scanner import scan


def gz(payload: bytes, *, level: int = 9) -> bytes:
    compressor = zlib.compressobj(level, zlib.DEFLATED, 31)
    return compressor.compress(payload) + compressor.flush()


def corrupt_second_member(first: bytes, body: bytes) -> bytes:
    """返回 first + 一个 CRC32 被翻转的第二 member。"""
    broken = bytearray(gz(body))
    broken[-8] ^= 0xFF
    return first + bytes(broken)


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def build_tree(tmp_path: Path, files: dict[str, bytes], headers: dict[str, dict]) -> Path:
    responses = tmp_path / "responses"
    sidecars = tmp_path / "sidecars"
    responses.mkdir(parents=True, exist_ok=True)
    sidecars.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (responses / name).write_bytes(payload)
    for name, entry in headers.items():
        (sidecars / f"{name}.headers.json").write_text(
            json.dumps({"status": 200, "headers": entry}), encoding="utf-8"
        )
    return responses


def entry(manifest: dict, name: str) -> dict:
    return next(item for item in manifest["files"] if item["rel_path"] == name)


BODY_A = ("<html><head><meta charset=\"utf-8\"></head><body>" + "第一段正文。" * 8).encode()
BODY_B = ("<p>" + "第二段正文，串接 member。" * 8 + "</p></body></html>").encode()
