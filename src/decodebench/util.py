"""原子写入与确定性 JSON 序列化。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def json_text(data: Any) -> str:
    return json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
        allow_nan=False,
    ) + "\n"


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(payload)
    os.replace(temporary, path)


def write_json(path: Path, data: Any) -> None:
    atomic_write_bytes(path, json_text(data).encode("utf-8"))


def write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))
