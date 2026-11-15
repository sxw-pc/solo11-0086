"""统计源码与测试行数，并检查单文件 300 行上限。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [ROOT / "src", ROOT / "tests", ROOT / "scripts", ROOT / "decodebench"]
MAX_LINES = 300
MIN_TOTAL = 2500
MAX_TOTAL = 4500


def main() -> int:
    files = sorted(
        path
        for root in SCAN_ROOTS
        if root.exists()
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    rows: list[tuple[Path, int]] = []
    for path in files:
        count = len(path.read_text(encoding="utf-8").splitlines())
        rows.append((path.relative_to(ROOT), count))
    for relative, count in rows:
        print(f"{relative.as_posix():52s} {count:4d}")
    total = sum(count for _, count in rows)
    print("-" * 58)
    print(f"{'TOTAL':52s} {total:4d}")
    oversized = [(path, count) for path, count in rows if count > MAX_LINES]
    for path, count in oversized:
        print(f"OVER LIMIT: {path} = {count} > {MAX_LINES}")
    if not MIN_TOTAL <= total <= MAX_TOTAL:
        print(f"TOTAL OUT OF RANGE: {total}, expected {MIN_TOTAL}-{MAX_TOTAL}")
    return 1 if oversized or not MIN_TOTAL <= total <= MAX_TOTAL else 0


if __name__ == "__main__":
    raise SystemExit(main())
