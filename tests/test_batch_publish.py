"""候选产物/正式发布分离的批次归档测试。

覆盖：
- 两种发布契约（all_or_nothing 整批发布、qualified_only 合格文件发布）
- 旧批次在新批次失败时仍为当前，且失败文件的旧 UTF-8 输出不得冒充本批成功
- 四个切点的中断/重跑：候选文件写入中途、清单完成台账未提交、
  台账提交后报告未完成、正式发布切换中断
- 同配置幂等、源/配置指纹驱动的候选恢复、正式视图四件套同批次
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from decodebench import archive
from decodebench.pipeline import run


# --------------------------------------------------------------------------- #
# 合成源与公共工具
# --------------------------------------------------------------------------- #
GOOD_ONE = "alpha.txt"
GOOD_TWO = "beta.txt"
BAD_ONE = "broken.txt"


def _make_sources(root: Path, *, include_bad: bool) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / GOOD_ONE).write_text("第一份合格响应\n", encoding="utf-8")
    (root / GOOD_TWO).write_text("second qualified response\n", encoding="utf-8")
    if include_bad:
        # GBK 中文后接孤立 0xff：在仅含 utf-8/gb18030/big5 的候选集下，
        # 没有任何编码可以严格解码（latin-1 等全字节单字节编码不在候选内）。
        (root / BAD_ONE).write_bytes("中文响应".encode("gbk") + b"\xff")


# 与合成源配套的候选集：保证坏文件在 strict 下确实裁决为不可解码。
STRICT_CANDIDATES = ["utf-8", "gb18030", "big5"]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_current(config) -> dict:
    return json.loads((config.out_dir / "current.json").read_text(encoding="utf-8"))


def _state(config, batch_id: str) -> dict:
    return json.loads(
        (archive.batch_dir(config, batch_id) / "state.json").read_text(
            encoding="utf-8"
        )
    )


def _db_pointer(config) -> str:
    connection = sqlite3.connect(config.db_path)
    try:
        row = connection.execute(
            "SELECT batch_id FROM current_pointer WHERE singleton = 1"
        ).fetchone()
        return row[0] if row else None
    finally:
        connection.close()


def _formal_views_agree(config, batch_id: str) -> None:
    """正式 UTF-8 文件、manifest、台账、current.json 必须指向同一批次。"""
    current = _read_current(config)
    assert current["batch_id"] == batch_id
    assert _db_pointer(config) == batch_id
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    assert manifest["publish"]["batch_id"] == batch_id
    assert _sha(config.manifest_path) == current["manifest_sha256"]
    report = json.loads(
        (config.reports_dir / "report.json").read_text(encoding="utf-8")
    )
    assert report["batch_id"] == batch_id
    assert report["publish"]["batch_id"] == batch_id
    assert config.transcode_dir.is_symlink()
    assert config.reports_dir.is_symlink()

    connection = sqlite3.connect(config.db_path)
    connection.row_factory = sqlite3.Row
    try:
        for rel_path in current["published_files"]:
            formal = config.transcode_dir / rel_path
            assert formal.is_file()
            assert formal.resolve().parent == archive.batch_files_dir(
                config, batch_id
            ).resolve()
            entry = next(
                row for row in manifest["files"] if row["rel_path"] == rel_path
            )
            actual_output_sha = _sha(formal)
            # 输出摘要：正式文件 == manifest == SQLite。
            assert actual_output_sha == entry["transcode"]["output_sha256"]
            db_row = connection.execute(
                "SELECT source_sha256, final_encoding, output_sha256, "
                "transcode_success, output_rel_path FROM files "
                "WHERE batch_id = ? AND rel_path = ?",
                (batch_id, rel_path),
            ).fetchone()
            assert db_row is not None
            assert db_row["transcode_success"] == 1
            assert db_row["output_rel_path"] == rel_path
            assert db_row["output_sha256"] == actual_output_sha
            # 源摘要与裁决编码：manifest == SQLite。
            assert db_row["source_sha256"] == entry["source_sha256"]
            assert db_row["final_encoding"] == entry["decision"]["encoding"]
            # 重写证据在 manifest 中逐文件可核。
            assert isinstance(entry["transcode"]["rewrites"], list)
        for rel_path in current["quarantined_files"]:
            entry = next(
                row for row in manifest["files"] if row["rel_path"] == rel_path
            )
            assert entry["transcode"]["success"] is False
            assert entry["transcode"]["output_sha256"] is None
            assert not (config.transcode_dir / rel_path).exists()
            db_row = connection.execute(
                "SELECT transcode_success, output_sha256 FROM files "
                "WHERE batch_id = ? AND rel_path = ?",
                (batch_id, rel_path),
            ).fetchone()
            assert db_row["transcode_success"] == 0
            assert db_row["output_sha256"] is None
    finally:
        connection.close()


class _OneShotFault(RuntimeError):
    """只触发一次的注入故障，重跑时不再抛出。"""


def _install_oneshot(monkeypatch, target, name: str) -> None:
    original = getattr(target, name)
    state = {"fired": False}

    def wrapped(*args, **kwargs):
        if not state["fired"]:
            state["fired"] = True
            raise _OneShotFault(f"injected failure at {name}")
        return original(*args, **kwargs)

    monkeypatch.setattr(target, name, wrapped)


# --------------------------------------------------------------------------- #
# 两种发布契约
# --------------------------------------------------------------------------- #
def test_all_or_nothing_keeps_old_batch_when_any_file_fails(
    tmp_path, make_config
):
    # 第一批：两个合格文件，成功发布为当前批次。
    root_v1 = tmp_path / "src-v1"
    _make_sources(root_v1, include_bad=False)
    config_v1 = make_config(
        scan_root=root_v1,
        publish_policy="all_or_nothing",
        candidates=STRICT_CANDIDATES,
    )
    first = run(config_v1, "2024-01-01T00:00:00Z")
    old_batch = first["batch_id"]
    _formal_views_agree(config_v1, old_batch)
    old_good_bytes = (config_v1.transcode_dir / GOOD_ONE).read_bytes()
    old_manifest_sha = _sha(config_v1.manifest_path)

    # 第二批：同名合格文件内容变更 + 一个严格解码失败文件。
    root_v2 = tmp_path / "src-v2"
    _make_sources(root_v2, include_bad=True)
    (root_v2 / GOOD_ONE).write_text("第一份合格响应-已改版\n", encoding="utf-8")
    config_v2 = make_config(
        scan_root=root_v2,
        out_dir=config_v1.out_dir,
        publish_policy="all_or_nothing",
        candidates=STRICT_CANDIDATES,
    )
    second = run(config_v2, "2024-02-02T00:00:00Z")

    # 整批发布契约：任一文件失败 => 拒绝整批，当前仍是旧批次。
    assert second["batch_id"] != old_batch
    assert second["publish"]["state"] == archive.STATE_REJECTED
    assert second["publish"]["published_files"] == []
    assert set(second["publish"]["quarantined_files"]) == {
        GOOD_ONE,
        GOOD_TWO,
        BAD_ONE,
    }
    current = _read_current(config_v2)
    assert current["batch_id"] == old_batch
    assert _db_pointer(config_v2) == old_batch
    # 正式视图未被新候选污染。
    assert (config_v2.transcode_dir / GOOD_ONE).read_bytes() == old_good_bytes
    assert not (config_v2.transcode_dir / BAD_ONE).exists()
    assert _sha(config_v2.manifest_path) == old_manifest_sha
    # 失败批次的候选证据保留在批次目录，状态可复核。
    candidate = archive.batch_dir(config_v2, second["batch_id"])
    assert (candidate / "manifest.json").is_file()
    assert _state(config_v2, second["batch_id"])["state"] == "rejected"
    # 台账中当前指针仍指旧批次，被拒批次也留痕。
    connection = sqlite3.connect(config_v2.db_path)
    try:
        rows = dict(
            connection.execute(
                "SELECT batch_id, state FROM batch_publish"
            ).fetchall()
        )
        assert rows[old_batch] == "published"
        assert rows[second["batch_id"]] == "rejected"
    finally:
        connection.close()


def test_qualified_only_publishes_just_verified_files_with_quarantine(
    tmp_path, make_config
):
    root_v1 = tmp_path / "src-v1"
    _make_sources(root_v1, include_bad=False)
    config_v1 = make_config(
        scan_root=root_v1,
        publish_policy="qualified_only",
        candidates=STRICT_CANDIDATES,
    )
    first = run(config_v1, "2024-01-01T00:00:00Z")
    old_batch = first["batch_id"]
    old_good_bytes = (config_v1.transcode_dir / GOOD_ONE).read_bytes()

    root_v2 = tmp_path / "src-v2"
    _make_sources(root_v2, include_bad=True)
    (root_v2 / GOOD_ONE).write_text("第一份合格响应-已改版\n", encoding="utf-8")
    config_v2 = make_config(
        scan_root=root_v2,
        out_dir=config_v1.out_dir,
        publish_policy="qualified_only",
        candidates=STRICT_CANDIDATES,
    )
    second = run(config_v2, "2024-02-02T00:00:00Z")
    new_batch = second["batch_id"]
    assert new_batch != old_batch

    # 合格文件发布：当前切换为新批次（隔离态），只含两个已验证文件。
    assert second["publish"]["state"] == archive.STATE_QUARANTINED
    assert sorted(second["publish"]["published_files"]) == sorted(
        [GOOD_ONE, GOOD_TWO]
    )
    assert second["publish"]["quarantined_files"] == [BAD_ONE]
    _formal_views_agree(config_v2, new_batch)
    current = _read_current(config_v2)
    assert current["batch_id"] == new_batch
    assert current["state"] == archive.STATE_QUARANTINED
    assert current["quarantined_files"] == [BAD_ONE]
    # 新合格输出确实是改版内容，而非旧批次同名文件。
    assert (config_v2.transcode_dir / GOOD_ONE).read_bytes() != old_good_bytes
    assert (
        config_v2.transcode_dir / GOOD_ONE
    ).read_text(encoding="utf-8").startswith("第一份合格响应-已改版")
    assert not (config_v2.transcode_dir / BAD_ONE).exists()

    manifest = json.loads(config_v2.manifest_path.read_text(encoding="utf-8"))
    assert manifest["publish"]["policy"] == "qualified_only"
    assert manifest["publish"]["quarantined_files"] == [BAD_ONE]
    bad_entry = next(row for row in manifest["files"] if row["rel_path"] == BAD_ONE)
    assert bad_entry["transcode"]["success"] is False
    assert bad_entry["transcode"]["output_rel_path"] is None
    good_entry = next(
        row for row in manifest["files"] if row["rel_path"] == GOOD_ONE
    )
    # 源摘要/裁决编码/输出摘要/重写证据与台账记录一致。
    connection = sqlite3.connect(config_v2.db_path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM files WHERE batch_id = ? AND rel_path = ?",
            (new_batch, GOOD_ONE),
        ).fetchone()
        assert row["source_sha256"] == good_entry["source_sha256"]
        assert row["final_encoding"] == good_entry["decision"]["encoding"]
        assert row["output_sha256"] == good_entry["transcode"]["output_sha256"]
        assert row["transcode_success"] == 1
        # 实际正式文件摘要与 manifest/台账完全一致。
        assert _sha(config_v2.transcode_dir / GOOD_ONE) == row["output_sha256"]
        bad_row = connection.execute(
            "SELECT transcode_success, output_sha256 FROM files "
            "WHERE batch_id = ? AND rel_path = ?",
            (new_batch, BAD_ONE),
        ).fetchone()
        assert bad_row["transcode_success"] == 0
        assert bad_row["output_sha256"] is None
    finally:
        connection.close()
    # 重写证据字段结构保留（txt 无声明重写时为空列表）。
    assert good_entry["transcode"]["rewrites"] == []


def test_rejected_batch_then_fixed_source_publishes_cleanly(
    tmp_path, make_config
):
    """被拒批次修复源文件后重跑，应发布新批次而不混入旧候选。"""
    root = tmp_path / "src"
    _make_sources(root, include_bad=True)
    config = make_config(scan_root=root, publish_policy="all_or_nothing", candidates=STRICT_CANDIDATES)
    failed = run(config, "2024-01-01T00:00:00Z")
    assert failed["publish"]["state"] == archive.STATE_REJECTED
    assert not config.transcode_dir.exists() or not any(
        config.transcode_dir.rglob("*")
    )

    (root / BAD_ONE).write_text("修复后的合格内容\n", encoding="utf-8")
    fixed = run(config, "2024-01-02T00:00:00Z")
    assert fixed["publish"]["state"] == archive.STATE_PUBLISHED
    assert sorted(fixed["publish"]["published_files"]) == sorted(
        [GOOD_ONE, GOOD_TWO, BAD_ONE]
    )
    _formal_views_agree(config, fixed["batch_id"])


# --------------------------------------------------------------------------- #
# 切点 1：候选文件写完但下一文件失败
# --------------------------------------------------------------------------- #
def test_cutpoint_1_candidate_file_then_failure_and_rerun(
    tmp_path, make_config, monkeypatch
):
    root = tmp_path / "src"
    _make_sources(root, include_bad=True)
    config = make_config(scan_root=root, publish_policy="qualified_only", candidates=STRICT_CANDIDATES)

    # 让第二个合格文件（beta，扫描序在 broken 之前）首次转码后崩溃。
    import decodebench.transcoder as transcoder

    calls = {"n": 0}
    original = transcoder.transcode

    def flaky(source, raw, encoding, cfg, target_dir=None):
        calls["n"] += 1
        result = original(source, raw, encoding, cfg, target_dir=target_dir)
        if calls["n"] == 1:
            raise _OneShotFault("crash after first candidate file")
        return result

    monkeypatch.setattr(transcoder, "transcode", flaky)
    with pytest.raises(_OneShotFault):
        run(config, "2024-01-01T00:00:00Z")

    # 正式视图不存在/未发布；候选区只有第一个文件。
    assert not (config.out_dir / "current.json").exists()
    candidate_dirs = list((config.out_dir / "batches").iterdir())
    assert len(candidate_dirs) == 1
    staged = list((candidate_dirs[0] / "files").rglob("*"))
    assert [p for p in staged if p.is_file()][0].name == GOOD_ONE
    assert not config.transcode_dir.is_symlink()

    monkeypatch.undo()
    result = run(config, "2024-01-02T00:00:00Z")
    # 重跑复用已验证候选，最终只发布两个合格文件（问题文件隔离）。
    assert result["publish"]["state"] == archive.STATE_QUARANTINED
    assert sorted(result["publish"]["published_files"]) == [GOOD_ONE, GOOD_TWO]
    assert result["publish"]["quarantined_files"] == [BAD_ONE]
    _formal_views_agree(config, result["batch_id"])
    # 复用路径核对：候选文件摘要与 state/manifest 一致。
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    for rel in (GOOD_ONE, GOOD_TWO):
        entry = next(row for row in manifest["files"] if row["rel_path"] == rel)
        assert _sha(config.transcode_dir / rel) == entry["transcode"][
            "output_sha256"
        ]


# --------------------------------------------------------------------------- #
# 切点 2：清单完成但 SQLite 未提交
# --------------------------------------------------------------------------- #
def test_cutpoint_2_manifest_ready_before_ledger_commit(
    tmp_path, make_config, monkeypatch
):
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    import decodebench.pipeline as pipeline

    _install_oneshot(monkeypatch, pipeline, "record_batch")
    with pytest.raises(_OneShotFault):
        run(config, "2024-01-01T00:00:00Z")

    batch_dirs = list((config.out_dir / "batches").iterdir())
    assert len(batch_dirs) == 1
    bid = batch_dirs[0].name
    assert _state(config, bid)["state"] == archive.STATE_MANIFEST_READY
    assert (batch_dirs[0] / "manifest.json").is_file()
    assert not (config.out_dir / "current.json").exists()
    # 台账没有文件行（事务未提交）。
    connection = sqlite3.connect(config.db_path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    finally:
        connection.close()

    result = run(config, "2024-01-02T00:00:00Z")
    assert result["publish"]["state"] == archive.STATE_PUBLISHED
    _formal_views_agree(config, result["batch_id"])
    connection = sqlite3.connect(config.db_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM files WHERE batch_id = ?", (result["batch_id"],)
        ).fetchone()[0] == 2
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# 切点 3：SQLite 提交后报告尚未完成
# --------------------------------------------------------------------------- #
def test_cutpoint_3_ledger_committed_before_reports(
    tmp_path, make_config, monkeypatch
):
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    import decodebench.pipeline as pipeline

    _install_oneshot(monkeypatch, pipeline, "write_reports")
    with pytest.raises(_OneShotFault):
        run(config, "2024-01-01T00:00:00Z")

    batch_dirs = list((config.out_dir / "batches").iterdir())
    bid = batch_dirs[0].name
    assert _state(config, bid)["state"] == archive.STATE_LEDGER_READY
    assert not (batch_dirs[0] / "reports").exists() or not list(
        (batch_dirs[0] / "reports").iterdir()
    )
    assert not (config.out_dir / "current.json").exists()
    # 台账已提交且只描述本批候选。
    connection = sqlite3.connect(config.db_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM files WHERE batch_id = ?", (bid,)
        ).fetchone()[0] == 2
    finally:
        connection.close()

    result = run(config, "2024-01-02T00:00:00Z")
    assert result["batch_id"] == bid
    assert result["publish"]["state"] == archive.STATE_PUBLISHED
    _formal_views_agree(config, bid)
    for name in ("report.json", "report.md", "report.html"):
        assert (config.reports_dir / name).is_file()


# --------------------------------------------------------------------------- #
# 切点 4：正式发布切换中断
# --------------------------------------------------------------------------- #
def test_cutpoint_4_publish_switch_interrupted_and_roll_forward(
    tmp_path, make_config, monkeypatch
):
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    # 在固定发布顺序的第一步（transcode 符号链接切换）后崩溃。
    original_replace = archive._replace_symlink
    state = {"n": 0}

    def flaky(link, target_dir):
        original_replace(link, target_dir)
        state["n"] += 1
        if state["n"] == 1:
            raise _OneShotFault("crash mid publish switch")

    monkeypatch.setattr(archive, "_replace_symlink", flaky)
    with pytest.raises(_OneShotFault):
        run(config, "2024-01-01T00:00:00Z")

    batch_dirs = list((config.out_dir / "batches").iterdir())
    bid = batch_dirs[0].name
    assert _state(config, bid)["state"] == archive.STATE_COMMITTED
    # 只完成了第一个链接，reports 链接/current.json/正式 manifest 尚未切换。
    assert config.transcode_dir.is_symlink()
    assert not config.reports_dir.is_symlink()
    assert not (config.out_dir / "current.json").exists()
    assert _db_pointer(config) is None

    monkeypatch.undo()
    result = run(config, "2024-01-02T00:00:00Z")
    # 恢复逻辑前滚剩余发布步骤，当前批次一致且无重复批次。
    assert result["batch_id"] == bid
    assert result["publish"]["state"] == archive.STATE_PUBLISHED
    _formal_views_agree(config, bid)
    connection = sqlite3.connect(config.db_path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM batches").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 2
        assert _db_pointer(config) == bid
    finally:
        connection.close()


def test_publish_interruption_after_manifest_switch_recovers(
    tmp_path, make_config, monkeypatch
):
    """发布顺序后段中断（manifest 已切换、current.json 未写）也能前滚。"""
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    from decodebench.util import atomic_write_bytes

    state = {"n": 0}
    original = atomic_write_bytes

    def flaky(path, payload):
        original(path, payload)
        if path == config.manifest_path:
            state["n"] += 1
            if state["n"] == 1:
                raise _OneShotFault("crash after manifest switch")

    monkeypatch.setattr("decodebench.archive.atomic_write_bytes", flaky)
    with pytest.raises(_OneShotFault):
        run(config, "2024-01-01T00:00:00Z")

    bid = list((config.out_dir / "batches").iterdir())[0].name
    assert config.manifest_path.is_file()
    assert not (config.out_dir / "current.json").exists()

    monkeypatch.undo()
    result = run(config, "2024-01-02T00:00:00Z")
    assert result["batch_id"] == bid
    _formal_views_agree(config, bid)


def test_publish_interruption_between_db_pointer_and_current_json(
    tmp_path, make_config, monkeypatch
):
    """SQLite 指针已切换、current.json 未写时崩溃，重跑据 state.json 前滚。"""
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    import decodebench.archive as archive_mod

    original = archive_mod._write_current_json
    state = {"n": 0}

    def flaky(*args, **kwargs):
        state["n"] += 1
        if state["n"] == 1:
            raise _OneShotFault("crash before current.json")
        return original(*args, **kwargs)

    monkeypatch.setattr(archive_mod, "_write_current_json", flaky)
    with pytest.raises(_OneShotFault):
        run(config, "2024-01-01T00:00:00Z")

    bid = list((config.out_dir / "batches").iterdir())[0].name
    # 链接、manifest、DB 指针已完成；current.json 与最终发布态未落。
    assert config.transcode_dir.is_symlink()
    assert config.reports_dir.is_symlink()
    assert config.manifest_path.is_file()
    assert _db_pointer(config) == bid
    assert not (config.out_dir / "current.json").exists()
    assert _state(config, bid)["state"] == archive.STATE_COMMITTED

    monkeypatch.undo()
    result = run(config, "2024-01-02T00:00:00Z")
    assert result["batch_id"] == bid
    assert result["publish"]["state"] == archive.STATE_PUBLISHED
    _formal_views_agree(config, bid)
    assert _state(config, bid)["state"] == archive.STATE_PUBLISHED


# --------------------------------------------------------------------------- #
# 指纹驱动的候选恢复与防拼接
# --------------------------------------------------------------------------- #
def test_changed_source_invalidates_stale_candidate(tmp_path, make_config):
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)
    first = run(config, "2024-01-01T00:00:00Z")
    old_output = (config.transcode_dir / GOOD_ONE).read_bytes()

    # 修改源内容后重跑：新批次绝不能复用旧同名输出。
    (root / GOOD_ONE).write_text("完全不同的源字节\n", encoding="utf-8")
    second = run(config, "2024-01-02T00:00:00Z")
    assert second["batch_id"] != first["batch_id"]
    new_output = (config.transcode_dir / GOOD_ONE).read_bytes()
    assert new_output != old_output
    assert new_output.decode("utf-8").startswith("完全不同的源字节")
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    entry = next(row for row in manifest["files"] if row["rel_path"] == GOOD_ONE)
    assert _sha(config.transcode_dir / GOOD_ONE) == entry["transcode"][
        "output_sha256"
    ]


def test_rerun_is_idempotent_and_reuses_verified_candidates(
    tmp_path, make_config, monkeypatch
):
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    import decodebench.transcoder as transcoder

    counter = {"n": 0}
    original = transcoder.transcode

    def counting(source, raw, encoding, cfg, target_dir=None):
        counter["n"] += 1
        return original(source, raw, encoding, cfg, target_dir=target_dir)

    monkeypatch.setattr(transcoder, "transcode", counting)
    first = run(config, "2024-01-01T00:00:00Z")
    assert counter["n"] == 2
    second = run(config, "2024-01-02T00:00:00Z")
    # 第二次运行两个文件都命中候选复用，没有重新转码。
    assert counter["n"] == 2
    assert second["batch_id"] == first["batch_id"]
    assert second["ledger"] == first["ledger"]
    _formal_views_agree(config, first["batch_id"])


def test_unrelated_candidate_directories_are_cleaned(tmp_path, make_config):
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)
    result = run(config, "2024-01-01T00:00:00Z")
    # 手工放一个冒充其它批次的未发布候选目录。
    junk = config.out_dir / "batches" / "deadbeefcandidate01"
    (junk / "files").mkdir(parents=True)
    (junk / "state.json").write_text(
        json.dumps(
            {
                "batch_id": "deadbeefcandidate01",
                "state": "building",
                "policy": "all_or_nothing",
                "batch_key": "other",
                "config_fingerprint": "other",
                "source_fingerprint": "other",
                "published_files": [],
                "quarantined_files": [],
                "manifest_sha256": None,
                "updated_at": "2024-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    run(config, "2024-01-03T00:00:00Z")
    assert not junk.exists()
    assert archive.batch_dir(config, result["batch_id"]).is_dir()


def test_declaration_rewrite_evidence_is_published_and_verifiable(
    tmp_path, make_config
):
    """HTML 声明重写证据随批次发布，且与正式 UTF-8 文件实际内容一致。"""
    root = tmp_path / "src"
    root.mkdir(parents=True)
    (root / "page.html").write_bytes(
        '<!doctype html>\n<head><meta charset="gb18030"></head>\n'
        "<body><p>重写声明样本</p></body>\n".encode("gb18030")
    )
    (root / "plain.txt").write_text("plain utf-8\n", encoding="utf-8")
    config = make_config(
        scan_root=root, candidates=["utf-8", "gb18030", "big5"]
    )
    result = run(config, "2024-01-01T00:00:00Z")
    assert result["publish"]["state"] == archive.STATE_PUBLISHED
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    page = next(row for row in manifest["files"] if row["rel_path"] == "page.html")
    rewrites = page["transcode"]["rewrites"]
    assert len(rewrites) == 1
    assert rewrites[0]["kind"] == "html_meta_charset"
    assert rewrites[0]["original"] == "gb18030"
    assert rewrites[0]["new"] == "utf-8"
    formal_text = (config.transcode_dir / "page.html").read_text(encoding="utf-8")
    assert '<meta charset="utf-8">' in formal_text
    assert "gb18030" not in formal_text
    # 台账决策编码与 manifest 一致，正式文件摘要可复核。
    connection = sqlite3.connect(config.db_path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT final_encoding, output_sha256 FROM files "
            "WHERE batch_id = ? AND rel_path = 'page.html'",
            (result["batch_id"],),
        ).fetchone()
        assert row["final_encoding"] == page["decision"]["encoding"]
        assert row["output_sha256"] == _sha(config.transcode_dir / "page.html")
    finally:
        connection.close()


def test_failed_files_old_output_never_stands_in_for_new_batch(
    tmp_path, make_config
):
    """曾成功发布的同名文件在源损坏后重跑，不得用旧 UTF-8 输出冒充成功。"""
    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(
        scan_root=root,
        publish_policy="qualified_only",
        candidates=STRICT_CANDIDATES,
    )
    first = run(config, "2024-01-01T00:00:00Z")
    old_sha = _sha(config.transcode_dir / GOOD_ONE)

    # 让 GOOD_ONE 变成严格不可解码字节，批次身份随之改变。
    (root / GOOD_ONE).write_bytes("中文响应".encode("gbk") + b"\xff")
    second = run(config, "2024-02-02T00:00:00Z")
    assert second["batch_id"] != first["batch_id"]
    assert second["publish"]["quarantined_files"] == [GOOD_ONE]
    assert GOOD_ONE not in second["publish"]["published_files"]
    # 当前视图里 GOOD_ONE 是旧批次的历史文件，不得出现在新批次清单的成功项中。
    manifest = json.loads(config.manifest_path.read_text(encoding="utf-8"))
    entry = next(row for row in manifest["files"] if row["rel_path"] == GOOD_ONE)
    assert entry["transcode"]["success"] is False
    assert entry["transcode"]["output_sha256"] is None
    # 新批次候选区不含 GOOD_ONE 的成功输出，正式视图也不暴露该文件。
    new_files = archive.batch_files_dir(config, second["batch_id"])
    assert not (new_files / GOOD_ONE).exists()
    assert not (config.transcode_dir / GOOD_ONE).exists()
    # 旧批次目录中的历史输出保持原样、仅可经旧批次目录复核。
    old_files = archive.batch_files_dir(config, first["batch_id"])
    assert _sha(old_files / GOOD_ONE) == old_sha
    # 新批次台账中该文件明确失败，绝不引用旧输出摘要。
    connection = sqlite3.connect(config.db_path)
    try:
        row = connection.execute(
            "SELECT transcode_success, output_sha256 FROM files "
            "WHERE batch_id = ? AND rel_path = ?",
            (second["batch_id"], GOOD_ONE),
        ).fetchone()
        assert row[0] == 0
        assert row[1] is None
    finally:
        connection.close()


def test_legacy_database_and_entity_directories_migrate(tmp_path, make_config):
    """旧版数据库（无发布表）与实体输出目录可平滑迁移到新归档布局。"""
    from decodebench.ledger_schema import SCHEMA

    root = tmp_path / "src"
    _make_sources(root, include_bad=False)
    config = make_config(scan_root=root, candidates=STRICT_CANDIDATES)

    # 手工构造旧版库：只建原始四张表，不含 batch_publish/current_pointer。
    config.db_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_schema = SCHEMA.split("-- 发布状态机")[0]
    connection = sqlite3.connect(config.db_path)
    try:
        connection.executescript(legacy_schema)
        connection.commit()
    finally:
        connection.close()
    # 旧版实体目录布局。
    config.transcode_dir.mkdir(parents=True)
    (config.transcode_dir / "old.txt").write_bytes(b"legacy bytes")
    config.reports_dir.mkdir(parents=True)
    (config.reports_dir / "report.json").write_text("{}", encoding="utf-8")

    result = run(config, "2024-01-01T00:00:00Z")
    assert result["publish"]["state"] == archive.STATE_PUBLISHED
    _formal_views_agree(config, result["batch_id"])
    # 新表已迁移，旧实体目录被备份而非删除。
    connection = sqlite3.connect(config.db_path)
    try:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"batch_publish", "current_pointer"} <= names
    finally:
        connection.close()
    assert config.transcode_dir.is_symlink()
    assert config.reports_dir.is_symlink()
    legacy_trans = list(config.out_dir.glob("transcoded.legacy-*"))
    legacy_reports = list(config.out_dir.glob("reports.legacy-*"))
    assert len(legacy_trans) == 1 and len(legacy_reports) == 1
    assert (legacy_trans[0] / "old.txt").read_bytes() == b"legacy bytes"
    # 重跑不再产生新的备份目录。
    run(config, "2024-01-02T00:00:00Z")
    assert len(list(config.out_dir.glob("transcoded.legacy-*"))) == 1
