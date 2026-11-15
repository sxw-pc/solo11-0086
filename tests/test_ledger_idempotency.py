from __future__ import annotations

import sqlite3

from decodebench import RULE_VERSION
from decodebench.ledger_queries import (
    get_batch,
    get_file_detail,
    list_batches,
    list_files,
)
from decodebench.pipeline import run


def test_repeated_batch_updates_one_batch_without_duplicate_files(
    run_demo, now, fixture_hashes_map
):
    before = fixture_hashes_map()
    config, first = run_demo()
    second = run(config, now)
    after = fixture_hashes_map()
    assert before == after
    assert first["batch_id"] == second["batch_id"]
    assert first["ledger"] == second["ledger"]

    connection = sqlite3.connect(config.db_path)
    connection.row_factory = sqlite3.Row
    try:
        batches = connection.execute("SELECT * FROM batches").fetchall()
        assert len(batches) == 1
        assert batches[0]["run_count"] == 2
        assert batches[0]["status"] == "reprocessed"
        assert connection.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 10
        assert (
            connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            == first["ledger"]["evidence_rows"]
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM warnings").fetchone()[0]
            == first["ledger"]["warning_rows"]
        )
        file_row = connection.execute(
            "SELECT * FROM files ORDER BY rel_path LIMIT 1"
        ).fetchone()
        expected = f"{file_row['source_sha256']}:{RULE_VERSION}:{config.fingerprint}"
        assert file_row["idempotency_key"] == expected
        assert file_row["batch_id"] == first["batch_id"]
    finally:
        connection.close()

    assert len(list_batches(config.db_path)) == 1
    batch = get_batch(config.db_path, first["batch_id"])
    assert batch is not None
    files = list_files(config.db_path, first["batch_id"])
    assert [item["rel_path"] for item in files] == sorted(item["rel_path"] for item in files)
    detail = get_file_detail(
        config.db_path, first["batch_id"], "gb18030_with_utf8_meta.html"
    )
    assert detail is not None
    assert detail["final_encoding"] == "gb18030"
    assert detail["decision"]["encoding"] == "gb18030"
    assert detail["evidence"]
    assert detail["warnings"]
    assert detail["evidence"][0]["matches_decision"] in {True, False, None}


def test_missing_database_queries_are_empty(tmp_path):
    missing = tmp_path / "missing.sqlite3"
    assert list_batches(missing) == []
    assert get_batch(missing, "none") is None
    assert list_files(missing, "none") == []
    assert get_file_detail(missing, "none", "x.txt") is None
