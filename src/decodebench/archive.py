"""候选产物与正式发布分离的批次归档。

设计要点（供复核人员核对）：

1. 每次运行先在 ``out/batches/<batch_id>/`` 下构建**候选批次**：UTF-8 候选
   文件、候选清单、候选报告都只写在该批次目录内，正式视图（transcode_dir、
   reports_dir、manifest.json）在发布完成前不被修改。
2. 每个批次有持久化状态文件 ``state.json`` 与 SQLite ``batch_publish`` 行，
   状态机覆盖：building → manifest_ready → ledger_ready → reports_ready →
   committed / published / rejected / quarantined。
3. 发布通过两个固定位置的相对符号链接（transcode_dir、reports_dir）与
   current.json、manifest.json、SQLite 当前指针按**固定顺序**切换；单文件
   os.replace/os.symlink 各自原子，跨对象的整批一致性由状态机在重跑时
   前滚（roll-forward）保证，而不是假装存在全局原子事务。
4. 重跑依据保存的源/配置指纹与实际文件摘要恢复已验证候选；指纹不匹配或
   属于其它批次的候选目录一律清理，绝不把旧批次同名输出与本次候选拼接。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .config import Config
from .ledger import (
    get_current_pointer,
    get_publish_state,
    record_publish_state,
    set_current_pointer,
)
from .util import atomic_write_bytes, write_json

POLICY_ALL_OR_NOTHING = "all_or_nothing"
POLICY_QUALIFIED_ONLY = "qualified_only"
POLICIES = (POLICY_ALL_OR_NOTHING, POLICY_QUALIFIED_ONLY)

# 状态机
STATE_BUILDING = "building"
STATE_MANIFEST_READY = "manifest_ready"
STATE_LEDGER_READY = "ledger_ready"
STATE_REPORTS_READY = "reports_ready"
STATE_COMMITTED = "committed"
STATE_PUBLISHED = "published"
STATE_REJECTED = "rejected"
STATE_QUARANTINED = "quarantined"

STATE_FILENAME = "state.json"
MANIFEST_FILENAME = "manifest.json"
REPORTS_DIRNAME = "reports"
FILES_DIRNAME = "files"
CURRENT_FILENAME = "current.json"
RESULTS_FILENAME = "transcode-results.json"


# --------------------------------------------------------------------------- #
# 路径与基础工具
# --------------------------------------------------------------------------- #
def batches_root(config: Config) -> Path:
    return config.out_dir / "batches"


def batch_dir(config: Config, batch_id: str) -> Path:
    return batches_root(config) / batch_id


def batch_files_dir(config: Config, batch_id: str) -> Path:
    return batch_dir(config, batch_id) / FILES_DIRNAME


def batch_manifest_path(config: Config, batch_id: str) -> Path:
    return batch_dir(config, batch_id) / MANIFEST_FILENAME


def batch_reports_dir(config: Config, batch_id: str) -> Path:
    return batch_dir(config, batch_id) / REPORTS_DIRNAME


def current_pointer_path(config: Config) -> Path:
    return config.out_dir / CURRENT_FILENAME


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_fingerprint(sources: list[Any]) -> str:
    """源集合指纹：相对路径 + 源摘要的确定性哈希。"""
    parts = sorted(f"{item.rel_path}|{item.sha256}" for item in sources)
    return hashlib.sha256(
        json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _atomic_write_json(path: Path, data: Any) -> None:
    write_json(path, data)


def read_state(config: Config, batch_id: str) -> dict[str, Any] | None:
    path = batch_dir(config, batch_id) / STATE_FILENAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_state(
    config: Config,
    batch_id: str,
    state: str,
    *,
    policy: str,
    batch_key: str,
    source_fp: str,
    published: list[str] | None = None,
    quarantined: list[str] | None = None,
    now: str,
    manifest_sha256: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """状态文件先落盘（含 fsync 的原子写），再镜像到 SQLite。"""
    payload: dict[str, Any] = {
        "batch_id": batch_id,
        "state": state,
        "policy": policy,
        "batch_key": batch_key,
        "config_fingerprint": config.fingerprint,
        "source_fingerprint": source_fp,
        "published_files": sorted(published or []),
        "quarantined_files": sorted(quarantined or []),
        "manifest_sha256": manifest_sha256,
        "updated_at": now,
    }
    if extra:
        payload.update(extra)
    _atomic_write_json(batch_dir(config, batch_id) / STATE_FILENAME, payload)
    record_publish_state(
        config,
        batch_id,
        state,
        policy,
        payload["published_files"],
        payload["quarantined_files"],
        batch_key,
        source_fp,
        now,
    )
    return payload


# --------------------------------------------------------------------------- #
# 候选恢复与清理
# --------------------------------------------------------------------------- #
def _load_results(config: Config, batch_id: str) -> dict[str, dict[str, Any]]:
    path = batch_dir(config, batch_id) / RESULTS_FILENAME
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_results(
    config: Config, batch_id: str, results: dict[str, dict[str, Any]]
) -> None:
    _atomic_write_json(batch_dir(config, batch_id) / RESULTS_FILENAME, results)


def reusable_candidate(
    config: Config,
    batch_id: str,
    source: Any,
    decision_encoding: str,
) -> dict[str, Any] | None:
    """仅当候选产物与当前源字节、裁决编码、配置指纹全部一致时才复用。

    同时重新计算磁盘候选文件摘要，防止把上次同名输出当作本批成功结果。
    """
    state = read_state(config, batch_id)
    if state is None or state.get("config_fingerprint") != config.fingerprint:
        return None
    saved = _load_results(config, batch_id).get(source.rel_path)
    if not saved or not saved.get("success"):
        return None
    if saved.get("source_sha256") != source.sha256:
        return None
    if saved.get("encoding") != decision_encoding:
        return None
    candidate_path = batch_files_dir(config, batch_id) / source.rel_path
    actual_sha = _sha256_file(candidate_path)
    if actual_sha is None or actual_sha != saved.get("output_sha256"):
        return None
    return saved


def prepare_batch(
    config: Config,
    batch_id: str,
    batch_key: str,
    source_fp: str,
    policy: str,
    now: str,
) -> None:
    """创建/校验候选批次目录；指纹不匹配的未发布候选整体清理后重建。"""
    root = batch_dir(config, batch_id)
    state = read_state(config, batch_id)
    if state is not None:
        same_fingerprint = (
            state.get("config_fingerprint") == config.fingerprint
            and state.get("source_fingerprint") == source_fp
            and state.get("batch_key") == batch_key
        )
        if not same_fingerprint and state.get("state") not in {
            STATE_PUBLISHED,
            STATE_COMMITTED,
            STATE_QUARANTINED,
        }:
            # 同 batch_id 但内容已变：旧候选不可信，清理重建，杜绝拼接。
            shutil.rmtree(root, ignore_errors=True)
            state = None
    root.mkdir(parents=True, exist_ok=True)
    batch_files_dir(config, batch_id).mkdir(parents=True, exist_ok=True)
    if state is None:
        write_state(
            config,
            batch_id,
            STATE_BUILDING,
            policy=policy,
            batch_key=batch_key,
            source_fp=source_fp,
            now=now,
        )


def cleanup_unrelated_candidates(config: Config, keep_batch_ids: set[str]) -> None:
    """删除不属于本次批次的未发布候选目录；已发布/已提交批次永远保留。"""
    root = batches_root(config)
    if not root.is_dir():
        return
    for child in root.iterdir():
        if not child.is_dir() or child.name in keep_batch_ids:
            continue
        state = read_state(config, child.name)
        if state is None:
            shutil.rmtree(child, ignore_errors=True)
            continue
        if state.get("state") in {
            STATE_PUBLISHED,
            STATE_COMMITTED,
            STATE_QUARANTINED,
        }:
            continue
        shutil.rmtree(child, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 正式视图切换（固定发布顺序，每步原子、可前滚）
# --------------------------------------------------------------------------- #
def _replace_symlink(link: Path, target_dir: Path) -> None:
    """用相对符号链接原子切换目录视图；首次发布时把既有实体目录归档让位。"""
    link.parent.mkdir(parents=True, exist_ok=True)
    relative_target = os.path.relpath(target_dir, start=link.parent)
    if link.is_symlink() or not link.exists():
        temporary = link.with_name(link.name + ".link.tmp")
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()
        os.symlink(relative_target, temporary)
        os.replace(temporary, link)
        return
    # 兼容历史：正式位置是普通目录（首次发布前的旧布局），整体改名为备份。
    legacy = link.with_name(link.name + ".legacy-" + hashlib.sha1(
        str(link).encode("utf-8")
    ).hexdigest()[:10])
    os.replace(link, legacy)
    temporary = link.with_name(link.name + ".link.tmp")
    if temporary.is_symlink() or temporary.exists():
        temporary.unlink()
    os.symlink(relative_target, temporary)
    os.replace(temporary, link)


def _write_current_json(
    config: Config,
    batch_id: str,
    state: str,
    manifest_sha256: str,
    published_files: list[str],
    quarantined_files: list[str],
    policy: str,
    now: str,
) -> None:
    payload = {
        "schema_version": "1.0",
        "batch_id": batch_id,
        "state": state,
        "policy": policy,
        "config_fingerprint": config.fingerprint,
        "manifest_path": config.manifest_path.as_posix(),
        "manifest_sha256": manifest_sha256,
        "transcode_dir": config.transcode_dir.as_posix(),
        "reports_dir": config.reports_dir.as_posix(),
        "database": config.db_path.as_posix(),
        "published_files": sorted(published_files),
        "quarantined_files": sorted(quarantined_files),
        "published_at": now,
    }
    write_json(current_pointer_path(config), payload)


def _current_json_batch(config: Config) -> str | None:
    path = current_pointer_path(config)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    batch_id = data.get("batch_id")
    return batch_id if isinstance(batch_id, str) else None


def _verify_published_artifacts(
    config: Config,
    batch_id: str,
    state: dict[str, Any],
) -> bool:
    """核对正式视图确实指向该批次，且清单摘要与发布文件实际字节一致。"""
    if not config.transcode_dir.is_symlink():
        return False
    if os.readlink(config.transcode_dir) != os.path.relpath(
        batch_files_dir(config, batch_id), start=config.transcode_dir.parent
    ):
        return False
    if not config.reports_dir.is_symlink():
        return False
    if os.readlink(config.reports_dir) != os.path.relpath(
        batch_reports_dir(config, batch_id), start=config.reports_dir.parent
    ):
        return False
    if not config.manifest_path.is_file():
        return False
    if _sha256_file(config.manifest_path) != state.get("manifest_sha256"):
        return False
    for rel_path in state.get("published_files", []):
        formal = config.transcode_dir / rel_path
        candidate = batch_files_dir(config, batch_id) / rel_path
        if not formal.is_file() or not candidate.is_file():
            return False
        if _sha256_file(formal) != _sha256_file(candidate):
            return False
    return True


def roll_forward_published(
    config: Config, batch_id: str, state: dict[str, Any], now: str
) -> None:
    """按固定发布顺序前滚一个已 committed/published 批次的剩余切换步骤。

    发布顺序（每一步本身原子，崩溃后重跑从断点继续）：
      1. transcode_dir 符号链接 → 本批 files/
      2. reports_dir 符号链接 → 本批 reports/
      3. manifest.json → 本批 manifest（os.replace 原子）
      4. SQLite current_pointer → 本批（单事务）
      5. current.json 落盘（权威“当前”描述）
      6. 批次状态 → published/quarantined（state.json + SQLite 单事务）
    """
    published = list(state.get("published_files", []))
    quarantined = list(state.get("quarantined_files", []))
    policy = str(state.get("policy"))
    manifest_sha = str(state.get("manifest_sha256"))
    final_state = STATE_QUARANTINED if quarantined else STATE_PUBLISHED

    _replace_symlink(config.transcode_dir, batch_files_dir(config, batch_id))
    _replace_symlink(config.reports_dir, batch_reports_dir(config, batch_id))

    atomic_write_bytes(
        config.manifest_path,
        batch_manifest_path(config, batch_id).read_bytes(),
    )
    if get_current_pointer(config) != batch_id:
        set_current_pointer(config, batch_id, now)
    _write_current_json(
        config, batch_id, final_state, manifest_sha,
        published, quarantined, policy, now,
    )
    if state.get("state") != final_state:
        write_state(
            config,
            batch_id,
            final_state,
            policy=policy,
            batch_key=str(state.get("batch_key")),
            source_fp=str(state.get("source_fingerprint")),
            published=published,
            quarantined=quarantined,
            now=now,
            manifest_sha256=manifest_sha,
        )


def recover_published_state(config: Config, now: str) -> str | None:
    """启动恢复：若 current.json 与 SQLite 指针/实际视图漂移，按状态前滚。

    返回恢复后当前批次 ID；从未发布过时返回 None，正式视图保持不存在或
    历史实体目录不动（首次发布时才处理）。
    """
    json_batch = _current_json_batch(config)
    db_batch = get_current_pointer(config)
    candidate_id = json_batch or db_batch
    if candidate_id is None:
        return None
    state = read_state(config, candidate_id)
    db_state = get_publish_state(config, candidate_id)
    if state is None or db_state is None:
        # 指针指向的批次状态缺失：不猜测、不拼接，保留指针等待人工核查，
        # 但本次运行会重新构建并发布完整批次来覆盖它。
        return candidate_id
    if state.get("state") in {
        STATE_COMMITTED,
        STATE_PUBLISHED,
        STATE_QUARANTINED,
    }:
        if (
            json_batch == candidate_id
            and db_batch == candidate_id
            and state.get("state") in {STATE_PUBLISHED, STATE_QUARANTINED}
            and _verify_published_artifacts(config, candidate_id, state)
        ):
            return candidate_id
        # 视图已切换但终态尚未写回（committed），或任一正式对象漂移：前滚补齐。
        roll_forward_published(config, candidate_id, state, now)
        return candidate_id
    return candidate_id


def publish_batch(
    config: Config,
    batch_id: str,
    state: dict[str, Any],
    now: str,
) -> None:
    """把一个已提交批次按固定顺序切换为正式当前批次。"""
    roll_forward_published(config, batch_id, state, now)
