"""端到端流水线：扫描 → 证据 → 决策 → 候选转码 → 诊断 → 台账 → 发布。

与旧实现的关键区别：转码产物先进入 ``out/batches/<batch_id>/files`` 候选区，
清单、台账、报告全部在候选批次内完成并核对后，才按固定发布顺序切换正式
视图（见 :mod:`decodebench.archive`）。任何切点中断都不会让正式目录出现
“新文件 + 旧清单/台账”的混合状态。
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import archive
from . import transcoder as transcoder_module
from .config import Config
from .evidence import collect_evidence
from .ledger import _batch_identity, record_batch, reserve_batch
from .manifest import build_file_entry, build_manifest
from .mojibake import diagnose_bytes, to_warning_items
from .models import WarningItem
from .reporting import write_reports
from .resolver import resolve
from .scanner import ScanError, scan
from .scorer import analyze_candidates
from .util import write_json


class PipelineError(RuntimeError):
    """流水线不可恢复错误。"""


def _transcode_warning(result: Any) -> WarningItem:
    return WarningItem(
        code="E_UNDECODABLE",
        severity="high",
        message=f"转码失败：{result.error or '未知解码错误'}",
    )


def _manifest_sha256(path: Any) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(config: Config, now: str) -> dict[str, Any]:
    """运行一个确定性批次并返回可打印摘要。"""
    config.ensure_directories()
    # 启动恢复：若上一次运行在正式切换阶段中断，先把当前批次前滚到一致状态。
    archive.recover_published_state(config, now)

    try:
        sources = scan(config)
    except ScanError as exc:
        raise PipelineError(str(exc)) from exc

    source_fp = archive.source_fingerprint(sources)
    # 先执行每文件决策，批次身份只依赖源摘要/相对路径/配置指纹，
    # 与转码结果无关（与 ledger._batch_identity 的 key 构成保持一致）。
    staged: list[dict[str, Any]] = []
    for source in sources:
        try:
            raw = source.path.read_bytes()
        except OSError as exc:
            raise PipelineError(f"无法读取 {source.rel_path}: {exc}") from exc
        evidence = collect_evidence(source, raw, config)
        candidates = analyze_candidates(raw, config.candidate_encodings)
        decision, evidence, warnings = resolve(raw, source, evidence, candidates, config)
        mojibake = diagnose_bytes(raw, decision.encoding, config)
        warnings.extend(to_warning_items(mojibake))
        staged.append(
            {
                "source": source,
                "raw": raw,
                "evidence": evidence,
                "candidates": candidates,
                "decision": decision,
                "mojibake": mojibake,
                "warnings": warnings,
            }
        )

    identity_files = [
        {"source_sha256": item["source"].sha256, "rel_path": item["source"].rel_path}
        for item in staged
    ]
    batch_key, batch_id = _batch_identity(identity_files, config)
    policy = config.publish_policy

    archive.prepare_batch(config, batch_id, batch_key, source_fp, policy, now)
    files_root = archive.batch_files_dir(config, batch_id)

    # 切点 1 覆盖区：候选文件逐个写入候选区，正式视图不受影响。
    saved_results = archive._load_results(config, batch_id)
    entries: list[dict[str, Any]] = []
    for item in staged:
        source = item["source"]
        raw = item["raw"]
        decision = item["decision"]
        warnings = item["warnings"]

        reusable = archive.reusable_candidate(
            config, batch_id, source, decision.encoding
        )
        if reusable is not None:
            from .models import TranscodeResult

            output = TranscodeResult(**reusable)
        else:
            output = transcoder_module.transcode(
                source, raw, decision.encoding, config, target_dir=files_root
            )
            saved_results[source.rel_path] = output.to_dict()
            archive.save_results(config, batch_id, saved_results)

        if not output.success and not any(
            warning.code == "E_UNDECODABLE" for warning in warnings
        ):
            warnings.append(_transcode_warning(output))
        entries.append(
            build_file_entry(
                source,
                raw,
                item["evidence"],
                item["candidates"],
                decision,
                output,
                item["mojibake"],
                warnings,
            )
        )

    qualified = [
        item["rel_path"] for item in entries if item["transcode"]["success"]
    ]
    failed = [
        item["rel_path"] for item in entries if not item["transcode"]["success"]
    ]

    if policy == archive.POLICY_ALL_OR_NOTHING:
        # 整批发布：任一文件失败即拒绝整批，正式视图保持旧批次。
        if failed:
            published: list[str] = []
            quarantined: list[str] = qualified + failed
        else:
            published, quarantined = qualified, []
    else:
        # 合格文件发布：合格子集进入当前，问题文件进入隔离列表。
        published, quarantined = qualified, failed

    # 候选清单（含发布契约与源/配置指纹），先落候选目录。
    manifest = build_manifest(
        config,
        now,
        entries,
        batch_id=batch_id,
        batch_key=batch_key,
        source_fingerprint=source_fp,
        published_files=published,
        quarantined_files=quarantined,
    )
    candidate_manifest = archive.batch_manifest_path(config, batch_id)
    write_json(candidate_manifest, manifest)  # 切点 2：清单完成
    manifest_sha = _manifest_sha256(candidate_manifest)
    reserve_batch(config, batch_id, batch_key, now, len(entries))
    archive.write_state(
        config,
        batch_id,
        archive.STATE_MANIFEST_READY,
        policy=policy,
        batch_key=batch_key,
        source_fp=source_fp,
        published=published,
        quarantined=quarantined,
        now=now,
        manifest_sha256=manifest_sha,
    )

    # 台账在单个 SQLite 事务提交（切点 3：提交后报告尚未完成也可恢复）。
    ledger_summary = record_batch(config, manifest, now)
    archive.write_state(
        config,
        batch_id,
        archive.STATE_LEDGER_READY,
        policy=policy,
        batch_key=batch_key,
        source_fp=source_fp,
        published=published,
        quarantined=quarantined,
        now=now,
        manifest_sha256=manifest_sha,
    )

    report_paths = write_reports(
        config,
        manifest,
        ledger_summary,
        now,
        target_dir=archive.batch_reports_dir(config, batch_id),
    )

    # 终态裁决：整批发布失败 => rejected（不切换正式视图）；
    # 合格文件发布且有隔离项 => quarantined（合格子集仍切换为当前）。
    rejected = policy == archive.POLICY_ALL_OR_NOTHING and bool(failed)
    terminal_state = (
        archive.STATE_REJECTED
        if rejected
        else (archive.STATE_QUARANTINED if failed else archive.STATE_COMMITTED)
    )
    archive.write_state(
        config,
        batch_id,
        archive.STATE_REPORTS_READY if not rejected else terminal_state,
        policy=policy,
        batch_key=batch_key,
        source_fp=source_fp,
        published=published,
        quarantined=quarantined,
        now=now,
        manifest_sha256=manifest_sha,
    )

    if not rejected:
        # 切点 4：正式发布切换；内部每步原子，崩溃后由 recover 前滚。
        # publish_batch 末尾把状态落为 published（无隔离）或 quarantined。
        archive.write_state(
            config,
            batch_id,
            archive.STATE_COMMITTED,
            policy=policy,
            batch_key=batch_key,
            source_fp=source_fp,
            published=published,
            quarantined=quarantined,
            now=now,
            manifest_sha256=manifest_sha,
        )
        state = archive.read_state(config, batch_id)
        assert state is not None
        archive.publish_batch(config, batch_id, state, now)
        final_state = (
            archive.STATE_QUARANTINED if quarantined else archive.STATE_PUBLISHED
        )
        formal_manifest = config.manifest_path
        formal_reports = {
            name: config.reports_dir / path.name for name, path in report_paths.items()
        }
    else:
        # 拒绝：正式视图保持旧批次；候选证据保留在批次目录供复核。
        final_state = terminal_state
        formal_manifest = config.manifest_path
        formal_reports = {name: path for name, path in report_paths.items()}

    archive.cleanup_unrelated_candidates(config, {batch_id})

    return {
        "batch_id": ledger_summary["batch_id"],
        "manifest": formal_manifest.as_posix(),
        "database": config.db_path.as_posix(),
        "reports": {name: path.as_posix() for name, path in formal_reports.items()},
        "summary": manifest["summary"],
        "ledger": ledger_summary,
        "publish": {
            "policy": policy,
            "state": final_state,
            "published_files": sorted(published),
            "quarantined_files": sorted(quarantined),
            "candidate_dir": archive.batch_dir(config, batch_id).as_posix(),
        },
    }
