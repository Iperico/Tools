#!/usr/bin/env python3
r"""
Batch runner for M1 Windows Logs ingestion (read-only on dataset files).

Scans:
  <dataset_root>\<device>\<tool>\<run>\LOGS\<channel>\*.csv
and ingests into the M1 fast-search schema.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent.parent
CONFIG_FILE = TOOLS_DIR / "forensic_config.json"
DEFAULT_MYSQL = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "safenet_ingest",
    "password": "",
    "database": "forensic",
}
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from m1_windows_logs_ingest_skeleton import (  # noqa: E402
    AcquisitionRecord,
    EvidenceFileRecord,
    IngestionManager,
    MysqlWriter,
    DryRunWriter,
    WindowsCsvExtractor,
    compute_sha256,
)


@dataclass
class CsvTarget:
    device_label: str
    tool_tag: str
    run_id: str
    channel_name: str
    csv_path: Path
    run_dir: Path


def parse_run_id(run_id: str) -> Optional[datetime]:
    try:
        return datetime.strptime(run_id, "%Y%m%d_%H%M%S")
    except ValueError:
        return None


def load_default_dataset_root() -> Path:
    fallback = Path("C:/SAFENET/DataSetGlobal/windows_logs")
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            milestones = data.get("milestones", {})
            for key in ("M1 - Windows Logs (fast)", "M1 - Windows Logs", "M02 - Windows Logs"):
                ms = milestones.get(key, {})
                folder = ms.get("folder")
                if folder:
                    return Path(folder)
            workspace = data.get("globals", {}).get("workspace_folder")
            if workspace:
                return Path(workspace) / "DataSetGlobal" / "windows_logs"
        except Exception:
            pass
    return fallback


def load_default_mysql_config() -> Dict[str, object]:
    cfg = DEFAULT_MYSQL.copy()
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            globals_cfg = data.get("globals", {})
            cfg["host"] = globals_cfg.get("mysql_host", cfg["host"])
            cfg["port"] = int(globals_cfg.get("mysql_port", cfg["port"]))
            cfg["user"] = globals_cfg.get("mysql_user", cfg["user"])
            cfg["password"] = globals_cfg.get("mysql_password", cfg["password"])
            cfg["database"] = globals_cfg.get("mysql_database", cfg["database"])
        except Exception:
            pass
    return cfg


def iter_csv_targets(
    dataset_root: Path,
    device_label: Optional[str] = None,
    tool_tag: Optional[str] = None,
    run_id: Optional[str] = None,
    channel_name: Optional[str] = None,
) -> Iterable[CsvTarget]:
    for device_dir in sorted(dataset_root.iterdir()):
        if not device_dir.is_dir():
            continue
        if device_label and device_dir.name != device_label:
            continue
        for tool_dir in sorted(device_dir.iterdir()):
            if not tool_dir.is_dir():
                continue
            if tool_tag and tool_dir.name != tool_tag:
                continue
            for run_dir in sorted(tool_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                if run_id and run_dir.name != run_id:
                    continue
                logs_root = run_dir / "LOGS"
                if not logs_root.is_dir():
                    continue
                for channel_dir in sorted(logs_root.iterdir()):
                    if not channel_dir.is_dir():
                        continue
                    if channel_name and channel_dir.name != channel_name:
                        continue
                    for csv_path in sorted(channel_dir.glob("*.csv")):
                        yield CsvTarget(
                            device_label=device_dir.name,
                            tool_tag=tool_dir.name,
                            run_id=run_dir.name,
                            channel_name=channel_dir.name,
                            csv_path=csv_path,
                            run_dir=run_dir,
                        )


def pick_evidence_path(
    run_dir: Path,
    channel_name: str,
    csv_path: Path,
    prefer: str,
) -> Optional[Path]:
    if prefer == "csv":
        return csv_path

    evtx = find_evtx_candidate(run_dir, channel_name)
    if prefer == "evtx":
        return evtx

    return evtx or csv_path


def find_evtx_candidate(run_dir: Path, channel_name: str) -> Optional[Path]:
    channel_lower = channel_name.lower()
    candidates: List[Path] = []

    logs_channel = run_dir / "LOGS" / channel_name
    raw_all = run_dir / "RAW_ALL"

    for folder in (logs_channel, raw_all):
        if folder.is_dir():
            candidates.extend(sorted(folder.glob("*.evtx")))

    if not candidates:
        return None

    for path in candidates:
        if channel_lower in path.name.lower():
            return path
    return candidates[0]


def evidence_type_from_path(path: Path) -> str:
    ext = path.suffix.lower().lstrip(".")
    if not ext:
        return "unknown"
    return ext


def build_evidence_record(
    evidence_path: Path,
    tool_name: str,
    tool_version: Optional[str],
    compute_hash: bool,
) -> EvidenceFileRecord:
    stat = evidence_path.stat()
    file_hash = compute_sha256(evidence_path) if compute_hash else None
    return EvidenceFileRecord(
        evidence_type=evidence_type_from_path(evidence_path),
        file_path=str(evidence_path),
        file_hash_sha256=file_hash,
        file_size_bytes=stat.st_size,
        collected_at_utc=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).replace(tzinfo=None),
        tool_name=tool_name,
        tool_version=tool_version,
    )


def build_acquisition_record(
    target: CsvTarget,
    tool_version: Optional[str],
) -> AcquisitionRecord:
    run_dt = parse_run_id(target.run_id)
    return AcquisitionRecord(
        device_label=target.device_label,
        run_id=target.run_id,
        channel_name=target.channel_name,
        tool_name=target.tool_tag,
        tool_version=tool_version,
        source_path=str(target.csv_path),
        collected_at_utc=run_dt,
    )


def build_report_path(path: Optional[str]) -> Optional[Path]:
    if not path:
        return None
    return Path(path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Batch runner for M1 Windows Logs")
    ap.add_argument(
        "--dataset-root",
        default=None,
        help="DataSetGlobal/windows_logs root (default from forensic_config.json)",
    )
    ap.add_argument("--device-label", help="Filter device label")
    ap.add_argument("--tool-tag", help="Filter tool tag")
    ap.add_argument("--run-id", help="Filter run id (YYYYMMDD_HHMMSS)")
    ap.add_argument("--channel-name", help="Filter channel name")
    ap.add_argument("--evidence-prefer", choices=["auto", "evtx", "csv"], default="auto")
    ap.add_argument("--hash-evidence", action="store_true", help="Compute SHA256 for evidence")
    ap.add_argument("--tool-version", help="Tool version for acquisition/evidence")
    ap.add_argument("--account-label", help="Default account label")
    ap.add_argument("--limit-events-per-file", type=int, help="Limit rows per CSV")
    ap.add_argument("--dry-run", action="store_true", help="No DB writes")
    ap.add_argument("--report-path", help="Write JSON report to this path")
    ap.add_argument("--continue-on-error", action="store_true", help="Keep going on errors")
    ap.add_argument("--mysql-host", default=None)
    ap.add_argument("--mysql-port", type=int, default=None)
    ap.add_argument("--mysql-user", default=None)
    ap.add_argument("--mysql-password", default=None)
    ap.add_argument("--mysql-database", default=None)
    args = ap.parse_args()

    dataset_root = Path(args.dataset_root) if args.dataset_root else load_default_dataset_root()
    if not dataset_root.is_dir():
        raise SystemExit(f"Dataset root not found: {dataset_root}")

    mysql_cfg = load_default_mysql_config()
    mysql_host = args.mysql_host or mysql_cfg["host"]
    mysql_port = int(args.mysql_port or mysql_cfg["port"])
    mysql_user = args.mysql_user or mysql_cfg["user"]
    mysql_password = args.mysql_password if args.mysql_password is not None else mysql_cfg["password"]
    mysql_database = args.mysql_database or mysql_cfg["database"]

    report_path = build_report_path(args.report_path)
    report: Dict[str, object] = {
        "dataset_root": str(dataset_root),
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "dry_run": args.dry_run,
        "mysql_host": mysql_host,
        "mysql_port": mysql_port,
        "mysql_user": mysql_user,
        "mysql_database": mysql_database,
        "files": [],
        "total_events": 0,
        "total_files": 0,
        "errors": 0,
    }

    writer = DryRunWriter() if args.dry_run else MysqlWriter(
        host=mysql_host,
        port=mysql_port,
        user=mysql_user,
        password=mysql_password,
        database=mysql_database,
    )
    manager = IngestionManager(writer)

    evidence_cache: Dict[str, Optional[int]] = {}
    acq_cache: Dict[Tuple[str, str, str, str], Optional[int]] = {}

    try:
        for target in iter_csv_targets(
            dataset_root,
            device_label=args.device_label,
            tool_tag=args.tool_tag,
            run_id=args.run_id,
            channel_name=args.channel_name,
        ):
            report["total_files"] = int(report["total_files"]) + 1
            result: Dict[str, object] = {
                "device_label": target.device_label,
                "tool_tag": target.tool_tag,
                "run_id": target.run_id,
                "channel_name": target.channel_name,
                "csv_path": str(target.csv_path),
            }
            try:
                evidence_path = pick_evidence_path(
                    target.run_dir,
                    target.channel_name,
                    target.csv_path,
                    args.evidence_prefer,
                )
                evidence_id = None
                if evidence_path and evidence_path.exists():
                    result["evidence_path"] = str(evidence_path)
                    evidence_key = str(evidence_path)
                    evidence_id = evidence_cache.get(evidence_key)
                    if evidence_id is None:
                        evidence = build_evidence_record(
                            evidence_path=evidence_path,
                            tool_name=target.tool_tag,
                            tool_version=args.tool_version,
                            compute_hash=args.hash_evidence,
                        )
                        evidence_id = writer.insert_evidence(evidence)
                        evidence_cache[evidence_key] = evidence_id

                acq_key = (
                    target.device_label,
                    target.run_id,
                    target.channel_name,
                    target.tool_tag,
                )
                win_acq_id = acq_cache.get(acq_key)
                if win_acq_id is None:
                    acquisition = build_acquisition_record(target, args.tool_version)
                    if evidence_id and not acquisition.evidence_id:
                        acquisition.evidence_id = evidence_id
                    win_acq_id = writer.insert_acquisition(acquisition)
                    acq_cache[acq_key] = win_acq_id

                extractor = WindowsCsvExtractor(
                    csv_path=target.csv_path,
                    device_label=target.device_label,
                    default_channel=target.channel_name,
                    account_label=args.account_label,
                    limit=args.limit_events_per_file,
                )
                inserted = manager.ingest(
                    extractor,
                    existing_evidence_id=evidence_id,
                    existing_win_acq_id=win_acq_id,
                )
                report["total_events"] = int(report["total_events"]) + inserted
                result["events_inserted"] = inserted
                result["status"] = "ok"
            except Exception as exc:
                result["status"] = "error"
                result["error"] = str(exc)
                report["errors"] = int(report["errors"]) + 1
                if not args.continue_on_error:
                    report["files"].append(result)
                    raise
            report["files"].append(result)
    finally:
        writer.close()

    report["ended_at_utc"] = datetime.now(timezone.utc).isoformat()

    print(
        f"Processed files: {report['total_files']}, "
        f"events: {report['total_events']}, errors: {report['errors']}"
    )
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"Report written: {report_path}")


if __name__ == "__main__":
    main()
