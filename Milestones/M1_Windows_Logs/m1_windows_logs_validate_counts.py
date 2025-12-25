#!/usr/bin/env python3
"""
Validate M1 Windows Logs ingestion by comparing CSV row counts vs DB rows.

Checks per (device, tool, run_id, channel):
- CSV rows (header excluded)
- WIN_EVENT_CORE rows (by win_acq_id)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from m1_windows_logs_batch_runner import (  # noqa: E402
    iter_csv_targets,
    load_default_dataset_root,
    load_default_mysql_config,
)


@dataclass(frozen=True)
class Key:
    device_label: str
    tool_tag: str
    run_id: str
    channel_name: str


def import_mysql_connector():
    try:
        import mysql.connector  # type: ignore
    except Exception as exc:
        raise SystemExit(
            "Missing mysql-connector-python. Install with: pip install mysql-connector-python\n"
            f"Details: {exc}"
        )
    return mysql.connector


def connect_mysql(host: str, port: int, user: str, password: str, database: str):
    mysql = import_mysql_connector()
    return mysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        autocommit=True,
    )


def missing_tables(conn, database: str, required: List[str]) -> List[str]:
    if not required:
        return []
    required_lower = [name.lower() for name in required]
    placeholders = ", ".join(["%s"] * len(required_lower))
    sql = f"""
    SELECT LOWER(table_name)
    FROM information_schema.tables
    WHERE table_schema = %s AND LOWER(table_name) IN ({placeholders})
    """
    params = [database] + required_lower
    with conn.cursor() as cur:
        cur.execute(sql, params)
        present = {row[0] for row in cur.fetchall()}
    missing = [name for name in required_lower if name not in present]
    return [name.upper() for name in missing]


def count_csv_rows(csv_path: Path) -> int:
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            return 0
        if len(header) == 1 and "no events" in header[0].lower():
            return 0
        return sum(1 for _ in reader)


def collect_csv_counts(
    dataset_root: Path,
    device_label: Optional[str],
    tool_tag: Optional[str],
    run_id: Optional[str],
    channel_name: Optional[str],
) -> Dict[Key, Dict[str, int]]:
    counts: Dict[Key, Dict[str, int]] = {}
    for target in iter_csv_targets(
        dataset_root,
        device_label=device_label,
        tool_tag=tool_tag,
        run_id=run_id,
        channel_name=channel_name,
    ):
        key = Key(
            device_label=target.device_label,
            tool_tag=target.tool_tag,
            run_id=target.run_id,
            channel_name=target.channel_name,
        )
        entry = counts.setdefault(key, {"csv_files": 0, "csv_rows": 0})
        entry["csv_files"] += 1
        entry["csv_rows"] += count_csv_rows(target.csv_path)
    return counts


def fetch_device_map(conn) -> Dict[str, int]:
    mapping: Dict[str, int] = {}
    with conn.cursor() as cur:
        cur.execute("SELECT device_id, device_label FROM DEVICE_MASTER")
        for device_id, label in cur.fetchall():
            if label:
                mapping[str(label)] = int(device_id)
    return mapping


def fetch_acq_map(conn) -> Dict[Tuple[int, str, str, str], int]:
    mapping: Dict[Tuple[int, str, str, str], int] = {}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT win_acq_id, device_id, run_id, channel_name, tool_name
            FROM WIN_LOG_ACQUISITION
            """
        )
        for row in cur.fetchall():
            win_acq_id, device_id, run_id, channel_name, tool_name = row
            key = (int(device_id), str(run_id), str(channel_name), str(tool_name))
            mapping[key] = int(win_acq_id)
    return mapping


def fetch_event_counts(conn) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT win_acq_id, COUNT(*)
            FROM WIN_EVENT_CORE
            WHERE win_acq_id IS NOT NULL
            GROUP BY win_acq_id
            """
        )
        for win_acq_id, total in cur.fetchall():
            counts[int(win_acq_id)] = int(total)
    return counts


def format_row(parts: List[str], widths: List[int]) -> str:
    padded = []
    for value, width in zip(parts, widths):
        text = value[:width]
        padded.append(text.ljust(width))
    return " | ".join(padded)


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate CSV row counts vs DB events (M1)")
    ap.add_argument("--dataset-root", default=None)
    ap.add_argument("--device-label")
    ap.add_argument("--tool-tag")
    ap.add_argument("--run-id")
    ap.add_argument("--channel-name")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero if mismatch found")
    ap.add_argument("--report-path", help="Write JSON report to this path")
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

    csv_counts = collect_csv_counts(
        dataset_root,
        device_label=args.device_label,
        tool_tag=args.tool_tag,
        run_id=args.run_id,
        channel_name=args.channel_name,
    )

    conn = connect_mysql(
        host=mysql_host,
        port=mysql_port,
        user=mysql_user,
        password=mysql_password,
        database=mysql_database,
    )
    try:
        required = ["DEVICE_MASTER", "WIN_LOG_ACQUISITION", "WIN_EVENT_CORE"]
        missing = missing_tables(conn, mysql_database, required)
        if missing:
            print(f"Missing tables: {', '.join(missing)}")
            print("Run: Milestones/M1_Windows_Logs/m1_windows_logs_01_init.mysql.sql")
            return 3
        device_map = fetch_device_map(conn)
        acq_map = fetch_acq_map(conn)
        event_counts = fetch_event_counts(conn)
    finally:
        conn.close()

    report_rows: List[Dict[str, object]] = []
    mismatch = 0
    total_csv = 0
    total_db = 0

    widths = [14, 12, 15, 12, 9, 10, 10, 8, 10]
    header = format_row(
        ["device", "tool", "run_id", "channel", "csv_files", "csv_rows", "db_rows", "delta", "status"],
        widths,
    )
    print(header)
    print("-" * len(header))

    for key, values in sorted(csv_counts.items(), key=lambda k: (k[0].device_label, k[0].run_id, k[0].channel_name)):
        device_id = device_map.get(key.device_label)
        status = "OK"
        win_acq_id = None
        db_rows = 0

        if device_id is None:
            status = "NO_DEVICE"
        else:
            acq_key = (device_id, key.run_id, key.channel_name, key.tool_tag)
            win_acq_id = acq_map.get(acq_key)
            if win_acq_id is None:
                status = "NO_ACQ"
            else:
                db_rows = event_counts.get(win_acq_id, 0)

        csv_rows = values["csv_rows"]
        delta = csv_rows - db_rows
        if status == "OK" and delta != 0:
            status = "MISMATCH"
            mismatch += 1
        elif status != "OK":
            mismatch += 1

        total_csv += csv_rows
        total_db += db_rows

        row = format_row(
            [
                key.device_label,
                key.tool_tag,
                key.run_id,
                key.channel_name,
                str(values["csv_files"]),
                str(csv_rows),
                str(db_rows),
                str(delta),
                status,
            ],
            widths,
        )
        print(row)

        report_rows.append(
            {
                "device_label": key.device_label,
                "tool_tag": key.tool_tag,
                "run_id": key.run_id,
                "channel_name": key.channel_name,
                "csv_files": values["csv_files"],
                "csv_rows": csv_rows,
                "db_rows": db_rows,
                "delta": delta,
                "status": status,
                "win_acq_id": win_acq_id,
            }
        )

    print(f"\nTotal CSV rows: {total_csv} | Total DB rows: {total_db} | Issues: {mismatch}")

    if args.report_path:
        report = {
            "dataset_root": str(dataset_root),
            "mysql_host": mysql_host,
            "mysql_port": mysql_port,
            "mysql_user": mysql_user,
            "mysql_database": mysql_database,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "rows": report_rows,
        }
        report_path = Path(args.report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report written: {report_path}")

    if args.strict and mismatch:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
