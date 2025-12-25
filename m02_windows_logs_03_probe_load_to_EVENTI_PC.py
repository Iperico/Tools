#!/usr/bin/env python
# m02_windows_logs_03_probe_load_to_EVENTI_PC.py
#
# Probe Windows logs normalized in SAFENET and push into EVENTI_PC (MySQL).
#
# v5:
#   - MySQL connector (mysql-connector-python)
#   - reads CSV in utf-8-sig (BOM-safe)
#   - uses parse_event_time from m02_windows_logs_01_log_dump.py
#   - inserts into EVENTI_PC and mirrors raw rows into EVENTI_RAW (json)
#
# Usage:
#
#   python.exe m02_windows_logs_03_probe_load_to_EVENTI_PC.py ^
#       --dataset-root "C:\\SAFENET\\DataSetGlobal\\windows_logs" ^
#       --mysql-host "127.0.0.1" ^
#       --mysql-port 3306 ^
#       --mysql-user "safenet_ingest" ^
#       --mysql-password "..." ^
#       --mysql-database "forensic" ^
#       --source-log "Security" ^
#       --device-label "PICCIRILLA_AleNew" ^
#       --event-code 4624 ^
#       --limit-per-run 20 ^
#       --dry-run
#

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except Exception as e:
    raise SystemExit(
        "Missing mysql-connector-python. Install with: pip install mysql-connector-python\n"
        f"Details: {e}"
    )

# ---------------------------------------------------------------------------
# Import from M02_01 utility (Windows log dumper)
# ---------------------------------------------------------------------------

try:
    from m02_windows_logs_01_log_dump import parse_event_time
except Exception as e:
    raise SystemExit(
        "Impossibile importare parse_event_time da m02_windows_logs_01_log_dump.py.\n"
        "Assicurati che m02_windows_logs_01_log_dump.py sia nella stessa cartella di questo script.\n"
        f"Dettagli: {e}"
    )


# ---------------------------------------------------------------------------
# Helper DB
# ---------------------------------------------------------------------------

def load_device_map(conn) -> Dict[str, int]:
    """
    device_label -> device_id from DEVICE_MASTER.
    """
    cur = conn.cursor()
    cur.execute("SELECT device_id, device_label FROM DEVICE_MASTER")
    mapping: Dict[str, int] = {}
    for device_id, label in cur.fetchall():
        if label:
            mapping[str(label)] = int(device_id)
    cur.close()
    return mapping


def ensure_device_id(conn, device_label: str) -> Optional[int]:
    """
    Ensure a device exists in DEVICE_MASTER and return its device_id.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT device_id FROM DEVICE_MASTER WHERE device_label = %s",
        (device_label,),
    )
    row = cur.fetchone()
    if row:
        device_id = int(row[0])
        cur.close()
        return device_id

    cur.execute(
        """
        INSERT INTO DEVICE_MASTER (device_label, device_type, platform)
        VALUES (%s, %s, %s)
        """,
        (device_label, "PC", "Windows"),
    )
    conn.commit()
    device_id = int(cur.lastrowid) if cur.lastrowid else None
    cur.close()
    return device_id


# ---------------------------------------------------------------------------
# Iteration on SAFENET folders
# ---------------------------------------------------------------------------

def iter_main_log_csv_files(
    dataset_root: Path,
    source_log: str,
    device_label_filter: Optional[str] = None,
) -> Iterable[Tuple[str, str, str, Path]]:
    """
    Scan:

        <dataset_root>/<device_label>/<tool_tag>/<run_id>/LOGS/<source_log>/

    and return tuples:

        (device_label, tool_tag, run_id, csv_path)

    taking ONLY:
        <source_log>.csv
        or <source_log>_events.csv
    """
    src_norm = source_log.strip()

    for dev_dir in sorted(dataset_root.iterdir()):
        if not dev_dir.is_dir():
            continue

        device_label = dev_dir.name
        if device_label_filter and device_label != device_label_filter:
            continue

        for tool_dir in sorted(dev_dir.iterdir()):
            if not tool_dir.is_dir():
                continue
            tool_tag = tool_dir.name

            for run_dir in sorted(tool_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                run_id = run_dir.name

                logs_root = run_dir / "LOGS" / src_norm
                if not logs_root.is_dir():
                    continue

                main_csv = logs_root / f"{src_norm}.csv"
                if main_csv.exists():
                    yield device_label, tool_tag, run_id, main_csv
                    continue

                events_csv = logs_root / f"{src_norm}_events.csv"
                if events_csv.exists():
                    yield device_label, tool_tag, run_id, events_csv
                    continue


# ---------------------------------------------------------------------------
# CSV read (BOM-safe) + extract fields
# ---------------------------------------------------------------------------

def event_rows_from_file(csv_path: Path) -> List[dict]:
    """
    Read a CSV (UTF-8 with BOM) and return a list of dict rows.
    """
    if csv_path.suffix.lower() != ".csv":
        print(f"  [INFO] Skip non-CSV file in this probe: {csv_path}")
        return []

    events: List[dict] = []
    # 'utf-8-sig' strips BOM so header "TimeCreated" is correct
    with csv_path.open("r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)
    return events


def extract_basic_fields(row: dict) -> Tuple[Optional[str], Optional[int], str]:
    """
    Extract:
      - timestamp_utc_str (or raw string if parse fails)
      - event_code (int, if possible)
      - description (Message/Description)
    """
    # Timestamp: common variants
    ts_value = (
        row.get("TimeCreated")
        or row.get("timeCreated")
        or row.get("TimeCreatedUtc")
        or row.get("Date")
        or ""
    )
    ts_value = str(ts_value).strip()

    ts_utc_str: Optional[str]
    if ts_value:
        dt_obj = parse_event_time(ts_value)
        if dt_obj is not None:
            ts_utc_str = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Parse failed: keep raw string
            ts_utc_str = ts_value
    else:
        ts_utc_str = None

    # EventID
    ev_raw = (
        row.get("Id")
        or row.get("EventID")
        or row.get("Event Id")
        or row.get("EventId")
        or ""
    )
    try:
        event_code = int(str(ev_raw).strip())
    except Exception:
        event_code = None

    # Description
    desc = (
        row.get("Message")
        or row.get("Description")
        or ""
    )
    if desc is None:
        desc = ""
    desc = str(desc)

    return ts_utc_str, event_code, desc


def extract_event_type(row: dict) -> Optional[str]:
    value = (
        row.get("ProviderName")
        or row.get("Source")
        or row.get("Provider")
        or ""
    )
    value = str(value).strip()
    return value or None


def lookup_windows_acquisition_id(conn, device_id: int, run_id: str, source_log: str, tool_tag: str) -> Optional[int]:
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT windows_acquisition_id
            FROM WINDOWS_ACQUISITIONS
            WHERE device_id = %s AND run_id = %s AND log_type = %s AND tool_name = %s
            """,
            (device_id, run_id, source_log, tool_tag),
        )
        row = cur.fetchone()
        if row:
            return int(row[0])
        return None
    finally:
        cur.close()


def eventi_raw_available(conn) -> bool:
    cur = conn.cursor()
    try:
        cur.execute("SHOW TABLES LIKE 'EVENTI_RAW'")
        return cur.fetchone() is not None
    finally:
        cur.close()


def open_mysql_connection(args):
    kwargs = {
        "host": args.mysql_host,
        "port": args.mysql_port,
        "user": args.mysql_user,
        "database": args.mysql_database,
        "use_pure": True,
    }
    if args.mysql_password:
        kwargs["password"] = args.mysql_password
    try:
        conn = mysql.connector.connect(**kwargs)
    except MySQLError as e:
        raise SystemExit(f"MySQL connection failed: {e}")
    conn.autocommit = False
    return conn


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "M02 Windows logs probe: move events from LOGS/<source_log> into EVENTI_PC "
            "(timestamp + EventID + Message) using MySQL."
        )
    )
    ap.add_argument(
        "--dataset-root",
        required=True,
        help="Root DataSetGlobal for windows_logs (ex. C:\\SAFENET\\DataSetGlobal\\windows_logs).",
    )
    ap.add_argument(
        "--mysql-host",
        default="127.0.0.1",
        help="MySQL host (default 127.0.0.1).",
    )
    ap.add_argument(
        "--mysql-port",
        type=int,
        default=3306,
        help="MySQL port (default 3306).",
    )
    ap.add_argument(
        "--mysql-user",
        default="safenet_ingest",
        help="MySQL user (default safenet_ingest).",
    )
    ap.add_argument(
        "--mysql-password",
        help="MySQL password (optional).",
    )
    ap.add_argument(
        "--mysql-database",
        default="forensic",
        help="MySQL database name (default forensic).",
    )
    ap.add_argument(
        "--source-log",
        required=True,
        help="Source log name (Security, System, Application, PowerShell, AMSI...).",
    )
    ap.add_argument(
        "--device-label",
        help="Filter by device_label (as in DEVICE_MASTER.device_label).",
    )
    ap.add_argument(
        "--event-code",
        type=int,
        help="Filter by EventID (4624, 4625, 7045, ...).",
    )
    ap.add_argument(
        "--limit-per-run",
        type=int,
        default=100,
        help="Max events to insert per CSV (default 100).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="If set, does not insert into DB, prints what it would do.",
    )

    args = ap.parse_args()

    raw_milestone = "M02"
    dataset_root = Path(args.dataset_root)
    if not dataset_root.is_dir():
        raise SystemExit(f"dataset-root not valid: {dataset_root}")

    conn = open_mysql_connection(args)

    device_map = load_device_map(conn)
    if not device_map:
        print("[WARN] No devices in DEVICE_MASTER, will create as needed.")

    raw_enabled = eventi_raw_available(conn)
    if not raw_enabled:
        print("[WARN] EVENTI_RAW table not found. Raw mirror will be skipped.")

    print(f"[INFO] Device map: {device_map}")
    print(f"[INFO] Source log: {args.source_log}")
    if args.event_code is not None:
        print(f"[INFO] Filter event_code = {args.event_code}")
    if args.device_label:
        print(f"[INFO] Filter device_label = {args.device_label}")

    total_seen = 0
    total_inserted = 0
    windows_acq_lookup_failed = False

    for device_label, tool_tag, run_id, csv_file in iter_main_log_csv_files(
        dataset_root=dataset_root,
        source_log=args.source_log,
        device_label_filter=args.device_label,
    ):
        print(f"\n[FILE] {csv_file}")
        print(f"       device_logical = {device_label}")
        print(f"       tool_tag       = {tool_tag}")
        print(f"       run_id         = {run_id}")

        device_id = device_map.get(device_label)
        if device_id is None:
            device_id = ensure_device_id(conn, device_label)
            if device_id is None:
                print(f"  [WARN] Failed to create device for '{device_label}', skip.")
                continue
            device_map[device_label] = device_id
            print(f"  [INFO] Created device '{device_label}' -> device_id={device_id}")

        windows_acquisition_id = None
        if not windows_acq_lookup_failed:
            try:
                windows_acquisition_id = lookup_windows_acquisition_id(
                    conn=conn,
                    device_id=device_id,
                    run_id=run_id,
                    source_log=args.source_log,
                    tool_tag=tool_tag,
                )
            except MySQLError as e:
                windows_acq_lookup_failed = True
                print(f"  [WARN] WINDOWS_ACQUISITIONS lookup failed: {e}")

        rows = event_rows_from_file(csv_file)
        if not rows:
            print("  [INFO] No events (or file empty/non supported), skip.")
            continue

        inserted_for_file = 0
        cur = conn.cursor()

        for row in rows:
            ts_utc_str, event_code, desc = extract_basic_fields(row)
            total_seen += 1

            # filter EventID
            if args.event_code is not None and event_code != args.event_code:
                continue

            # need a timestamp
            if ts_utc_str is None:
                continue

            if inserted_for_file >= args.limit_per_run:
                break

            if args.dry_run:
                print(
                    f"  [DRY] Would insert EVENTI_PC: ts={ts_utc_str}, "
                    f"device_id={device_id}, source_log={args.source_log}, "
                    f"event_code={event_code}"
                )
            else:
                try:
                    cur.execute(
                        """
                        INSERT INTO EVENTI_PC (
                            timestamp_utc,
                            device_id,
                            source_log,
                            event_code,
                            account_id,
                            ip_remoto,
                            logon_type,
                            process_name,
                            command_line,
                            description,
                            sospetto_flag,
                            motivazione_sospetto
                        ) VALUES (%s, %s, %s, %s, NULL, NULL, NULL, NULL, NULL, %s, 0, NULL)
                        """,
                        (
                            ts_utc_str,
                            device_id,
                            args.source_log,
                            event_code,
                            desc,
                        ),
                    )
                    if raw_enabled:
                        raw_payload = json.dumps(row, ensure_ascii=False)
                        cur.execute(
                            """
                            INSERT INTO EVENTI_RAW (
                                milestone_code,
                                device_id,
                                account_id,
                                windows_acquisition_id,
                                source_log,
                                event_time_utc,
                                event_code,
                                event_type,
                                raw_format,
                                raw_payload,
                                source_path
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                raw_milestone,
                                device_id,
                                None,
                                windows_acquisition_id,
                                args.source_log,
                                ts_utc_str,
                                event_code,
                                extract_event_type(row),
                                "json",
                                raw_payload,
                                str(csv_file),
                            ),
                        )
                except MySQLError as e:
                    print(f"  [WARN] Insert failed: {e}")
                    continue

            inserted_for_file += 1
            total_inserted += 1

        if not args.dry_run:
            conn.commit()

        cur.close()
        print(f"  [INFO] Events inserted for this file: {inserted_for_file}")

    conn.close()

    print("\n[SUMMARY]")
    print(f"  Events seen (all files): {total_seen}")
    print(f"  Events inserted (after filters/limits): {total_inserted}")
    if args.dry_run:
        print("  DRY-RUN mode: no changes made to DB.")


if __name__ == "__main__":
    main()
