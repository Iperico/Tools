#!/usr/bin/env python
# m02_windows_logs_03_probe_load_to_EVENTI_PC.py
#
# Versione ripulita v2:
#   - usa generate_windows_report.py per read_csv_events
#   - considera solo i file principali del log (Security.csv / Security_events.csv)
#   - IGNORA gli .evtx (già esportati in CSV dai tuoi tool)
#   - NON fa parsing datetime: salva il timestamp grezzo come stringa in timestamp_utc
#
# Pipeline:
#   C:\SAFENET\DataSetGlobal\windows_logs\<device_logical>\<tool_tag>\<run_id>\
#       LOGS\<source_log>\Security.csv
#     -> read_csv_events()
#     -> insert in EVENTI_PC
#
# Uso tipico:
#
#   python .\m02_windows_logs_03_probe_load_to_EVENTI_PC.py ^
#       --dataset-root "C:\SAFENET\DataSetGlobal\windows_logs" ^
#       --db "C:\SAFENET\DB\forensic.db" ^
#       --source-log "Security" ^
#       --device-label "PICCIRILLA_AleNew" ^
#       --limit-per-run 20 ^
#       --dry-run
#

import argparse
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# Usiamo le funzioni del tuo generate_windows_report.py
try:
    from m02_windows_logs_01_log_dump import (
        parse_event_time,   # non lo usiamo ora, ma lo teniamo importato se ti serve dopo
        read_csv_events,
    )
except Exception as e:
    raise SystemExit(
        "Impossibile importare parse_event_time/read_csv_events "
        "da generate_windows_report.py.\n"
        "Metti generate_windows_report.py nella stessa cartella di questo script.\n"
        f"Dettagli: {e}"
    )


def load_device_map(conn: sqlite3.Connection) -> Dict[str, int]:
    """
    Crea una mappa device_label -> device_id partendo da DEVICE_MASTER.
    """
    cur = conn.cursor()
    cur.execute("SELECT device_id, device_label FROM DEVICE_MASTER")
    mapping: Dict[str, int] = {}
    for device_id, label in cur.fetchall():
        if label:
            mapping[str(label)] = int(device_id)
    return mapping


def iter_main_log_files(
    dataset_root: Path,
    device_label_filter: Optional[str],
    source_log: str,
) -> Iterable[tuple]:
    """
    Scorre DataSetGlobal/windows_logs e cerca SOLO i file principali del log:
      LOGS/<source_log>/Security.csv
      LOGS/<source_log>/Security_events.csv

    Ritorna tuple:
        (device_logical, tool_tag, run_id, log_file_path)
    """
    source_log_norm = source_log.strip()

    MAIN_BASENAMES = {
        source_log_norm,               # ad es. "Security"
        f"{source_log_norm}_events",   # "Security_events"
    }

    for dev_dir in sorted(dataset_root.iterdir()):
        if not dev_dir.is_dir():
            continue
        device_logical = dev_dir.name
        if device_label_filter and device_logical != device_label_filter:
            continue

        for tool_dir in sorted(dev_dir.iterdir()):
            if not tool_dir.is_dir():
                continue
            tool_tag = tool_dir.name

            for run_dir in sorted(tool_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                run_id = run_dir.name
                logs_root = run_dir / "LOGS" / source_log_norm
                if not logs_root.exists() or not logs_root.is_dir():
                    continue

                for log_file in sorted(logs_root.iterdir()):
                    if not log_file.is_file():
                        continue

                    stem = log_file.stem
                    if stem not in MAIN_BASENAMES:
                        # ignoriamo tutti i Microsoft-Windows-xxx ecc.
                        continue

                    yield device_logical, tool_tag, run_id, log_file


def event_rows_from_file(log_file: Path) -> List[dict]:
    """
    Ritorna una lista di dict per gli eventi contenuti nel file.

    v2: usiamo SOLO i CSV già generati.
    Gli EVTX vengono ignorati.
    """
    suffix = log_file.suffix.lower()

    if suffix == ".csv":
        # read_csv_events expects a Path object, not a string.
        rows = read_csv_events(log_file, start=None, end=None)
        return rows

    print(f"  [INFO] Salto file non-CSV in questo probe: {log_file}")
    return []


def extract_basic_fields(row: dict) -> tuple:
    """
    Estrae i campi base per EVENTI_PC da una riga CSV generica.

    v2:
    - NON tenta di convertire a datetime/UTC.
    - Usa il timestamp grezzo dal CSV come stringa.
    """
    # Timestamp grezzo dalla riga
    ts_value = (
        row.get("TimeCreated")
        or row.get("timeCreated")
        or row.get("Date")
        or row.get("Timestamp")
        or ""
    )
    ts_utc_str = str(ts_value).strip().strip('"') if ts_value else None

    # EventID / codice evento
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

    # Messaggio / descrizione
    desc = (
        row.get("Message")
        or row.get("Description")
        or ""
    )
    desc = "" if desc is None else str(desc)

    return ts_utc_str, event_code, desc


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "M02 Windows logs – probe: prende il log principale (es. Security) "
            "da LOGS/<source_log> e inserisce eventi in EVENTI_PC."
        )
    )
    ap.add_argument(
        "--dataset-root",
        required=True,
        help="Root DataSetGlobal per windows_logs (es. C:\\SAFENET\\DataSetGlobal\\windows_logs).",
    )
    ap.add_argument(
        "--db",
        required=True,
        help="Percorso al DB SQLite forense (es. C:\\SAFENET\\DB\\forensic.db).",
    )
    ap.add_argument(
        "--source-log",
        default="Security",
        help="Nome del log sorgente (Security, System, Application, PowerShell, AMSI). Default: Security.",
    )
    ap.add_argument(
        "--event-code",
        type=int,
        help="Filtra per un singolo EventID (es. 4624, 4625). Se omesso, inserisce tutti gli eventi.",
    )
    ap.add_argument(
        "--device-label",
        help="Limita ai log di un solo device_logical (es. PICCIRILLA_AleNew).",
    )
    ap.add_argument(
        "--limit-per-run",
        type=int,
        default=100,
        help="Massimo numero di eventi da inserire per ogni file/log (default: 100).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Non inserisce nel DB, mostra solo cosa farebbe.",
    )

    args = ap.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    if not dataset_root.exists() or not dataset_root.is_dir():
        raise SystemExit(f"dataset-root non valida: {dataset_root}")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    device_map = load_device_map(conn)
    if not device_map:
        print("[WARN] Nessun device in DEVICE_MASTER, impossibile proseguire.")
        conn.close()
        return

    print(f"[INFO] Device map: {device_map}")
    print(f"[INFO] Source log: {args.source_log}")
    if args.event_code is not None:
        print(f"[INFO] Filter event_code = {args.event_code}")
    if args.device_label:
        print(f"[INFO] Filter device_label = {args.device_label}")

    total_inserted = 0
    total_seen = 0

    for device_logical, tool_tag, run_id, log_file in iter_main_log_files(
        dataset_root=dataset_root,
        device_label_filter=args.device_label,
        source_log=args.source_log,
    ):
        print(f"\n[FILE] {log_file}")
        print(f"       device_logical = {device_logical}")
        print(f"       tool_tag       = {tool_tag}")
        print(f"       run_id         = {run_id}")

        device_id = device_map.get(device_logical)
        if device_id is None:
            print(f"  [WARN] Nessun device_id in DEVICE_MASTER per '{device_logical}', salto questo file.")
            continue

        rows = event_rows_from_file(log_file)
        if not rows:
            print("  [INFO] Nessun evento dopo il parsing, salto.")
            continue

        inserted_for_file = 0
        cur = conn.cursor()

        for row in rows:
            ts_utc_str, event_code, desc = extract_basic_fields(row)
            total_seen += 1

            if args.event_code is not None and event_code != args.event_code:
                continue

            if ts_utc_str is None:
                continue

            if inserted_for_file >= args.limit_per_run:
                break

            if args.dry_run:
                print(
                    f"  [DRY] Inserirei EVENTI_PC: ts={ts_utc_str}, "
                    f"device_id={device_id}, source_log={args.source_log}, "
                    f"event_code={event_code}"
                )
            else:
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
                    ) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, 0, NULL)
                    """,
                    (
                        ts_utc_str,
                        device_id,
                        args.source_log,
                        event_code,
                        desc,
                    ),
                )

            inserted_for_file += 1
            total_inserted += 1

        if not args.dry_run:
            conn.commit()

        print(f"  [INFO] Eventi inseriti per questo file: {inserted_for_file}")

    conn.close()

    print("\n[SUMMARY]")
    print(f"  Eventi visti (tutti i file): {total_seen}")
    print(f"  Eventi inseriti (dopo filtri/limiti): {total_inserted}")
    if args.dry_run:
        print("  Modalità DRY-RUN: nessuna modifica reale al DB.")


if __name__ == "__main__":
    main()
