#!/usr/bin/env python
# m02_windows_logs_03_probe_load_to_EVENTI_PC.py
#
# Probe Windows logs normalizzati in SAFENET e push in EVENTI_PC.
#
# v4:
#   - lavora su:
#       C:\SAFENET\DataSetGlobal\windows_logs\<device_label>\<tool_tag>\<run_id>\LOGS\<source_log>\
#   - prende SOLO il CSV principale:
#       <source_log>.csv      (es. Security.csv)
#       o <source_log>_events.csv
#   - legge il CSV con encoding "utf-8-sig" (fix BOM)
#   - usa parse_event_time() di m02_windows_logs_01_log_dump.py
#     ma se il parse fallisce, tiene il timestamp grezzo come stringa
#   - inserisce in EVENTI_PC (timestamp_utc = stringa, device_id, source_log, event_code, description)
#
# Uso tipico:
#
#   python.exe m02_windows_logs_03_probe_load_to_EVENTI_PC.py ^
#       --dataset-root "C:\SAFENET\DataSetGlobal\windows_logs" ^
#       --db "C:\SAFENET\DB\forensic.db" ^
#       --source-log "Security" ^
#       --device-label "PICCIRILLA_AleNew" ^
#       --event-code 4624 ^
#       --limit-per-run 20 ^
#       --dry-run
#

import argparse
import csv
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Import dalle utility del modulo M02_01 (il tuo log dumper Windows)
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

def load_device_map(conn: sqlite3.Connection) -> Dict[str, int]:
    """
    device_label -> device_id da DEVICE_MASTER.
    """
    cur = conn.cursor()
    cur.execute("SELECT device_id, device_label FROM DEVICE_MASTER")
    mapping: Dict[str, int] = {}
    for device_id, label in cur.fetchall():
        if label:
            mapping[str(label)] = int(device_id)
    return mapping


# ---------------------------------------------------------------------------
# Iterazione sulle cartelle SAFENET
# ---------------------------------------------------------------------------

def iter_main_log_csv_files(
    dataset_root: Path,
    source_log: str,
    device_label_filter: Optional[str] = None,
) -> Iterable[Tuple[str, str, str, Path]]:
    """
    Scorre:

        <dataset_root>/<device_label>/<tool_tag>/<run_id>/LOGS/<source_log>/

    e restituisce tuple:

        (device_label, tool_tag, run_id, csv_path)

    prendendo SOLO:
        <source_log>.csv
        oppure <source_log>_events.csv
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
# Lettura CSV (fix BOM) + estrazione campi
# ---------------------------------------------------------------------------

def event_rows_from_file(csv_path: Path) -> List[dict]:
    """
    Legge un CSV di eventi (UTF-8 con BOM) e restituisce una lista di dict.
    Non fa filtri temporali qui; li gestiamo eventualmente a livello DB in seguito.
    """
    if csv_path.suffix.lower() != ".csv":
        print(f"  [INFO] Salto file non-CSV in questo probe: {csv_path}")
        return []

    events: List[dict] = []
    # 'utf-8-sig' mangia il BOM iniziale → header "TimeCreated" diventa corretto
    with csv_path.open("r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)
    return events


def extract_basic_fields(row: dict) -> Tuple[Optional[str], Optional[int], str]:
    """
    Estrae:
      - timestamp_utc_str (o stringa grezza se il parse fallisce)
      - event_code (int, se possibile)
      - description (Message/Description)
    """
    # Timestamp: varianti possibili
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
            # Parse fallito → usiamo la stringa grezza (locale)
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

    # Descrizione
    desc = (
        row.get("Message")
        or row.get("Description")
        or ""
    )
    if desc is None:
        desc = ""
    desc = str(desc)

    return ts_utc_str, event_code, desc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "M02 Windows logs – probe: porta eventi da LOGS/<source_log> in EVENTI_PC "
            "(timestamp grezzo + EventID + Message)."
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
        help="Percorso DB SQLite forense (es. C:\\SAFENET\\DB\\forensic.db).",
    )
    ap.add_argument(
        "--source-log",
        required=True,
        help="Nome log sorgente (Security, System, Application, PowerShell, AMSI...).",
    )
    ap.add_argument(
        "--device-label",
        help="Filtra su uno specifico device_label (come in DEVICE_MASTER.device_label).",
    )
    ap.add_argument(
        "--event-code",
        type=int,
        help="Filtra su un EventID specifico (4624, 4625, 7045, ...).",
    )
    ap.add_argument(
        "--limit-per-run",
        type=int,
        default=100,
        help="Limite max eventi da inserire per ogni CSV (default 100).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Se impostato, NON inserisce nel DB, ma stampa cosa farebbe.",
    )

    args = ap.parse_args()

    dataset_root = Path(args.dataset_root)
    if not dataset_root.is_dir():
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

    total_seen = 0
    total_inserted = 0

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
            print(f"  [WARN] Nessun device_id per '{device_label}', salto.")
            continue

        rows = event_rows_from_file(csv_file)
        if not rows:
            print("  [INFO] Nessun evento (o file vuoto/non supportato), salto.")
            continue

        inserted_for_file = 0
        cur = conn.cursor()

        for row in rows:
            ts_utc_str, event_code, desc = extract_basic_fields(row)
            total_seen += 1

            # filtro per EventID
            if args.event_code is not None and event_code != args.event_code:
                continue

            # serve almeno qualcosa nel timestamp
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
