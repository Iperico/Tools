#!/usr/bin/env python

# m02_windows_logs_02_extract_to_safenet.py
#
# Versione adattata alla struttura attuale dei tuoi log Windows.
#
# Scopo:
#   Prendere i log Windows (EVTX/CSV) già esportati nelle cartelle "Forensic_Logs"
#   e riorganizzarli nella struttura SAFENET DataSetGlobal:
#
#       <dataset_root>\windows_logs\<device_logical>\<tool_tag>\<run_id>\
#           META\
#           LOGS\
#               Security\
#               System\
#               Application\
#               PowerShell\
#               AMSI\
#           RAW_ALL\
#
# Struttura SORGENTE attesa (--windows-logs-root):
#
#   <root>\
#     PICCIRILLA_AleNew_20251123_233251\
#         EVTX\
#             Security.evtx
#             System.evtx
#             Application.evtx
#             PowerShell.evtx
#             AMSI.evtx
#         META\
#             ... (eventuali meta tuoi)
#         TRIAGE_20241111_to_now\
#             ... (csv o altro, opzionali)
#     SPARTACUS_20251124_101500\
#         EVTX\...
#         META\...
#         ...
#
# Dove:
#   - Il nome cartella di run segue il pattern:
#         <device_logical>_<run_id>
#     con run_id = YYYYMMDD_HHMMSS (es. 20251123_233251)
#
#   - <device_logical> deve combaciare con DEVICE_MASTER.device_label in DB
#     (es. 'PICCIRILLA_AleNew', 'SPARTACUS', 'VAGABONDO', 'AleOld', ...)
#
# Esempio uso (PowerShell):
#
#   python .\m02_windows_logs_02_extract_to_safenet.py `
#       --windows-logs-root "C:\Users\OMICRON\Desktop\Beb_Info_Fango\ForenInv\logY\Forensic_Logs" `
#       --dataset-root "C:\SAFENET\DataSetGlobal\windows_logs" `
#       --db "C:\SAFENET\DB\forensic.db" `
#       --tool-tag "wevtutil_export" `
#       --dry-run
#
# Opzioni:
#   --dry-run    -> non scrive su disco né DB, mostra solo cosa farebbe.
#
# NOTA:
#   Questo script NON fa parsing dei singoli eventi (quello sarà il ruolo del probe
#   m02_windows_logs_03_probe_load_to_EVENTI_PC.py). Qui ci limitiamo a:
#     sorgente -> SAFENET + meta + WINDOWS_ACQUISITIONS.

import argparse
import json
import re
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Tipi di log riconosciuti, mappati per prefisso nel nome file (case insensitive)
LOG_TYPE_PATTERNS: Dict[str, str] = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "powershell": "PowerShell",
    "am-si": "AMSI",           # es. "AMSI.evtx", "am-si.csv", etc.
    "amsi": "AMSI",
}


RUN_SUBDIRS = [
    "META",
    "LOGS",
    "RAW_ALL",
]


@dataclass
class RunInfo:
    device_logical: str
    run_id: str
    device_id: int
    tool_tag: str
    source_run_dir: Path
    target_run_base: Path


def parse_run_dir_name(run_dir_name: str) -> Optional[Tuple[str, str]]:
    """
    Interpreta il nome della cartella run come:
        <device_logical>_<run_id>
    dove run_id = YYYYMMDD_HHMMSS (14 cifre, con underscore in mezzo).
    Esempio: PICCIRILLA_AleNew_20251123_233251
             ^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^
               device_logical       run_id

    Ritorna (device_logical, run_id) oppure None se il formato non matcha.
    """
    m = re.match(r"^(?P<dev>.+)_(?P<run>\d{8}_\d{6})$", run_dir_name)
    if not m:
        return None
    return m.group("dev"), m.group("run")


def parse_run_id(run_id: str) -> Optional[datetime]:
    """
    run_id atteso: YYYYMMDD_HHMMSS
    Ritorna datetime o None se il formato non matcha.
    """
    m = re.match(r"^(20\d{2})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$", run_id)
    if not m:
        return None
    year, mm, dd, hh, mi, ss = map(int, m.groups())
    try:
        return datetime(year, mm, dd, hh, mi, ss)
    except ValueError:
        return None


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


def ensure_dirs(base: Path, dry_run: bool = False) -> None:
    """
    Crea la struttura base di una run windows_logs sotto dataset_root.
    """
    for sub in RUN_SUBDIRS:
        if sub == "LOGS":
            target = base / "LOGS"
            if not dry_run:
                target.mkdir(parents=True, exist_ok=True)
        else:
            target = base / sub
            if not dry_run:
                target.mkdir(parents=True, exist_ok=True)


def classify_log_type(filename: str) -> Optional[str]:
    """
    Cerca di indovinare il tipo di log (Security/System/…) dal nome del file.
    Usa preferenze su LOG_TYPE_PATTERNS.
    """
    name = filename.lower()
    for pattern, log_type in LOG_TYPE_PATTERNS.items():
        if pattern in name:
            return log_type
    return None


def iter_runs(windows_logs_root: Path) -> List[RunInfo]:
    """
    Trova tutti i run nella struttura:
      <root>/<device_logical>_<run_id>/EVTX/...

    Ritorna una lista di RunInfo *senza* device_id (verrà riempito dopo con la mappa DB).
    """
    runs: List[RunInfo] = []

    for run_dir in sorted(windows_logs_root.iterdir()):
        if not run_dir.is_dir():
            continue

        parsed = parse_run_dir_name(run_dir.name)
        if not parsed:
            print(f"[WARN] Cartella run non riconosciuta (nome non matcha pattern <device>_YYYYMMDD_HHMMSS): {run_dir.name}")
            continue

        device_logical, run_id = parsed
        runs.append(
            RunInfo(
                device_logical=device_logical,
                run_id=run_id,
                device_id=-1,  # placeholder, verrà risolto dopo
                tool_tag="",   # placeholder, verrà impostato nel main
                source_run_dir=run_dir,
                target_run_base=Path("."),  # placeholder, verrà impostato nel main
            )
        )

    return runs


def copy_and_classify_files(run_info: RunInfo, dry_run: bool = False) -> Dict[str, List[str]]:
    """
    Copia i file sorgenti in RAW_ALL e LOGS/<log_type>.

    Sorgente principale: <run_dir>/EVTX
    - Se esiste la cartella EVTX, consideriamo solo i file al suo interno.
    - Altrimenti, consideriamo i file direttamente dentro run_dir.

    Ritorna un dict log_type -> lista di path relativi (sotto LOGS/log_type).
    """
    log_files: Dict[str, List[str]] = {}
    base = run_info.target_run_base

    raw_all_dir = base / "RAW_ALL"
    logs_root_dir = base / "LOGS"

    if not dry_run:
        raw_all_dir.mkdir(parents=True, exist_ok=True)
        logs_root_dir.mkdir(parents=True, exist_ok=True)

    evtx_dir = run_info.source_run_dir / "EVTX"
    if evtx_dir.exists() and evtx_dir.is_dir():
        files_source = sorted(evtx_dir.iterdir())
    else:
        # fallback: tutti i file direttamente sotto run_dir
        files_source = sorted(p for p in run_info.source_run_dir.iterdir() if p.is_file())

    for src in files_source:
        if not src.is_file():
            continue

        filename = src.name

        # Copia in RAW_ALL
        dst_raw = raw_all_dir / filename
        if dry_run:
            print(f"  [DRY] Copierei: {src} -> {dst_raw}")
        else:
            shutil.copy2(src, dst_raw)

        # Classifica e copia in LOGS/<log_type> se riconosciuto
        log_type = classify_log_type(filename)
        if log_type:
            log_type_dir = logs_root_dir / log_type
            if not dry_run:
                log_type_dir.mkdir(parents=True, exist_ok=True)
            dst_log = log_type_dir / filename
            if dry_run:
                print(f"  [DRY] Copierei anche in LOGS/{log_type}: {src} -> {dst_log}")
            else:
                shutil.copy2(src, dst_log)

            rel_path = str(dst_log.relative_to(base))
            log_files.setdefault(log_type, []).append(rel_path)

    return log_files


def write_meta(run_info: RunInfo, log_files: Dict[str, List[str]], dry_run: bool = False) -> None:
    """
    Scrive META/acquisition_meta.json per la run.
    """
    base = run_info.target_run_base
    meta_dir = base / "META"
    if not dry_run:
        meta_dir.mkdir(parents=True, exist_ok=True)

    run_dt = parse_run_id(run_info.run_id)
    acquisition_time_utc = run_dt.isoformat(sep=" ") if run_dt else None

    # Costruisci struttura meta
    meta = {
        "script_name": "m02_windows_logs_02_extract_to_safenet.py",
        "script_version": "0.2",
        "device_logical": run_info.device_logical,
        "device_id": run_info.device_id,
        "run_id": run_info.run_id,
        "tool_tag": run_info.tool_tag,
        "source_run_dir": str(run_info.source_run_dir),
        "target_run_base": str(run_info.target_run_base),
        "acquisition_time_utc": acquisition_time_utc,
        "log_files": log_files,              # log_type -> [relative paths]
        "total_log_files": sum(len(v) for v in log_files.values()),
    }

    meta_path = meta_dir / "acquisition_meta.json"
    if dry_run:
        print(f"  [DRY] Scriverei meta in {meta_path}")
        preview = json.dumps(meta, indent=2, ensure_ascii=False)
        print(f"        meta preview:\n{preview[:400]}...\n")
    else:
        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)


def upsert_windows_acquisitions(
    conn: sqlite3.Connection,
    run_info: RunInfo,
    log_files: Dict[str, List[str]],
    dry_run: bool = False,
) -> None:
    """
    Inserisce (o aggiorna) righe in WINDOWS_ACQUISITIONS per ogni log_type presente.
    Usa la chiave unica (device_id, run_id, log_type, tool_name).
    """
    run_dt = parse_run_id(run_info.run_id)
    acquisition_time_utc = run_dt.isoformat(sep=" ") if run_dt else None

    cur = conn.cursor()

    for log_type, files in log_files.items():
        source_path = str(run_info.source_run_dir)
        target_run_base = str(run_info.target_run_base)
        tool_name = run_info.tool_tag

        notes = f"{len(files)} file per log_type {log_type}"

        if dry_run:
            print(
                f"  [DRY][DB] Inserirei/aggiornerei WINDOWS_ACQUISITIONS: "
                f"device_id={run_info.device_id}, run_id={run_info.run_id}, "
                f"log_type={log_type}, tool_name={tool_name}"
            )
            continue

        cur.execute(
            """
            INSERT INTO WINDOWS_ACQUISITIONS (
                device_id, run_id, log_type, tool_name,
                tool_version, source_path, target_run_base,
                acquisition_time_utc, validation_status, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, run_id, log_type, tool_name) DO UPDATE SET
                source_path = excluded.source_path,
                target_run_base = excluded.target_run_base,
                acquisition_time_utc = excluded.acquisition_time_utc,
                validation_status = excluded.validation_status,
                notes = excluded.notes
            """,
            (
                run_info.device_id,
                run_info.run_id,
                log_type,
                tool_name,
                None,  # tool_version (per ora)
                source_path,
                target_run_base,
                acquisition_time_utc,
                "PENDING",
                notes,
            ),
        )

    if not dry_run:
        conn.commit()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "M02 Windows logs – estrazione automatica in SAFENET "
            "DataSetGlobal/windows_logs + update WINDOWS_ACQUISITIONS "
            "(struttura sorgente: Forensic_Logs/<device>_YYYYMMDD_HHMMSS/EVTX/...)."
        )
    )
    ap.add_argument(
        "--windows-logs-root",
        required=True,
        help="Root dei log Windows esportati (es. C:\\Users\\...\\Forensic_Logs).",
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
        "--tool-tag",
        default="wevtutil_export",
        help="Tag per identificare il metodo di export (default: wevtutil_export).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra cosa farebbe senza copiare file né scrivere sul DB.",
    )

    args = ap.parse_args()

    windows_logs_root = Path(args.windows_logs_root).resolve()
    dataset_root = Path(args.dataset_root).resolve()

    if not windows_logs_root.exists() or not windows_logs_root.is_dir():
        raise SystemExit(f"windows-logs-root non valida: {windows_logs_root}")

    if not dataset_root.exists():
        if args.dry_run:
            print(f"[DRY] Creerei dataset_root: {dataset_root}")
        else:
            dataset_root.mkdir(parents=True, exist_ok=True)

    # Connessione al DB per mappa device e WINDOWS_ACQUISITIONS
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    device_map = load_device_map(conn)
    if not device_map:
        print("[WARN] Nessun device in DEVICE_MASTER. Controlla di aver inserito SPARTACUS, VAGABONDO, PICCIRILLA_AleNew, ecc.")
    else:
        print(f"[INFO] Device map: {device_map}")

    # Trova tutte le run partendo dai nomi cartella (device_logical_runId)
    runs = iter_runs(windows_logs_root)
    if not runs:
        print(f"[WARN] Nessuna run riconosciuta sotto {windows_logs_root}")
        conn.close()
        return

    print(f"[INFO] Trovate {len(runs)} run in {windows_logs_root}")

    for r in runs:
        print(f"\n[RUN] {r.source_run_dir}")
        print(f"      device_logical = {r.device_logical}")
        print(f"      run_id         = {r.run_id}")
        print(f"      tool_tag       = {args.tool_tag}")

        # Risolvo device_id
        device_id = device_map.get(r.device_logical)
        if device_id is None:
            print(f"  [WARN] Nessun device_id in DEVICE_MASTER per '{r.device_logical}', salto questa run.")
            continue

        # Costruisco target_run_base
        target_run_base = dataset_root / r.device_logical / args.tool_tag / r.run_id

        run_info = RunInfo(
            device_logical=r.device_logical,
            run_id=r.run_id,
            device_id=device_id,
            tool_tag=args.tool_tag,
            source_run_dir=r.source_run_dir,
            target_run_base=target_run_base,
        )

        print(f"      target_run_base = {run_info.target_run_base}")

        # Crea struttura base
        ensure_dirs(run_info.target_run_base, dry_run=args.dry_run)

        # Copia e classifica file
        log_files = copy_and_classify_files(run_info, dry_run=args.dry_run)

        # Scrivi meta
        write_meta(run_info, log_files, dry_run=args.dry_run)

        # Scrivi / aggiorna WINDOWS_ACQUISITIONS
        upsert_windows_acquisitions(conn, run_info, log_files, dry_run=args.dry_run)

    conn.close()
    print("\n[DONE] Estrazione Windows logs completata (o simulata se dry-run).")


if __name__ == "__main__":
    main()


#
# python .\m02_windows_logs_01_log_dump.py --log-dir "C:\SAFENET\DataSetGlobal\windows_logs\PICCIRILLA_AleNew\wevtutil_export\20251123_233251\LOGS\Security"  --from-date 2025-11-01   --to-date 2025-12-01    --max-files 10  --report-dir "C:\SAFENET\DataSetGlobal\windows_logs\PICCIRILLA_AleNew\wevtutil_export\20251123_233251\LOGS\Security"
