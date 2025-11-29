#!/usr/bin/env python
"""
m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py

Scopo:
  - Prendere i log normalizzati in SAFENET (android_adb_logs)
  - Leggere i file CORE_SYSTEM/logcat_main_*.txt
  - Estrarre alcune righe come "eventi di prova" e inserirle in EVENTI_ANDROID
  - Permettere di verificare facilmente che lo stesso evento esista sia nel file logcat che nel DB

ATTENZIONE:
  - Questo è uno script di *verifica pipeline*, non il parser definitivo.
  - Inserisce righe 1:1 con le linee di logcat (filtrate), con il testo completo nel campo `title`.
  - Il timestamp viene ricostruito usando il `run_id` (YYYYMMDD_HHMMSS) + timestamp logcat (MM-DD HH:MM:SS.mmm).

Uso tipico (PowerShell):

  python m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py `
      --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs" `
      --db "C:\SAFENET\DB\forensic.db" `
      --grep "ActivityManager" `
      --limit-per-run 50

Così per ogni run prenderà al massimo 50 righe di logcat_main che contengono la stringa "ActivityManager".
"""

import argparse
import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_run_id(run_id: str) -> Optional[Tuple[str, str, str, str, str, str]]:
    """
    run_id: 'YYYYMMDD_HHMMSS'
    ritorna (YYYY, MM, DD, hh, mm, ss) oppure None se invalido.
    """
    m = re.match(r"^(20\d{2})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$", run_id)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)


def extract_run_id_from_path(run_base: Path) -> Optional[str]:
    """
    run_base = <dataset_root>/<device_logical>/<script_tag>/<run_id>
    prendiamo il nome della cartella finale come run_id.
    """
    return run_base.name


def parse_logcat_time_line(line: str, year: str, default_date: str) -> Tuple[str, str]:
    """
    Prova a estrarre timestamp logcat in formato 'MM-DD HH:MM:SS.mmm' all'inizio della riga.

    Esempio logcat -v time:
      '11-29 03:19:34.123  1234  5678 I Tag: messaggio...'

    Ritorna (timestamp_sqlite, resto_linea)
      timestamp_sqlite: 'YYYY-MM-DD HH:MM:SS'
      resto_linea: linea originale senza la parte di timestamp (per il campo title)
    Se non matcha, usa default_date + ' 00:00:00' e ritorna la linea intera come resto.
    """
    m = re.match(r"^(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(.*)$", line.rstrip("\n"))
    if not m:
        # fallback: data di run, ora 00:00:00, testo completo
        return f"{default_date} 00:00:00", line.rstrip("\n")

    mm, dd, hh, mi, ss, rest = m.groups()
    ts_sql = f"{year}-{mm}-{dd} {hh}:{mi}:{ss}"
    return ts_sql, rest


def load_device_map(conn) -> Dict[str, int]:
    """
    Crea una mappa device_logical -> device_id
    Assumiamo che device_logical corrisponda a DEVICE_MASTER.device_label
    (es. ANDR_IO_S24, ANDR_ALE_S20, ANDR_ALE_A6).
    """
    cur = conn.cursor()
    cur.execute("SELECT device_id, device_label FROM DEVICE_MASTER")
    mapping: Dict[str, int] = {}
    for device_id, label in cur.fetchall():
        if label:
            mapping[str(label)] = int(device_id)
    return mapping


def find_runs(dataset_root: Path) -> List[Path]:
    """
    Trova tutte le cartelle run_base:
      <dataset_root>/<device_logical>/android_log_dump_0.2/<run_id>/
    (non hardcodiamo script_tag, ma assumiamo un solo livello di script-name/version sotto device_logical)
    """
    runs: List[Path] = []
    for device_dir in sorted(dataset_root.iterdir()):
        if not device_dir.is_dir():
            continue
        for script_dir in sorted(device_dir.iterdir()):
            if not script_dir.is_dir():
                continue
            for run_dir in sorted(script_dir.iterdir()):
                if run_dir.is_dir():
                    runs.append(run_dir)
    return runs


def insert_event(
    conn,
    timestamp_utc: str,
    device_id: int,
    title: str,
    source_file: str,
    product: str = "Android_ADB",
    app: str = "logcat_main",
    ip_remoto: str = "",
    extra_details: str = "",
):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO EVENTI_ANDROID (
            timestamp_utc,
            device_id,
            account_id,
            product,
            app,
            title,
            title_url,
            source_file,
            ip_remoto,
            extra_details,
            sospetto_flag,
            motivazione_sospetto
        ) VALUES (?, ?, NULL, ?, ?, ?, NULL, ?, ?, ?, 0, NULL)
        """,
        (timestamp_utc, device_id, product, app, title, source_file, ip_remoto, extra_details),
    )


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Carica alcuni eventi di prova da logcat_main (SAFENET) in EVENTI_ANDROID "
            "per verificare la correttezza della pipeline."
        )
    )
    ap.add_argument(
        "--dataset-root",
        "-d",
        required=True,
        help="Root DataSetGlobal per android_adb_logs (es. C:\\SAFENET\\DataSetGlobal\\android_adb_logs)",
    )
    ap.add_argument(
        "--db",
        required=True,
        help="Percorso al DB SQLite forense (es. C:\\SAFENET\\DB\\forensic.db)",
    )
    ap.add_argument(
        "--grep",
        help="Stringa da cercare nelle righe di logcat_main (case sensitive). Se omessa, prende le prime N righe.",
        default="",
    )
    ap.add_argument(
        "--limit-per-run",
        type=int,
        default=50,
        help="Numero massimo di eventi da inserire per ogni run (default: 50).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostra cosa farebbe senza inserire nel DB.",
    )
    args = ap.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    if not dataset_root.exists() or not dataset_root.is_dir():
        raise SystemExit(f"dataset_root non valida: {dataset_root}")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    device_map = load_device_map(conn)
    if not device_map:
        print("[WARN] Nessun device in DEVICE_MASTER. Controlla di aver inserito ANDR_IO_S24 / ANDR_ALE_S20 / ANDR_ALE_A6 ecc.")
    else:
        print("[INFO] Device map:", device_map)

    runs = find_runs(dataset_root)
    if not runs:
        raise SystemExit(f"Nessuna run trovata sotto {dataset_root}")

    print(f"[INFO] Trovate {len(runs)} run in SAFENET.")

    total_inserted = 0

    for run_base in runs:
        # run_base = <dataset_root>/<device_logical>/<script_tag>/<run_id>
        device_logical = run_base.parent.parent.name
        script_tag = run_base.parent.name
        run_id = extract_run_id_from_path(run_base)
        print(f"\n[RUN] {run_base}")
        print(f"      device_logical = {device_logical}")
        print(f"      script_tag     = {script_tag}")
        print(f"      run_id         = {run_id}")

        device_id = device_map.get(device_logical)
        if device_id is None:
            print(f"  [WARN] Nessun device_id trovato per device_logical='{device_logical}', salto questa run.")
            continue

        parsed_run = parse_run_id(run_id)
        if not parsed_run:
            print(f"  [WARN] run_id '{run_id}' non riconosciuto, salto questa run.")
            continue
        year, mm, dd, hh, mi, ss = parsed_run
        default_date = f"{year}-{mm}-{dd}"

        core_system_dir = run_base / "CORE_SYSTEM"
        if not core_system_dir.exists():
            print(f"  [WARN] CORE_SYSTEM mancante: {core_system_dir}")
            continue

        logcat_files = sorted(core_system_dir.glob("logcat_main_*.txt"))
        if not logcat_files:
            print(f"  [WARN] Nessun logcat_main_*.txt in {core_system_dir}")
            continue

        per_run_inserted = 0

        for log_path in logcat_files:
            print(f"  [INFO] Analizzo {log_path.name}")
            try:
                with log_path.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if args.grep and args.grep not in line:
                            continue
                        ts_sql, rest = parse_logcat_time_line(line, year, default_date)
                        title = rest
                        source_file = str(log_path)

                        print(f"    + EVENTO: ts={ts_sql} device_id={device_id}")
                        print(f"      title: {title[:120]}")

                        if not args.dry_run:
                            insert_event(
                                conn,
                                timestamp_utc=ts_sql,
                                device_id=device_id,
                                title=title,
                                source_file=source_file,
                                product="Android_ADB",
                                app="logcat_main",
                            )
                        per_run_inserted += 1
                        total_inserted += 1

                        if per_run_inserted >= args.limit_per_run:
                            print(f"    [INFO] Raggiunto limite per run ({args.limit_per_run}), passo alla prossima run.")
                            break
            except OSError as e:
                print(f"  [WARN] Errore leggendo {log_path}: {e}")

            if per_run_inserted >= args.limit_per_run:
                break

        print(f"  [INFO] Eventi inseriti per questa run: {per_run_inserted}")

    if not args.dry_run:
        conn.commit()
    conn.close()

    print("\n[DONE] Probe completato.")
    if args.dry_run:
        print(f"  Nessun inserimento effettuato (dry-run attivo). Eventi che SAREBBERO stati inseriti: {total_inserted}")
    else:
        print(f"  Eventi inseriti in EVENTI_ANDROID: {total_inserted}")


if __name__ == "__main__":
    main()
