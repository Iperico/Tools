#!/usr/bin/env python
"""
m01_android_adb_04_validate_coherence.py

Validation di coerenza tra:
  - righe in EVENTI_ANDROID (forensics.db)
  - file sorgenti in SAFENET (android_adb_logs)

Per ogni record selezionato da EVENTI_ANDROID controlla:
  1. Che il file `source_file` esista.
  2. Che il path di `source_file` sia sotto `--dataset-root`.
  3. Che il device_logical ricavato dal path combaci con DEVICE_MASTER.device_label
     associato a EVENTI_ANDROID.device_id.
  4. Che il run_id (YYYYMMDD_HHMMSS) ricavato dal path abbia stessa data (YYYY-MM-DD)
     del campo timestamp_utc.
  5. (Opzionale ma attivo) Che la stringa `title` sia effettivamente presente nel file
     (anche solo come substring di una riga).

Output:
  - Log per ogni anomalia trovata.
  - Riepilogo finale con numero di record OK / KO.
  - Exit code 0 se tutti OK, 1 se ci sono errori.

Esempi uso:

  python m01_android_adb_04_validate_coherence.py ^
      --db "C:\SAFENET\DB\forensic.db" ^
      --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs" ^
      --limit 50

  python m01_android_adb_04_validate_coherence.py ^
      --db "C:\SAFENET\DB\forensic.db" ^
      --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs" ^
      --device-id 201 ^
      --id-min 1 --id-max 100
"""

import argparse
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


@dataclass
class AndroidEventRecord:
    android_event_id: int
    timestamp_utc: str
    device_id: int
    title: str
    source_file: str


def load_device_labels(conn) -> Dict[int, str]:
    cur = conn.cursor()
    cur.execute("SELECT device_id, device_label FROM DEVICE_MASTER")
    res: Dict[int, str] = {}
    for device_id, label in cur.fetchall():
        if label is not None:
            res[int(device_id)] = str(label)
    return res


def parse_run_id_from_path(path: Path) -> Optional[str]:
    """
    Path atteso:
      <dataset-root>/<device_logical>/<script_tag>/<run_id>/CORE_SYSTEM/logcat_main_*.txt

    Estraggo run_id = nome della cartella padre di CORE_SYSTEM (prima di file).
    """
    try:
        # .../<run_id>/CORE_SYSTEM/file
        run_dir = path.parent.parent  # file -> CORE_SYSTEM -> run_id
        return run_dir.name
    except Exception:
        return None


def parse_device_logical_from_path(dataset_root: Path, path: Path) -> Optional[str]:
    """
    Path atteso dentro dataset_root:
      dataset_root / <device_logical> / <script_tag> / <run_id> / ...

    Ritorna <device_logical> oppure None se non riconosciuto.
    """
    try:
        rel = path.resolve().relative_to(dataset_root.resolve())
    except ValueError:
        return None
    parts = rel.parts
    if len(parts) < 2:
        return None
    return parts[0]  # <device_logical>


def parse_run_id(run_id: str) -> Optional[Tuple[str, str, str, str, str, str]]:
    """
    run_id: 'YYYYMMDD_HHMMSS'
    ritorna (YYYY, MM, DD, hh, mm, ss) oppure None se invalido.
    """
    m = re.match(r"^(20\d{2})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$", run_id)
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)


def date_from_timestamp_utc(ts: str) -> Optional[str]:
    """
    timestamp_utc atteso tipo 'YYYY-MM-DD HH:MM:SS'
    ritorna 'YYYY-MM-DD' oppure None.
    """
    m = re.match(r"^(20\d{2}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}", ts)
    if not m:
        return None
    return m.group(1)


def title_in_file(title: str, file_path: Path, max_bytes: int = 5_000_000) -> bool:
    """
    Controlla se `title` compare nel file (substring). Per evitare di esplodere con file
    giganteschi leggiamo solo i primi max_bytes (default ~5MB).
    """
    try:
        size = file_path.stat().st_size
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            if size <= max_bytes:
                content = f.read()
                return title in content
            else:
                read_bytes = 0
                for line in f:
                    read_bytes += len(line.encode("utf-8", errors="ignore"))
                    if title in line:
                        return True
                    if read_bytes >= max_bytes:
                        break
        return False
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(
        description="Validazione di coerenza EVENTI_ANDROID <-> SAFENET android_adb_logs"
    )
    ap.add_argument(
        "--db",
        required=True,
        help="Percorso al DB SQLite (es. C:\\SAFENET\\DB\\forensic.db)",
    )
    ap.add_argument(
        "--dataset-root",
        "-d",
        required=True,
        help="Root DataSetGlobal per android_adb_logs (es. C:\\SAFENET\\DataSetGlobal\\android_adb_logs)",
    )
    ap.add_argument(
        "--device-id",
        type=int,
        help="Filtra per device_id specifico (opzionale).",
    )
    ap.add_argument(
        "--id-min",
        type=int,
        help="android_event_id minimo (opzionale).",
    )
    ap.add_argument(
        "--id-max",
        type=int,
        help="android_event_id massimo (opzionale).",
    )
    ap.add_argument(
        "--limit",
        type=int,
        help="Limita il numero di record analizzati (opzionale).",
    )
    ap.add_argument(
        "--skip-title-check",
        action="store_true",
        help="Non controllare la presenza del title dentro il file (salta il controllo 5).",
    )
    args = ap.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    if not dataset_root.exists() or not dataset_root.is_dir():
        raise SystemExit(f"dataset-root non valida: {dataset_root}")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    device_labels = load_device_labels(conn)

    # Costruzione query dinamica per EVENTI_ANDROID
    where_clauses = []
    params = []

    if args.device_id is not None:
        where_clauses.append("device_id = ?")
        params.append(args.device_id)
    if args.id_min is not None:
        where_clauses.append("android_event_id >= ?")
        params.append(args.id_min)
    if args.id_max is not None:
        where_clauses.append("android_event_id <= ?")
        params.append(args.id_max)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    limit_sql = f" LIMIT {int(args.limit)}" if args.limit else ""

    sql = f"""
        SELECT android_event_id, timestamp_utc, device_id, title, source_file
        FROM EVENTI_ANDROID
        {where_sql}
        ORDER BY android_event_id
        {limit_sql}
    """

    cur = conn.cursor()
    cur.execute(sql, params)

    total = 0
    ok_count = 0
    fail_count = 0

    print(f"[INFO] Dataset root: {dataset_root}")
    print(f"[INFO] Device labels: {device_labels}")
    print(f"[INFO] Query: {sql.strip()}  params={params}")

    rows = cur.fetchall()

    for row in rows:
        total += 1
        rec = AndroidEventRecord(
            android_event_id=row["android_event_id"],
            timestamp_utc=row["timestamp_utc"],
            device_id=row["device_id"],
            title=row["title"],
            source_file=row["source_file"],
        )

        record_ok = True

        print(f"\n[CHECK] android_event_id={rec.android_event_id}, device_id={rec.device_id}")
        print(f"        ts={rec.timestamp_utc}")
        print(f"        source_file={rec.source_file}")

        if not rec.source_file:
            print("  [ERR] source_file vuoto o NULL")
            record_ok = False
        else:
            file_path = Path(rec.source_file)

            # 1. file esiste?
            if not file_path.exists():
                print(f"  [ERR] file non esiste: {file_path}")
                record_ok = False
            else:
                print("  [OK ] file esiste")

                # 2. path sotto dataset_root?
                try:
                    _ = file_path.resolve().relative_to(dataset_root.resolve())
                    print("  [OK ] file sotto dataset_root")
                except ValueError:
                    print(f"  [ERR] file NON sotto dataset_root ({dataset_root})")
                    record_ok = False

                # 3. device_logical dal path vs DEVICE_MASTER.device_label
                device_logical = parse_device_logical_from_path(dataset_root, file_path)
                expected_label = device_labels.get(rec.device_id)

                if device_logical is None:
                    print("  [ERR] Impossibile ricavare device_logical dal path")
                    record_ok = False
                else:
                    print(f"  [OK ] device_logical dal path: {device_logical}")
                    if expected_label is None:
                        print(f"  [WARN] Nessuna label in DEVICE_MASTER per device_id={rec.device_id}")
                    else:
                        if device_logical != expected_label:
                            print(
                                f"  [ERR] device_logical='{device_logical}' "
                                f"!= DEVICE_MASTER.device_label='{expected_label}'"
                            )
                            record_ok = False
                        else:
                            print("  [OK ] device_logical combacia con DEVICE_MASTER.device_label")

                # 4. data da run_id vs data da timestamp_utc
                run_id = parse_run_id_from_path(file_path)
                if run_id is None:
                    print("  [ERR] Impossibile ricavare run_id dal path")
                    record_ok = False
                else:
                    parsed_run = parse_run_id(run_id)
                    if not parsed_run:
                        print(f"  [ERR] run_id '{run_id}' non matcha il formato YYYYMMDD_HHMMSS")
                        record_ok = False
                    else:
                        year, mm, dd, *_ = parsed_run
                        date_from_run = f"{year}-{mm}-{dd}"
                        date_from_ts = date_from_timestamp_utc(rec.timestamp_utc)
                        if date_from_ts is None:
                            print(f"  [ERR] timestamp_utc '{rec.timestamp_utc}' non riconosciuto")
                            record_ok = False
                        else:
                            if date_from_run != date_from_ts:
                                print(
                                    f"  [ERR] data da run_id '{date_from_run}' "
                                    f"!= data da timestamp_utc '{date_from_ts}'"
                                )
                                record_ok = False
                            else:
                                print("  [OK ] data da run_id combacia con data da timestamp_utc")

                # 5. title trovato nel file?
                if not args.skip_title_check and file_path.exists():
                    if rec.title and title_in_file(rec.title, file_path):
                        print("  [OK ] title trovato nel file sorgente")
                    else:
                        print("  [ERR] title NON trovato nel file (o vuoto)")
                        record_ok = False

        if record_ok:
            ok_count += 1
            print("  [RES] OK")
        else:
            fail_count += 1
            print("  [RES] FAIL")

    conn.close()

    print("\n[SUMMARY]")
    print(f"  Totale record analizzati: {total}")
    print(f"  OK:   {ok_count}")
    print(f"  FAIL: {fail_count}")

    # Exit code for automation / CI style
    if fail_count > 0:
        raise SystemExit(1)
    else:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
