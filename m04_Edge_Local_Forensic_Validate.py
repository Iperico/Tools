#!/usr/bin/env python3
"""Validate that EvidenceIndex.csv rows are present in DB and optionally on disk.

PowerShell quick run (auto-detects paths when possibile):
  python .\m04_Edge_Local_Forensic_Validate.py `
      --check-files `
      --db "C:\SAFENET\DB\forensic.db"
"""

import argparse
import csv
import sqlite3
from pathlib import Path
from typing import Iterable, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent


def guess_case_root() -> Optional[Path]:
    candidates = [
        Path.cwd() / "Forensic_Collect",
        SCRIPT_DIR.parent / "DataSetGlobal" / "Forensic_Collect",
        Path("C:/SAFENET/DataSetGlobal/Forensic_Collect"),
        Path("C:/Forensic_Collect"),
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    return None


def guess_db_path() -> Optional[Path]:
    candidates = [
        Path.cwd() / "forensic.db",
        Path.cwd() / "DB" / "forensic.db",
        SCRIPT_DIR.parent / "DB" / "forensic.db",
        Path("C:/SAFENET/DB/forensic.db"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verifica che EvidenceIndex.csv sia coerente con il DB e i file raccolti."
    )
    parser.add_argument(
        "--case-folder",
        action="append",
        help="Cartella singola con EvidenceIndex.csv da validare (opzione ripetibile).",
    )
    parser.add_argument(
        "--case-root",
        help="Cartella radice: valida tutte le sottocartelle contenenti EvidenceIndex.csv.",
    )
    parser.add_argument(
        "--db",
        help="Percorso del DB SQLite forense.",
    )
    parser.add_argument(
        "--check-files",
        action="store_true",
        help="Controlla che ogni RelativePath esista sul disco.",
    )
    return parser.parse_args()


def iter_case_folders(case_args: List[str], case_root: Optional[str]) -> Iterable[Path]:
    if case_args:
        for item in case_args:
            folder = Path(item).resolve()
            if (folder / "EvidenceIndex.csv").is_file():
                yield folder
            else:
                print(f"[WARN] EvidenceIndex.csv non trovato in {folder}")
    if case_root:
        root = Path(case_root).resolve()
        if not root.is_dir():
            print(f"[WARN] case-root non valido: {root}")
        else:
            for child in sorted(root.iterdir()):
                if child.is_dir() and (child / "EvidenceIndex.csv").is_file():
                    yield child


def read_csv(folder: Path) -> List[dict]:
    with (folder / "EvidenceIndex.csv").open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def normalise_user_ref(raw: str) -> str:
    return (raw or "").strip()


def evidence_exists(cursor: sqlite3.Cursor, row: dict) -> bool:
    case_ref = (row.get("CaseRef") or "").strip()
    host_name = (row.get("Host") or "").strip()
    user_ref = normalise_user_ref(row.get("UserRef"))
    collected = (row.get("CollectedOn") or "").strip()
    source_type = (row.get("SourceType") or "").strip()
    relative_path = (row.get("RelativePath") or "").strip()

    if user_ref:
        cursor.execute(
            """
            SELECT evidence_id
            FROM EVIDENCE_INDEX
            WHERE case_ref = ?
              AND host_name = ?
              AND user_ref = ?
              AND collected_on_utc = ?
              AND source_type = ?
              AND relative_path = ?
            LIMIT 1
            """,
            (case_ref, host_name, user_ref, collected, source_type, relative_path),
        )
    else:
        cursor.execute(
            """
            SELECT evidence_id
            FROM EVIDENCE_INDEX
            WHERE case_ref = ?
              AND host_name = ?
              AND user_ref IS NULL
              AND collected_on_utc = ?
              AND source_type = ?
              AND relative_path = ?
            LIMIT 1
            """,
            (case_ref, host_name, collected, source_type, relative_path),
        )
    return cursor.fetchone() is not None


def main() -> None:
    args = parse_args()
    if not args.case_folder and not args.case_root:
        guessed_root = guess_case_root()
        if guessed_root:
            args.case_root = str(guessed_root)
            print(f"[INFO] case-root non specificato, uso {args.case_root}")

    folders = list(iter_case_folders(args.case_folder or [], args.case_root))
    if not folders:
        raise SystemExit("Nessuna cartella caso valida trovata.")

    if not args.db:
        guessed_db = guess_db_path()
        if guessed_db:
            args.db = str(guessed_db)
            print(f"[INFO] db non specificato, uso {args.db}")
        else:
            raise SystemExit("Specificare --db (file forensic.db non trovato automaticamente).")

    conn = sqlite3.connect(Path(args.db).resolve())
    cur = conn.cursor()

    missing_db = 0
    missing_file = 0

    for folder in folders:
        rows = read_csv(folder)
        print(f"[INFO] Validazione caso: {folder.name}")
        for row in rows:
            if not evidence_exists(cur, row):
                print(
                    "[WARN] Riga mancante nel DB -> case_ref=%s host=%s user=%s source=%s"
                    % (
                        (row.get("CaseRef") or "").strip(),
                        (row.get("Host") or "").strip(),
                        normalise_user_ref(row.get("UserRef")) or "(NULL)",
                        (row.get("SourceType") or "").strip(),
                    )
                )
                missing_db += 1
                continue
            if args.check_files:
                rel = (row.get("RelativePath") or "").strip()
                file_path = folder / rel
                if not file_path.exists():
                    print(f"[WARN] File non trovato sul disco: {file_path}")
                    missing_file += 1

    conn.close()

    print("[SUMMARY] Validazione completata.")
    print(f"  Mancanze DB   : {missing_db}")
    if args.check_files:
        print(f"  File mancanti : {missing_file}")


if __name__ == "__main__":
    main()
