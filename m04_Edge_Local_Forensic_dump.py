#!/usr/bin/env python3

r"""
m04_Edge_Local_Forensic_dump.py

Raccolta forense Edge-only per TUTTI gli utenti locali di una macchina Windows.

Per ogni utente locale (C:\Users\<user>):
  - cerca Edge User Data:  <user>\AppData\Local\Microsoft\Edge\User Data
  - per ogni profilo (Default, Profile X, ...):
      - copia i principali file Edge (History, Login Data, Cookies, Web Data, Bookmarks, Preferences, Favicons, Top Sites)
      - registra una riga in EvidenceIndex.csv

Output principale:

  <output_root>\<HOST>_<case_ref>_<YYYYMMDD_HHMMSS>\
      EvidenceIndex.csv
      Edge_Report.json
      Users\
          <user1>\Edge\<Profile>\Edge_History_<Profile>
                               Edge_Login_Data_<Profile>
                               Edge_Cookies_<Profile>
                               ...

EvidenceIndex.csv è compatibile con m04_Edge_Local_Forensic_INSERT_DB.py:
  CaseRef, Host, UserRef, CollectedOn, SourceType, Description, RelativePath
"""


import argparse
import datetime as dt
import csv
import os
import shutil
from pathlib import Path
from typing import List, Dict, Any

# principali file Edge da copiare per profilo
EDGE_FILES = [
    "History",
    "History-journal",
    "Login Data",
    "Login Data-journal",
    "Web Data",
    "Cookies",
    "Bookmarks",
    "Preferences",
    "Favicons",
    "Top Sites",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Raccolta forense Edge per tutti gli utenti locali (multi-profilo)."
    )
    p.add_argument(
        "--output-root",
        default=r"C:\ForensicEdge",
        help="Cartella radice per le raccolte (default: C:\\ForensicEdge).",
    )
    p.add_argument(
        "--case-ref",
        default=None,
        help="CaseRef da usare in EvidenceIndex (es. OMI_ADM_GUE). Default: EDGE_<HOST>.",
    )
    p.add_argument(
        "--host-name",
        default=None,
        help="Override nome host (default: COMPUTERNAME).",
    )
    p.add_argument(
        "--include-system-users",
        action="store_true",
        help="Includi anche account di sistema (Default, Public, ecc.).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Non copia file, stampa solo cosa farebbe.",
    )
    return p.parse_args()


def get_host_name(args: argparse.Namespace) -> str:
    if args.host_name:
        return args.host_name
    # Windows: COMPUTERNAME; fallback a nodename
    host = os.environ.get("COMPUTERNAME")
    if not host:
        try:
            import platform
            host = platform.node()
        except Exception:
            host = "UNKNOWN_HOST"
    return host


def should_skip_user(user_name: str, include_system: bool) -> bool:
    if include_system:
        return False
    # escludiamo utenti tipici di sistema
    sys_users = {"Public", "Default", "Default User", "All Users"}
    if user_name in sys_users:
        return True
    # profili temporanei / default vari
    if user_name.startswith("WDAGUtility"):  # sandbox Edge
        return True
    return False


def enumerate_local_users() -> List[Path]:
    users_root = Path(r"C:\Users")
    if not users_root.is_dir():
        return []
    return [p for p in users_root.iterdir() if p.is_dir()]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def copy_edge_file(
    src: Path,
    dst: Path,
    dry_run: bool,
) -> None:
    if dry_run:
        print(f"[DRY] Copy {src} -> {dst}")
        return
    ensure_dir(dst.parent)
    shutil.copy2(src, dst)


def main():
    args = parse_args()
    host = get_host_name(args)
    case_ref = args.case_ref or f"EDGE_{host}"

    now_local = dt.datetime.now()
    collected_on_iso = now_local.isoformat(timespec="seconds")  # compatibile con Insert script
    run_ts = now_local.strftime("%Y%m%d_%H%M%S")

    output_root = Path(args.output_root)
    ensure_dir(output_root)

    case_folder_name = f"{host}_{case_ref}_{run_ts}"
    case_folder = output_root / case_folder_name
    ensure_dir(case_folder)

    users_root_out = case_folder / "Users"
    ensure_dir(users_root_out)

    evidence_rows: List[Dict[str, Any]] = []
    report_users: List[Dict[str, Any]] = []

    print(f"[INFO] Host: {host}")
    print(f"[INFO] CaseRef: {case_ref}")
    print(f"[INFO] Output folder: {case_folder}")
    print(f"[INFO] CollectedOn: {collected_on_iso}")

    # Enumerazione utenti locali
    user_dirs = enumerate_local_users()
    print(f"[INFO] Utenti locali trovati in C:\\Users: {[p.name for p in user_dirs]}")

    for user_dir in user_dirs:
        user_name = user_dir.name
        if should_skip_user(user_name, args.include_system_users):
            print(f"[INFO] Skip utente di sistema: {user_name}")
            continue

        # Edge User Data path
        edge_user_data = user_dir / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data"
        if not edge_user_data.is_dir():
            print(f"[INFO] Nessun Edge User Data per utente {user_name} ({edge_user_data})")
            continue

        print(f"\n[INFO] Utente: {user_name}")
        print(f"       Edge User Data: {edge_user_data}")

        user_out_root = users_root_out / user_name / "Edge"
        ensure_dir(user_out_root)

        user_profile_summaries: List[Dict[str, Any]] = []

        # profili = subdir (Default, Profile 1, Profile 2, ecc.)
        try:
            for profile_dir in edge_user_data.iterdir():
                if not profile_dir.is_dir():
                    continue
                profile_name = profile_dir.name
                if not (profile_name == "Default" or profile_name.startswith("Profile ")):
                    # puoi decidere di includere anche altri tipi di profili, ma per ora teniamoci a questi
                    continue

                print(f"  [INFO] Profilo Edge: {profile_name}")
                dst_profile_root = user_out_root / profile_name
                ensure_dir(dst_profile_root)

                copied_files = []

                for fname in EDGE_FILES:
                    src = profile_dir / fname
                    if not src.is_file():
                        continue

                    safe_name = fname.replace(" ", "_")
                    dst_name = f"Edge_{safe_name}_{profile_name}"
                    dst = dst_profile_root / dst_name

                    try:
                        copy_edge_file(src, dst, args.dry_run)
                        copied_files.append(str(dst))
                    except Exception as e:
                        print(f"[WARN] Impossibile copiare {src} -> {dst}: {e}")
                        continue

                    # row EvidenceIndex
                    rel_path = dst.relative_to(case_folder) if not args.dry_run else dst.relative_to(case_folder)
                    evidence_rows.append(
                        {
                            "CaseRef": case_ref,
                            "Host": host,
                            "UserRef": user_name,
                            "CollectedOn": collected_on_iso,
                            "SourceType": f"Edge:Profile:{profile_name}",
                            "Description": f"Edge file {fname} per utente {user_name}, profilo {profile_name}",
                            "RelativePath": str(rel_path).replace("\\", "/"),
                        }
                    )

                user_profile_summaries.append(
                    {
                        "profile_name": profile_name,
                        "edge_user_data_path": str(profile_dir),
                        "files_copied": copied_files,
                    }
                )
        except Exception as e:
            print(f"[WARN] Errore durante la scansione dei profili per utente {user_name}: {e}")
            continue

        if user_profile_summaries:
            report_users.append(
                {
                    "user_name": user_name,
                    "edge_user_data_root": str(edge_user_data),
                    "profiles": user_profile_summaries,
                }
            )

    # Scrivi EvidenceIndex.csv
    evidence_index_path = case_folder / "EvidenceIndex.csv"
    if evidence_rows and not args.dry_run:
        fieldnames = [
            "CaseRef",
            "Host",
            "UserRef",
            "CollectedOn",
            "SourceType",
            "Description",
            "RelativePath",
        ]
        with evidence_index_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in evidence_rows:
                writer.writerow(row)
        print(f"\n[OK] EvidenceIndex.csv scritto: {evidence_index_path}")
    else:
        if args.dry_run:
            print("\n[DRY] EvidenceIndex.csv NON scritto (dry-run).")
        else:
            print("\n[WARN] Nessun dato Edge trovato, EvidenceIndex.csv vuoto/non creato.")

    # Scrivi report JSON
    import json

    report = {
        "schema": "m04_edge_local_forensic_dump_v1",
        "host": host,
        "case_ref": case_ref,
        "run_folder": case_folder.name,
        "collected_on_local": collected_on_iso,
        "users": report_users,
    }
    report_path = case_folder / "Edge_Report.json"
    if not args.dry_run:
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[OK] Edge_Report.json scritto: {report_path}")
    else:
        print("[DRY] Edge_Report.json NON scritto (dry-run).")

    print("\n[SUMMARY]")
    print(f"  Utenti elaborati  : {len(report_users)}")
    print(f"  Righe EvidenceIndex: {len(evidence_rows)}")
    print(f"  Output root       : {case_folder}")


if __name__ == "__main__":
    main()
