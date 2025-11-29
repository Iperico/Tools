#!/usr/bin/env python
# android_logs_validate_safenet.py
#
# Breve descrizione:
#   Valida che l'output riorganizzato di android_log_dump in SAFENET DataSetGlobal
#   non abbia perso dati:
#     - Per ogni cartella android_logs/<brand>_<model>_<serial>_<YYYYMMDD_HHMMSS>/
#       verifica che TUTTI i file originali siano presenti in:
#         <dataset_root>/<device_logical>/android_log_dump_<version>/<run_id>/RAW_ALL/
#       con lo stesso nome e dimensione (e opzionalmente hash).
#     - Usa principalmente run_id + serial per trovare la run target:
#         * run_id = YYYYMMDD_HHMMSS preso dal nome cartella
#         * serial  = ultima parte di <brand>_<model>_<serial>
#       e tenta di matchare con META/acquisition_meta.json (adb_info.ro.serialno).
#     - Verifica che i file con prefissi noti (logcat_*, dumpsys_*, ecc.)
#       siano presenti anche nella categoria logica corretta:
#         META / CORE_SYSTEM / CONNECTIVITY / APPS_PACKAGES.
#     - Controlla presenza di META/acquisition_meta.json, se esiste confronta total_files.
#
# Esempio una riga (PowerShell 5):
#   python .\android_logs_validate_safenet.py `
#       --android-logs-root "C:\SAFENET\android_logs" `
#       --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs" `
#       --script-name "android_log_dump" `
#       --script-version "0.2"
#
# Exit code:
#   0 -> tutte le run OK
#   1 -> almeno una run con errori (mancanza/mismatch)
#

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ---------------- CONFIG CATEGORIE (DEVE MATCHARE LO SCRIPT DI COPIA) ----------------

CATEGORY_PREFIXES: Dict[str, str] = {
    # META
    "device_info_": "META",
    "getprop_": "META",
    "report_summary_": "META",

    # CORE_SYSTEM
    "logcat_main_": "CORE_SYSTEM",
    "logcat_events_": "CORE_SYSTEM",
    "logcat_radio_": "CORE_SYSTEM",
    "logcat_crash_": "CORE_SYSTEM",
    "dmesg_": "CORE_SYSTEM",
    "dmesg_su_": "CORE_SYSTEM",
    "dumpsys_activity_": "CORE_SYSTEM",
    "dumpsys_power_": "CORE_SYSTEM",
    "settings_system_": "CORE_SYSTEM",
    "settings_global_": "CORE_SYSTEM",
    "settings_secure_": "CORE_SYSTEM",
    "df_": "CORE_SYSTEM",
    "mounts_": "CORE_SYSTEM",

    # CONNECTIVITY
    "netstat_": "CONNECTIVITY",
    "ip_addr_": "CONNECTIVITY",
    "ip_route_": "CONNECTIVITY",
    "dumpsys_connectivity_": "CONNECTIVITY",
    "dumpsys_wifi_": "CONNECTIVITY",
    "dumpsys_battery_": "CONNECTIVITY",

    # APPS_PACKAGES
    "dumpsys_package_": "APPS_PACKAGES",
    "packages_all_": "APPS_PACKAGES",
    "packages_third_party_": "APPS_PACKAGES",
    "ps_full_": "APPS_PACKAGES",
}

RUN_SUBDIRS = ["META", "CORE_SYSTEM", "CONNECTIVITY", "APPS_PACKAGES", "RAW_ALL"]


# ---------------- FUNZIONI UTILI ----------------

def parse_run_folder_name(folder_name: str) -> Tuple[str, str]:
    """
    Parsifica un nome tipo:
      <brand>_<model>_<serial>_<YYYYMMDD_HHMMSS>
    Restituisce (brand_model_serial, run_id) oppure (folder_name, "unknown_run").
    """
    m = re.match(r"^(.*)_(20\d{6}_\d{6})$", folder_name)
    if not m:
        return folder_name, "unknown_run"

    brand_model_serial = m.group(1)
    run_id = m.group(2)
    return brand_model_serial, run_id


def extract_serial_from_bms(brand_model_serial: str) -> str:
    """
    Estrae il serial dall'espressione <brand>_<model>_<serial>.
    Ritorna l'ultima parte dopo '_' (se esiste).
    """
    parts = brand_model_serial.split("_")
    if len(parts) >= 3:
        return parts[-1]
    if len(parts) == 2:
        return parts[1]
    return ""


def classify_category(filename: str) -> str:
    fname = filename.lower()
    for prefix, cat in CATEGORY_PREFIXES.items():
        if fname.startswith(prefix):
            return cat
    return ""


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def find_run_base_by_runid_and_serial(
    dataset_root: Path,
    script_tag: str,
    run_id: str,
    serial: str,
) -> Tuple[Optional[Path], List[str]]:
    """
    Cerca la cartella di destinazione della run usando:
      - script_tag = "android_log_dump_0.2"
      - run_id = "YYYYMMDD_HHMMSS"
      - serial = es. "RZCX60536TD"
    Strategia:
      1) Cerca tutte le cartelle dataset_root/*/<script_tag>/<run_id>/
      2) Se ce n'è una sola -> OK
      3) Se più di una -> prova a leggere META/acquisition_meta.json e matchare serial:
         - adb_info.ro.serialno oppure brand_model_serial
    Ritorna (run_base_path o None, warnings).
    """
    warnings: List[str] = []
    candidates: List[Path] = []

    for device_dir in dataset_root.iterdir():
        if not device_dir.is_dir():
            continue
        script_dir = device_dir / script_tag
        run_dir = script_dir / run_id
        if run_dir.is_dir():
            candidates.append(run_dir)

    if not candidates:
        warnings.append(
            f"Nessuna cartella target trovata per run_id={run_id} sotto {dataset_root}"
        )
        return None, warnings

    if len(candidates) == 1:
        return candidates[0], warnings

    # Più candidati, tentiamo match serial via META
    matched: List[Path] = []
    for c in candidates:
        meta_path = c / "META" / "acquisition_meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # prova con adb_info.ro.serialno
        adb_info = meta.get("adb_info", {})
        ro_serial = ""
        if isinstance(adb_info, dict):
            ro_serial = str(adb_info.get("ro.serialno", "")).strip()

        meta_bms = str(meta.get("brand_model_serial", "")).strip()

        if serial and ro_serial and serial in ro_serial:
            matched.append(c)
            continue
        if serial and meta_bms and serial in meta_bms:
            matched.append(c)
            continue

    if len(matched) == 1:
        return matched[0], warnings

    if not matched:
        warnings.append(
            f"Impossibile disambiguare run_id={run_id} con serial={serial}: "
            f"{len(candidates)} candidati, nessuno matcha il serial nei meta."
        )
    else:
        warnings.append(
            f"Più candidati ({len(matched)}) per run_id={run_id} con serial={serial}; "
            f"impossibile scegliere in modo univoco."
        )

    return None, warnings


# ---------------- VALIDAZIONE PER RUN ----------------

def validate_run(
    run_dir: Path,
    dataset_root: Path,
    script_name: str,
    script_version: str,
    use_hash: bool,
) -> Dict[str, object]:
    """
    Valida una singola run:
      android_logs/<brand>_<model>_<serial>_<run_id>/

    Controlla:
      - trovato run_base in DataSetGlobal usando run_id + serial
      - esistenza di RAW_ALL
      - ogni file sorgente presente in RAW_ALL con stessa dimensione (e opzionalmente hash)
      - per file categorizzabili, presenza anche nella cartella categoria
      - META/acquisition_meta.json coerente, se presente
      - file extra in RAW_ALL
    """
    brand_model_serial, run_id = parse_run_folder_name(run_dir.name)
    serial = extract_serial_from_bms(brand_model_serial)
    script_tag = f"{script_name}_{script_version}"

    info = {
        "run_dir": str(run_dir),
        "brand_model_serial": brand_model_serial,
        "serial": serial,
        "run_id": run_id,
        "run_base": "",
        "device_logical": "",
    }

    errors: List[str] = []
    warnings: List[str] = []

    if run_id == "unknown_run":
        errors.append("Impossibile estrarre run_id dal nome cartella.")
        return {"info": info, "errors": errors, "warnings": warnings}

    run_base, warn_find = find_run_base_by_runid_and_serial(
        dataset_root=dataset_root,
        script_tag=script_tag,
        run_id=run_id,
        serial=serial,
    )
    warnings.extend(warn_find)

    if run_base is None:
        errors.append("Cartella target run_base NON trovata per questa run.")
        return {"info": info, "errors": errors, "warnings": warnings}

    info["run_base"] = str(run_base)
    # device_logical = directory subito sotto dataset_root
    try:
        # dataset_root / <device_logical> / script_tag / run_id
        device_logical = run_base.parent.parent.name
    except Exception:
        device_logical = ""
    info["device_logical"] = device_logical

    raw_all_dir = run_base / "RAW_ALL"
    if not raw_all_dir.exists():
        errors.append(f"RAW_ALL mancante: {raw_all_dir}")
        return {"info": info, "errors": errors, "warnings": warnings}

    # indicizziamo RAW_ALL
    raw_files: Dict[str, Path] = {}
    for p in raw_all_dir.iterdir():
        if p.is_file():
            raw_files[p.name] = p

    # lista file sorgente
    src_files = [p for p in run_dir.iterdir() if p.is_file()]

    # validazione 1: tutti i src devono essere in RAW_ALL
    for src in src_files:
        name = src.name
        if name not in raw_files:
            errors.append(f"File sorgente NON trovato in RAW_ALL: {name}")
            continue

        dst = raw_files[name]

        # confronta dimensioni
        try:
            src_size = src.stat().st_size
            dst_size = dst.stat().st_size
        except OSError as e:
            errors.append(f"Errore leggendo dimensioni per {name}: {e}")
            continue

        if src_size != dst_size:
            errors.append(
                f"Mismatch dimensione per {name}: src={src_size}, dst={dst_size}"
            )
            continue

        # opzionale hash
        if use_hash:
            src_hash = sha256_file(src)
            dst_hash = sha256_file(dst)
            if src_hash != dst_hash:
                errors.append(
                    f"Mismatch SHA256 per {name}: src={src_hash}, dst={dst_hash}"
                )

    # validazione 2: categoria per file noti
    for src in src_files:
        cat = classify_category(src.name)
        if not cat or cat == "RAW_ALL":
            continue
        cat_dir = run_base / cat
        cat_file = cat_dir / src.name
        if not cat_dir.exists():
            warnings.append(f"Cartella categoria {cat} mancante (dovrebbe esistere).")
            continue
        if not cat_file.exists():
            warnings.append(
                f"File categorizzato atteso in {cat}: {src.name} non trovato."
            )

    # validazione 3: META/acquisition_meta.json (se c'è)
    meta_path = run_base / "META" / "acquisition_meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta_total = int(meta.get("total_files", -1))
            if meta_total != len(src_files):
                warnings.append(
                    f"acquisition_meta.json total_files={meta_total}, "
                    f"ma sorgenti={len(src_files)}"
                )

            # check consistenza serial nei meta, se presente
            adb_info = meta.get("adb_info", {})
            if isinstance(adb_info, dict):
                ro_serial = str(adb_info.get("ro.serialno", "")).strip()
                if serial and ro_serial and serial not in ro_serial:
                    warnings.append(
                        f"Serial da folder={serial}, ma adb_info.ro.serialno={ro_serial}"
                    )

        except Exception as e:
            warnings.append(f"Errore leggendo/parsing acquisition_meta.json: {e}")
    else:
        warnings.append("META/acquisition_meta.json non trovato.")

    # validazione 4: file extra in RAW_ALL (non presenti nell'originale)
    src_names = {p.name for p in src_files}
    extra_raw = [name for name in raw_files.keys() if name not in src_names]
    if extra_raw:
        warnings.append(
            f"{len(extra_raw)} file extra in RAW_ALL non presenti nella run sorgente: "
            f"{', '.join(sorted(extra_raw))[:200]}..."
        )

    return {"info": info, "errors": errors, "warnings": warnings}


# ---------------- MAIN ----------------

def main():
    ap = argparse.ArgumentParser(
        description=(
            "Valida che android_logs -> DataSetGlobal (android_adb_logs) "
            "non abbia perso dati (match per run_id + serial)."
        )
    )
    ap.add_argument(
        "--android-logs-root",
        "-a",
        required=True,
        help="Cartella che contiene android_logs/<brand>_<model>_<serial>_<YYYYMMDD_HHMMSS>/",
    )
    ap.add_argument(
        "--dataset-root",
        "-d",
        required=True,
        help="Root DataSetGlobal per android_adb_logs (es. C:\\SAFENET\\DataSetGlobal\\android_adb_logs)",
    )
    ap.add_argument(
        "--script-name",
        default="android_log_dump",
        help='Nome script usato nella struttura target (default: "android_log_dump")',
    )
    ap.add_argument(
        "--script-version",
        default="0.2",
        help='Versione script usata nella struttura target (default: "0.2")',
    )
    ap.add_argument(
        "--hash",
        action="store_true",
        help="Confronta anche SHA256 dei file (più lento ma più forte).",
    )
    args = ap.parse_args()

    android_root = Path(args.android_logs_root).resolve()
    dataset_root = Path(args.dataset_root).resolve()

    if not android_root.exists() or not android_root.is_dir():
        raise SystemExit(f"Android logs root non valida: {android_root}")

    if not dataset_root.exists() or not dataset_root.is_dir():
        raise SystemExit(f"Dataset root non valida: {dataset_root}")

    print(f"[INFO] android_logs_root : {android_root}")
    print(f"[INFO] dataset_root      : {dataset_root}")
    print(f"[INFO] script_name/ver   : {args.script_name} {args.script_version}")
    print(f"[INFO] hash check        : {args.hash}")
    print("")

    run_dirs = [p for p in sorted(android_root.iterdir()) if p.is_dir()]
    if not run_dirs:
        print("[WARN] Nessuna sottocartella trovata in android_logs_root.")
        raise SystemExit(1)

    print(f"[INFO] Trovate {len(run_dirs)} run folder da validare.\n")

    any_error = False
    total_runs = 0
    ok_runs = 0

    for run_dir in run_dirs:
        total_runs += 1
        result = validate_run(
            run_dir=run_dir,
            dataset_root=dataset_root,
            script_name=args.script_name,
            script_version=args.script_version,
            use_hash=args.hash,
        )
        info = result["info"]
        errors = result["errors"]
        warnings = result["warnings"]

        print(f"=== RUN: {info['run_dir']} ===")
        print(f"    serial         = {info['serial']}")
        print(f"    run_id         = {info['run_id']}")
        print(f"    run_base       = {info['run_base']}")
        print(f"    device_logical = {info['device_logical']}")

        if errors:
            any_error = True
            print("  [ERRORS]")
            for e in errors:
                print(f"    - {e}")
        if warnings:
            print("  [WARNINGS]")
            for w in warnings:
                print(f"    - {w}")

        if not errors:
            ok_runs += 1
            print("  [OK] Nessun errore critico per questa run.")
        print("")

    print("===== SUMMARY =====")
    print(f"Total runs      : {total_runs}")
    print(f"OK runs         : {ok_runs}")
    print(f"Runs with errors: {total_runs - ok_runs}")
    print("===================")

    if any_error:
        raise SystemExit(1)
    else:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
