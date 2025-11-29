#!/usr/bin/env python
# android_logs_to_safenet_auto.py
#
# Breve descrizione:
#   Riorganizza l'output di android_log_dump (cartelle android_logs/<brand>_<model>_<serial>_<YYYYMMDD_HHMMSS>)
#   nella struttura SAFENET DataSetGlobal:
#     <dataset_root>/<device_logical>/android_log_dump_<version>/<run_id>/{META,CORE_SYSTEM,CONNECTIVITY,APPS_PACKAGES,RAW_ALL}
#   Copia i file (non modifica gli originali), crea acquisition_meta.json per ogni run
#   e mappa automaticamente il device a partire da <brand>_<model>_<serial>.
#   Se presente platform-tools/adb.exe nella dir dello script e usi --adb-info,
#   prova a leggere alcune getprop dal device connesso e le mette nel meta.
#
# Esempio una riga (PowerShell 5):
#   python .\android_logs_to_safenet_auto.py `
#       --android-logs-root "C:\SAFENET\android_logs" `
#       --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs" `
#       --adb-info
#

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ---------------- CONFIG CATEGORIE ----------------

# mapping prefisso file -> categoria logica
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


# ---------------- DEVICE MAPPING ----------------
# Mapping automatico da <brand>_<model>_<serial> -> device_logical
# Puoi personalizzarlo:
#   - se nessun prefisso matcha in DEVICE_MAP, si applicano le euristiche (S24/S20/Samsung generico).

DEVICE_MAP: Dict[str, str] = {
    # Esempi se vuoi forzare un mapping fisso:
    # "samsung_SM-S921B_R58N123456X": "SpartacusPhone_S24",
    # "samsung_SM-G981B_R58N654321Y": "VagabondoPhone_S20",
}


def map_device_logical(brand_model_serial: str) -> str:
    """
    Ritorna il nome logico del device.

    Priorità:
      1) match esplicito in DEVICE_MAP (prefisso)
      2) euristiche su S24 / S20
      3) euristica Samsung generico
      4) fallback = brand_model_serial
    """
    bms = brand_model_serial
    bms_lower = bms.lower()
    parts = bms.split("_")
    brand = parts[0].lower() if parts else ""
    model = parts[1].lower() if len(parts) > 1 else ""

    # 1) mapping esplicito
    for prefix, logical in DEVICE_MAP.items():
        if bms.startswith(prefix):
            return logical

    # 2) euristiche S24 / S20 (usiamo model e codici HW tipici)
    # Samsung S24 series (es. SM-S921B, SM-S926B, SM-S928B)
    if "s24" in model or "sm-s92" in bms_lower:
        return "Samsung_S24"

    # Samsung S20 series (es. SM-G980F, SM-G981B, SM-G985F, SM-G986B, SM-G988B)
    if "s20" in model or "sm-g98" in bms_lower:
        return "Samsung_S20"

    # 3) Samsung generico
    if brand == "samsung":
        if len(parts) > 1:
            # es. Samsung_SM-S918B -> Samsung_SM-S918B (più leggibile e unico)
            return f"Samsung_{parts[1]}"
        else:
            return "Samsung_Unknown"

    # 4) fallback: usa direttamente il pattern completo
    return bms


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


def classify_category(filename: str) -> str:
    """
    Restituisce la categoria principale (META, CORE_SYSTEM, CONNECTIVITY, APPS_PACKAGES)
    oppure "" se non matcha nessun prefisso.
    """
    fname = filename.lower()
    for prefix, cat in CATEGORY_PREFIXES.items():
        if fname.startswith(prefix):
            return cat
    return ""


def copy_file(src: Path, dst: Path, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY] COPY {src} -> {dst}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def write_json(path: Path, data: dict, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY] WRITE JSON {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------- ADB INTEGRAZIONE (OPZIONALE) ----------------

def find_adb_executable() -> Optional[Path]:
    """
    Cerca adb in .\platform-tools\adb(.exe) rispetto alla posizione dello script.
    """
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "platform-tools" / "adb.exe",
        script_dir / "platform-tools" / "adb",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def adb_getprops(adb_path: Path, timeout: float = 5.0) -> Dict[str, str]:
    """
    Prova a leggere alcune getprop dal device connesso.
    Se qualcosa va storto, ritorna dict vuoto.
    """
    props = {}
    try:
        # brand, model, device, serial
        keys = [
            "ro.product.brand",
            "ro.product.model",
            "ro.product.device",
            "ro.serialno",
            "ro.build.version.release",
            "ro.build.version.sdk",
        ]
        for key in keys:
            result = subprocess.run(
                [str(adb_path), "shell", "getprop", key],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                props[key] = result.stdout.strip()
    except Exception as e:
        print(f"[WARN] adb_getprops error: {e}")

    try:
        # adb devices -l per avere info base
        result = subprocess.run(
            [str(adb_path), "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            props["adb_devices_output"] = result.stdout
    except Exception as e:
        print(f"[WARN] adb devices error: {e}")

    return props


# ---------------- LOGICA PRINCIPALE PER RUN ----------------

def process_run_folder(
    run_dir: Path,
    dataset_root: Path,
    script_name: str,
    script_version: str,
    dry_run: bool,
    adb_info: bool,
    adb_path: Optional[Path],
) -> None:
    """
    Processa una singola cartella:
      android_logs/<brand>_<model>_<serial>_<YYYYMMDD_HHMMSS>/
    e crea la struttura:

      <dataset_root>/<device_logical>/<script_name>_<script_version>/<run_id>/
        META/
        CORE_SYSTEM/
        CONNECTIVITY/
        APPS_PACKAGES/
        RAW_ALL/
    """
    brand_model_serial, run_id = parse_run_folder_name(run_dir.name)
    device_logical = map_device_logical(brand_model_serial)
    script_tag = f"{script_name}_{script_version}"

    run_base = dataset_root / device_logical / script_tag / run_id

    print(f"\n[RUN] {run_dir}")
    print(f"      brand_model_serial = {brand_model_serial}")
    print(f"      device_logical     = {device_logical}")
    print(f"      run_id             = {run_id}")
    print(f"      target base        = {run_base}")

    # Prepara contatori per meta
    total_files = 0
    category_counts = {name: 0 for name in RUN_SUBDIRS}
    uncategorized_files: List[str] = []

    # Crea sottocartelle (in dry_run solo log)
    for sub in RUN_SUBDIRS:
        subdir = run_base / sub
        if dry_run:
            print(f"[DRY] MKDIR {subdir}")
        else:
            subdir.mkdir(parents=True, exist_ok=True)

    # Copy dei file
    for item in sorted(run_dir.iterdir()):
        if not item.is_file():
            continue

        total_files += 1
        cat = classify_category(item.name)
        # Sempre RAW_ALL
        raw_dest = run_base / "RAW_ALL" / item.name
        copy_file(item, raw_dest, dry_run)
        category_counts["RAW_ALL"] += 1

        if cat:
            dst_cat = run_base / cat / item.name
            copy_file(item, dst_cat, dry_run)
            category_counts[cat] += 1
        else:
            uncategorized_files.append(item.name)

    # Meta base
    meta = {
        "device_logical": device_logical,
        "brand_model_serial": brand_model_serial,
        "run_id": run_id,
        "script_name": script_name,
        "script_version": script_version,
        "source_run_dir": str(run_dir),
        "target_run_base": str(run_base),
        "total_files": total_files,
        "category_counts": category_counts,
        "uncategorized_files": uncategorized_files,
    }

    # Se richiesto, aggiunge info da adb (live, best effort)
    if adb_info and adb_path is not None:
        meta["adb_info"] = adb_getprops(adb_path)
    elif adb_info and adb_path is None:
        meta["adb_info"] = {"warning": "adb non trovato in platform-tools/"}

    meta_path = run_base / "META" / "acquisition_meta.json"
    write_json(meta_path, meta, dry_run)

    print(f"[SUMMARY] files={total_files}, category_counts={category_counts}")
    if uncategorized_files:
        print(f"[INFO] {len(uncategorized_files)} file non categorizzati (solo in RAW_ALL)")


# ---------------- ENTRYPOINT ----------------

def main():
    parser = argparse.ArgumentParser(
        description="Riorganizza android_logs in struttura SAFENET DataSetGlobal (solo copia, non modifica gli originali)."
    )
    parser.add_argument(
        "--android-logs-root",
        "-a",
        required=True,
        help="Cartella che contiene android_logs/<brand>_<model>_<serial>_<YYYYMMDD_HHMMSS>/",
    )
    parser.add_argument(
        "--dataset-root",
        "-d",
        required=True,
        help="Root DataSetGlobal per android_adb_logs (es. C:\\SAFENET\\DataSetGlobal\\android_adb_logs)",
    )
    parser.add_argument(
        "--script-name",
        default="android_log_dump",
        help='Nome script (default: "android_log_dump")',
    )
    parser.add_argument(
        "--script-version",
        default="0.2",
        help='Versione script (default: "0.2")',
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Non copia niente, mostra solo cosa farebbe.",
    )
    parser.add_argument(
        "--adb-info",
        action="store_true",
        help="Se true, prova a leggere getprop tramite platform-tools\\adb.exe e mette i dati nel meta.",
    )
    args = parser.parse_args()

    android_root = Path(args.android_logs_root).resolve()
    dataset_root = Path(args.dataset_root).resolve()

    if not android_root.exists() or not android_root.is_dir():
        raise SystemExit(f"Android logs root non valida: {android_root}")

    if not args.dry_run:
        dataset_root.mkdir(parents=True, exist_ok=True)

    adb_path = None
    if args.adb_info:
        adb_path = find_adb_executable()
        if adb_path:
            print(f"[INFO] adb trovato: {adb_path}")
        else:
            print("[WARN] adb non trovato in platform-tools/, adb-info sarà vuoto.")

    print(f"[INFO] android_logs_root : {android_root}")
    print(f"[INFO] dataset_root      : {dataset_root}")
    print(f"[INFO] script_name/ver   : {args.script_name} {args.script_version}")
    print(f"[INFO] dry_run           : {args.dry_run}")
    print(f"[INFO] adb_info          : {args.adb_info}")
    print("")

    # Trova tutte le sottocartelle "run"
    run_dirs = [p for p in sorted(android_root.iterdir()) if p.is_dir()]

    if not run_dirs:
        print("[WARN] Nessuna sottocartella trovata in android_logs_root.")
        return

    print(f"[INFO] Trovate {len(run_dirs)} run folder da processare.")
    for run_dir in run_dirs:
        process_run_folder(
            run_dir=run_dir,
            dataset_root=dataset_root,
            script_name=args.script_name,
            script_version=args.script_version,
            dry_run=args.dry_run,
            adb_info=args.adb_info,
            adb_path=adb_path,
        )

    print("\n[DONE] Riorganizzazione completata (o simulata se dry-run).")


if __name__ == "__main__":
    main()
