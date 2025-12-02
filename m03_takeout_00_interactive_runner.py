#!/usr/bin/env python3
"""
m03_takeout_00_interactive_runner.py

Runner interattivo per la pipeline Takeout:

1) Estrazione Takeout -> SAFENET (m03_takeout_02_extract_to_safenet.py)
2) Validazione (m03_takeout_02b_validate_safenet.py)
3) Load EVENTI_ANDROID (m03_takeout_03_probe_load_to_EVENTI_ANDROID.py)
"""

import os
import sys
import subprocess
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent

# Nomi script “step”
EXTRACT_SCRIPT = THIS_DIR / "m03_takeout_02_extract_to_safenet.py"
VALIDATE_SCRIPT = THIS_DIR / "m03_takeout_02b_validate_safenet.py"
LOAD_SCRIPT = THIS_DIR / "m03_takeout_03_probe_load_to_EVENTI_ANDROID.py"

DEFAULTS = {
    "db": r"C:\SAFENET\DB\forensic.db",
    "dataset_root_takeout": r"C:\SAFENET\DataSetGlobal\takeout",
    "account_label": "ACC_OMI_MAIN",
    "takeout_source": r"C:\Users\OMICRON\Desktop\Beb_Info_Fango\Takeout",
}

SOURCE_TYPES = [
    "PLAY_INSTALLS",
    "PLAY_ORDERS",
    "PLAY_PURCHASES",
    "PLAY_SUBSCRIPTIONS",
    "ACCESS_LOG",
]


def ask(prompt: str, default: str | None = None) -> str:
    if default:
        full = f"{prompt} [{default}]: "
    else:
        full = f"{prompt}: "
    val = input(full).strip()
    return val or (default or "")


def pause():
    input("\nPremi INVIO per continuare...")


def run_subprocess(cmd: list[str]) -> int:
    print("\n[DEBUG] Command:")
    print("  " + " ".join(cmd))
    print()
    result = subprocess.run(cmd)
    return result.returncode


def step_extract():
    print("\n=== STEP 1: ESTRAZIONE TAKEOUT → SAFENET ===\n")

    if not EXTRACT_SCRIPT.is_file():
        print(f"[ERROR] Script non trovato: {EXTRACT_SCRIPT}")
        return

    source = ask("Percorso cartella TAKEOUT (quella con 'Access Log Activity', 'Google Play Store', ...)",
                 DEFAULTS["takeout_source"])
    target = ask("Root DataSetGlobal/takeout",
                 DEFAULTS["dataset_root_takeout"])
    db = ask("Path DB forensic.db",
             DEFAULTS["db"])
    account_label = ask("ACCOUNT_MASTER.account_label",
                        DEFAULTS["account_label"])

    from_date = ask("Filtro FROM date (YYYY-MM-DD) o vuoto per nessun filtro", "")
    to_date = ask("Filtro TO date (YYYY-MM-DD, esclusiva) o vuoto per nessun filtro", "")

    cmd = [
        sys.executable,
        str(EXTRACT_SCRIPT),
        "--source", source,
        "--target", target,
        "--db", db,
        "--account-label", account_label,
    ]
    if from_date:
        cmd += ["--from-date", from_date]
    if to_date:
        cmd += ["--to-date", to_date]

    rc = run_subprocess(cmd)
    if rc == 0:
        print("\n[OK] Estrazione completata.")
    else:
        print(f"\n[ERROR] Estrazione terminata con codice {rc}.")


def step_validate():
    print("\n=== STEP 2: VALIDAZIONE TAKEOUT IN SAFENET ===\n")

    if not VALIDATE_SCRIPT.is_file():
        print(f"[ERROR] Script non trovato: {VALIDATE_SCRIPT}")
        return

    dataset_root = ask("Root DataSetGlobal/takeout",
                       DEFAULTS["dataset_root_takeout"])
    account_label = ask("ACCOUNT_MASTER.account_label",
                        DEFAULTS["account_label"])
    takeout_label = ask("takeout_label (es. takeout_20251116_224500, vuoto = ultimo)", "")

    cmd = [
        sys.executable,
        str(VALIDATE_SCRIPT),
        "--dataset-root", dataset_root,
        "--account-label", account_label,
    ]
    if takeout_label:
        cmd += ["--takeout-label", takeout_label]

    rc = run_subprocess(cmd)
    if rc == 0:
        print("\n[OK] Validazione terminata (controlla eventuali WARN/ERROR nel log sopra).")
    else:
        print(f"\n[ERROR] Validazione terminata con codice {rc}.")


def choose_source_type() -> str:
    print("\nSorgenti disponibili da caricare in EVENTI_ANDROID:")
    for idx, s in enumerate(SOURCE_TYPES, start=1):
        print(f"  {idx}) {s}")
    while True:
        choice = input("Seleziona sorgente (numero): ").strip()
        if not choice:
            continue
        if not choice.isdigit():
            print("Inserisci un numero valido.")
            continue
        i = int(choice)
        if 1 <= i <= len(SOURCE_TYPES):
            return SOURCE_TYPES[i - 1]
        print("Numero fuori range.")


def step_load():
    print("\n=== STEP 3: LOAD EVENTI_ANDROID (TAKEOUT) ===\n")

    if not LOAD_SCRIPT.is_file():
        print(f"[ERROR] Script non trovato: {LOAD_SCRIPT}")
        return

    dataset_root = ask("Root DataSetGlobal/takeout",
                       DEFAULTS["dataset_root_takeout"])
    db = ask("Path DB forensic.db",
             DEFAULTS["db"])
    account_label = ask("ACCOUNT_MASTER.account_label",
                        DEFAULTS["account_label"])
    takeout_label = ask("takeout_label (es. takeout_20251116_224500, vuoto = ultimo)", "")

    print()
    src_type = choose_source_type()
    print(f"[INFO] Source-type scelto: {src_type}")

    limit_str = ask("limit-per-run (max eventi da inserire, default 500)", "500")
    try:
        limit = int(limit_str)
    except ValueError:
        limit = 500

    cmd = [
        sys.executable,
        str(LOAD_SCRIPT),
        "--dataset-root", dataset_root,
        "--db", db,
        "--account-label", account_label,
        "--source-type", src_type,
        "--limit-per-run", str(limit),
    ]
    if takeout_label:
        cmd += ["--takeout-label", takeout_label]

    rc = run_subprocess(cmd)
    if rc == 0:
        print("\n[OK] Load completato.")
    else:
        print(f"\n[ERROR] Load terminato con codice {rc}.")


def main_menu():
    while True:
        print("\n======================================")
        print("  M03 – TAKEOUT PIPELINE INTERATTIVA ")
        print("======================================")
        print("1) Estrazione Takeout → SAFENET")
        print("2) Validazione Takeout in SAFENET")
        print("3) Load EVENTI_ANDROID (probe)")
        print("4) Esci")
        choice = input("\nSeleziona un'operazione: ").strip()

        if choice == "1":
            step_extract()
            pause()
        elif choice == "2":
            step_validate()
            pause()
        elif choice == "3":
            step_load()
            pause()
        elif choice == "4":
            print("Bye.")
            break
        else:
            print("Scelta non valida.")


if __name__ == "__main__":
    main_menu()
