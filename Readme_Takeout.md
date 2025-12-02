# M03 – Google Takeout → SAFENET → EVENTI_ANDROID

Pipeline Takeout per DB FORENSIC / SAFENET.

Copre:
- Copia Takeout in DataSetGlobal
- Normalizzazione CSV con generate_takeout_report.py
- Validazione
- Inserimento EVENTI_ANDROID

## 1. Struttura finale SAFENET

C:\SAFENET\DataSetGlobal\takeout\<account_label>\takeout_<run_id>\
    RAW_ALL\
    REPORT\
    META\acquisition_meta.json

## 2. Script della milestone

- m03_takeout_02_extract_to_safenet.py
- m03_takeout_02b_validate_safenet.py
- m03_takeout_03_probe_load_to_EVENTI_ANDROID.py

## 3. Init SQL richiesto

CREATE TABLE IF NOT EXISTS TAKEOUT_ACQUISITIONS (
    takeout_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    takeout_label TEXT NOT NULL,
    source_root_path TEXT NOT NULL,
    safenet_root_path TEXT NOT NULL,
    acquisition_ts_utc TEXT NOT NULL,
    tool_version TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS IX_TAKEOUT_ACQ_ACCOUNT
   ON TAKEOUT_ACQUISITIONS(account_id);

## 4. Uso

### Estrarre Takeout
python m03_takeout_02_extract_to_safenet.py ^
  --source "C:\Users\...\Takeout" ^
  --target "C:\SAFENET\DataSetGlobal\takeout" ^
  --db "C:\SAFENET\DB\forensic.db" ^
  --account-label "ACC_OMI_MAIN"

### Validare
python m03_takeout_02b_validate_safenet.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\takeout" ^
  --account-label "ACC_OMI_MAIN"

### Caricare in EVENTI_ANDROID
python m03_takeout_03_probe_load_to_EVENTI_ANDROID.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\takeout" ^
  --db "C:\SAFENET\DB\forensic.db" ^
  --account-label "ACC_OMI_MAIN" ^
  --source-type "PLAY_INSTALLS"
