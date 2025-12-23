# M01 - Android ADB logs -> SAFENET -> EVENTI_ANDROID

README della milestone M01. Obiettivo: prendere dump ADB grezzi,
normalizzarli in DataSetGlobal e preparare EVENTI_ANDROID.

## Scope
- Acquisizioni ADB da `android_log_dump_0.2` (o simili).
- Normalizzazione in `DataSetGlobal\android_adb_logs`.
- Registrazione in `ANDROID_ACQUISITIONS`.
- Loader di prova per EVENTI_ANDROID (attuale: SQLite legacy).

## Struttura SAFENET attesa

```text
C:\SAFENET\DataSetGlobal\android_adb_logs\
  <device_logical>\
    android_log_dump_0.2\
      <run_id>\
        META\
        CORE_SYSTEM\
        CONNECTIVITY\
        APPS_PACKAGES\
        RAW_ALL\
```

`META/acquisition_meta.json` e' obbligatorio.

## Tabelle DB coinvolte
- DEVICE_MASTER (bootstrap).
- ANDROID_ACQUISITIONS (DDL milestone).
- EVENTI_ANDROID (DDL milestone).

## DDL
- MySQL: `myScript/m01_android_adb_01_init.mysql.sql`
- SQLite legacy: `m01_android_adb_01_init.sql`
- Seed device (opzionale): `m01_android_adb_01b_seed_DEVICE_MASTER.sql`

## Script della milestone
- Extract: `m01_android_adb_02_extract_to_safenet.py`
- Validate: `m01_android_adb_02b_validate_safenet.py`
- Load (probe): `m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py` (SQLite legacy)
- Post-check: `m01_android_adb_04_validate_coherence.py`

## Procedura standard (M01)
1. Eseguire il DDL MySQL della milestone.
2. Acquisire i dump ADB (cartelle `brand_model_serial_YYYYMMDD_HHMMSS`).
3. Extract in SAFENET:

```bash
python C:\SAFENET\Tools\m01_android_adb_02_extract_to_safenet.py ^
  --android-logs-root "D:\Evidence\ANDROID_Mobile\android_logs" ^
  --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs"
```

4. Validazione:

```bash
python C:\SAFENET\Tools\m01_android_adb_02b_validate_safenet.py ^
  --android-logs-root "D:\Evidence\ANDROID_Mobile\android_logs" ^
  --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs"
```

5. Load (probe, SQLite legacy):

```bash
python C:\SAFENET\Tools\m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs" ^
  --db "C:\SAFENET\DB\forensic.db"
```

6. Post-check (opzionale):

```bash
python C:\SAFENET\Tools\m01_android_adb_04_validate_coherence.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs"
```

## Note
- Il loader M01 e' ancora SQLite. Per allinearsi allo standard MySQL va portato.
- DEVICE_MASTER deve contenere i device label usati come `<device_logical>`.
