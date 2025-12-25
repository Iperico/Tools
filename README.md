# DB Forensic - README generale

Questo README descrive la strategia attuale del DB forense SAFENET e le
procedure standard per le milestone.

## Strategia attuale (MySQL first)
- MySQL e' il database di riferimento per il lavoro nuovo.
- SQLite e' legacy o solo per migrazioni/compatibilita'.
- Bootstrap core separato dal DDL milestone:
  - Bootstrap: `mysql_forensic_init_optimized.sql` (oppure `myScript/mysql_forensic_init.sql`)
    crea DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION.
  - Shared raw: `myScript/m00_eventi_raw.mysql.sql` crea EVENTI_RAW (lossless, comune).
  - Milestone DDL: `mXX_*_01_init.mysql.sql` (primario) e `.sql` legacy.
- Ogni milestone produce ACQUISITIONS + EVENTI_* e usa DataSetGlobal
  come area normalizzata.

## Procedura standard per ogni milestone
1. Bootstrap (una volta): eseguire lo script bootstrap MySQL.
2. Raw shared (una volta): eseguire `myScript/m00_eventi_raw.mysql.sql`.
3. Init milestone: eseguire `mXX_*_01_init.mysql.sql`.
4. Acquisizione: raccogliere i dati grezzi con lo strumento previsto.
5. Extract to SAFENET: `mXX_*_02_extract_to_safenet.py` copia in DataSetGlobal
   e scrive `META/acquisition_meta.json`.
6. Validate: `mXX_*_02b_validate_safenet.py` verifica coerenza sorgente vs SAFENET.
7. Load: `mXX_*_03_probe_load_to_EVENTI_*.py` inserisce in EVENTI_* (supporto dry-run).
8. Raw mirror: EVENTI_RAW popolato insieme al load (solo se insert OK).
9. Post-check (opzionale): `mXX_*_04_*` per coerenza, conteggi, coverage.

## Contratto minimo (funzionalita standard)
- Struttura dataset:
  `DataSetGlobal/<source>/<device_or_account>/<tool_tag>/<run_id>/...`
- `META/acquisition_meta.json` sempre presente.
- Tabella `*_ACQUISITIONS` aggiornata con device/account label, run_id,
  tool_tag, percorsi e stato.
- Loader usa mapping in DEVICE_MASTER/ACCOUNT_MASTER e registra device_id/account_id
  quando disponibili.
- Loader MySQL inserisce anche in EVENTI_RAW (json lossless) dopo inserimento in EVENTI_*.
- Flags minimi consigliati: `--dataset-root`, `--mysql-host`, `--mysql-port`,
  `--mysql-user`, `--mysql-password`, `--mysql-database`, `--dry-run`.

## DB diagram (high-level)
```text
------------------------------+
| DEVICE_MASTER ACCOUNT_MASTER|
|        SCHEMA_VERSION       |
+--------------+--------------+
               |
       +-------+-------+
       | ACQUISITIONS  |
       +-------+-------+
               |
          +----+----+
          | EVENTI_*|
          +----+----+
               |
          +----+----+
          | EVENTI_RAW |
          +----+----+
               |
        TIMELINE_MASTER (planned)
```
Interactive diagram (hover for table info): `db_diagram_interactive.html`

## Milestone correnti
- M1 Windows Logs (fast-search schema, new dev):
  - DDL: `Milestones/M1_Windows_Logs/m1_windows_logs_01_init.mysql.sql`
  - Doc: `Milestones/M1_Windows_Logs/README.md`
- M01 Android ADB:
  - DDL: `m01_android_adb_01_init.sql`, `myScript/m01_android_adb_01_init.mysql.sql`
  - Seed device (opzionale): `m01_android_adb_01b_seed_DEVICE_MASTER.sql`
  - Extract/Validate/Load: `m01_android_adb_02_extract_to_safenet.py`,
    `m01_android_adb_02b_validate_safenet.py`,
    `m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py` (SQLite legacy).
  - Post-check: `m01_android_adb_04_validate_coherence.py`
- M02 Windows logs:
  - DDL: `m02_windows_logs_01_init.sql`, `myScript/m02_windows_logs_01_init.mysql.sql`
  - Triage: `m02_windows_logs_01_log_dump.py`
  - Extract/Load: `m02_windows_logs_02_extract_to_safenet.py`,
    `m02_windows_logs_03_probe_load_to_EVENTI_PC.py` (MySQL).
  - Coverage: `m02_windows_logs_04_build_event_type_pipelines_pre.py`
- M03 Takeout:
  - DDL: `m03_takeout_01_init.sql` (MySQL port in progress)
  - Runner: `m03_takeout_00_interactive_runner.py`
  - Extract/Validate/Load: `m03_takeout_02_extract_to_safenet.py`,
    `m03_takeout_02b_validate_safenet.py`,
    `m03_takeout_03_probe_load_to_EVENTI_ANDROID.py` (SQLite legacy).
- M04 Edge Local Forensic (da riallineare al contratto standard):
  - `m04_Edge_Local_Forensic_dump.*`, `m04_Edge_Local_Forensic_Validate.py`,
    `m04_Edge_Local_Forensic_INSERT_DB.py`, `m04_Edge_Local_Forensic_Insrt.sql`

## Doc
- `00_TUTORIAL_DB_FORENSIC.md`
- `M01_Android_ADB_README.md`
- `M03_Takeout_README.md`
