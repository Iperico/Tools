# DB Forensic – README generale

Questo README descrive in breve la strategia di costruzione del database forense, i passi standard della pipeline e dove trovare gli script principali.

## Strategia in sintesi
- Milestone per sorgente (M01 Android ADB, M02 Windows logs, poi Takeout/Drive/Gmail…).
- Ogni sorgente segue lo stesso schema: init SQL → estrazione in SAFENET → validazione → caricamento su tabelle EVENTI_*.
- Directory convenzionali: `C:/SAFENET/DB/forensic.db` per il DB, `C:/SAFENET/DataSetGlobal/...` per i dati normalizzati, `C:/SAFENET/Tools/` per script e SQL.
- Tabelle di base (da `DEVICE_MASTER` e `ACCOUNT_MASTER`) già esistenti o da creare a parte.

## Pipeline (ASCII)
```text
Sorgenti grezze                     SAFENET                  Database forense
(dump ADB, evtx, ecc.)              DataSetGlobal            forensic.db (SQLite)
    |                                   |                          |
    |  _02_extract_*                    |                          |
    +--> normalizza e copia --------> [RAW/META/...]               |
    |                                   |                          |
    |  _02b_validate_*                  |                          |
    +--> confronta sorgente e SAFENET   |                          |
    |                                   v                          |
    |                            (pronto per load)                 |
    |                                   |  _03_load_*              |
    +-----------------------------------+------------------------->+--> ACQUISITIONS
                                        |                          \--> EVENTI_*
```

Legenda (per ogni sorgente):
- `_01_init.sql`: crea/accenta le tabelle dedicate (ACQUISITIONS, EVENTI_*).
- `_02_extract_to_safenet.py`: copia/riorganizza i dump grezzi in `DataSetGlobal` e registra l’acquisizione.
- `_02b_validate_safenet.py`: controlli di integrità tra sorgente e copia normalizzata.
- `_03_load_to_EVENTI_*.py`: parsing e traduzione in eventi logici nel DB.

## Milestone attuali
- **M01 Android ADB**: tabelle [Tools/m01_android_adb_01_init.sql](Tools/m01_android_adb_01_init.sql), estrazione [Tools/m01_android_adb_02_extract_to_safenet.py](Tools/m01_android_adb_02_extract_to_safenet.py), validazione [Tools/m01_android_adb_02b_validate_safenet.py](Tools/m01_android_adb_02b_validate_safenet.py), caricamento previsto [Tools/m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py](Tools/m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py).
- **M02 Windows logs**:
    - Init SQL [Tools/m02_windows_logs_01_init.sql](Tools/m02_windows_logs_01_init.sql): crea `WINDOWS_ACQUISITIONS` e `EVENTI_PC` con indici.
    - Raccolta/triage locale [Tools/m02_windows_logs_01_log_dump.py](Tools/m02_windows_logs_01_log_dump.py) per esportare/riassumere EVTX/CSV (report markdown/CSV).
    - Normalizzazione in SAFENET [Tools/m02_windows_logs_02_extract_to_safenet.py](Tools/m02_windows_logs_02_extract_to_safenet.py): attende sorgenti `<device_label>_<run_id>/EVTX/...` e popola `DataSetGlobal/windows_logs/<device_label>/<tool_tag>/<run_id>/` con `META`, `LOGS/<Security|System|Application|PowerShell|AMSI>`, `RAW_ALL`; registra l'acquisizione se DB passato.
    - Probe/ingest [Tools/m02_windows_logs_03_probe_load_to_EVENTI_PC.py](Tools/m02_windows_logs_03_probe_load_to_EVENTI_PC.py): legge i CSV normalizzati e inserisce in `EVENTI_PC` (filtri per `--source-log`, `--event-code`, `--device-label`, supporto `--dry-run`).
    - Analisi copertura [Tools/m02_windows_logs_04_build_event_type_pipelines_pre.py](Tools/m02_windows_logs_04_build_event_type_pipelines_pre.py): genera `event_type_pipelines.json` con i tipi di evento più popolati (per costruire pipeline ETL mirate).
- Milestone future: Takeout/My Activity, Drive, Gmail, TIMELINE_MASTER (schema analogo con prefissi m03, m04, m05…).

## Passi consigliati per costruire il DB
1. Creare/aggiungere il DB: `sqlite3 forensic.db` in `C:/SAFENET/DB`.
2. Eseguire i file `_01_init.sql` rilevanti per la sorgente.
3. Lanciare lo script `_02_extract_to_safenet.py` con `--source`, `--target` e `--db` per popolare `DataSetGlobal` e registrare l’acquisizione.
4. Eseguire `_02b_validate_safenet.py` per assicurare coerenza tra sorgente e copia.
5. Usare `_03_load_to_EVENTI_*.py` per popolare le tabelle EVENTI_* a partire dai file normalizzati.

## Note operative
- Tenere separati i percorsi sorgente originali (sola lettura) dalla destinazione `DataSetGlobal`.
- Versionare gli script in `Tools/` e non modificare i dump sorgente.
- Aggiornare `00_TUTORIAL_DB_FORENSIC.md` quando cambia la sequenza operativa di una milestone.
