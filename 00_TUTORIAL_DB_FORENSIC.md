# DB FORENSIC - TUTORIAL AND ROADMAP (MySQL first)

Questo file descrive come usare il progetto DB FORENSIC per milestone.
MySQL e' il riferimento per il lavoro nuovo, SQLite e' legacy.

## 0. Prerequisiti generali
- Python 3.x disponibile in PATH.
- MySQL client (`mysql`) disponibile in PATH.
- SQLite CLI solo se devi usare script legacy (`sqlite3`).
- Struttura directory consigliata:

```text
C:\SAFENET\
  DataSetGlobal\     <-- dataset normalizzati
  DB\                <-- DB legacy SQLite (se serve)
  Tools\             <-- script e SQL
```

## 1. Bootstrap core (una volta)
Il bootstrap crea DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION.

Script principali:
- `mysql_forensic_init_optimized.sql`
- `myScript/mysql_forensic_init.sql`

Esempio MySQL:

```bash
mysql -h 127.0.0.1 -P 3306 -u forensic -p forensic < C:\SAFENET\Tools\mysql_forensic_init_optimized.sql
```

Nota: il DDL delle milestone e' separato e va eseguito per ogni sorgente.

## 2. Procedura standard per ogni milestone (runbook)
1. Init milestone: eseguire `mXX_*_01_init.mysql.sql`.
2. Acquisizione: raccogliere i dati grezzi con lo strumento previsto.
3. Extract to SAFENET: `mXX_*_02_extract_to_safenet.py`.
4. Validate: `mXX_*_02b_validate_safenet.py` (exit code nonzero se mismatch).
5. Load: `mXX_*_03_probe_load_to_EVENTI_*.py`.
6. Post-check (opzionale): `mXX_*_04_*` per coerenza/coverage.

Flags MySQL consigliati per i loader:
- `--mysql-host`, `--mysql-port`, `--mysql-user`, `--mysql-password`, `--mysql-database`
- `--dataset-root`, `--dry-run`, `--limit-per-run` (quando presenti)

## 2.1. Grafo DB e esempi (3 righe per tabella)
Nota: esempi sintetici per controllo umano (non dati reali). Colonne ridotte alle chiavi principali.

Grafo (relazioni principali):
```text
[DEVICE_MASTER] 1---< [ANDROID_ACQUISITIONS]
[DEVICE_MASTER] 1---< [WINDOWS_ACQUISITIONS]
[DEVICE_MASTER] 1---< [EVENTI_ANDROID]
[DEVICE_MASTER] 1---< [EVENTI_PC]
[ACCOUNT_MASTER] 1---< [EVENTI_ANDROID]
[ACCOUNT_MASTER] 1---< [EVENTI_PC]
[ACCOUNT_MASTER] 1---< [TAKEOUT_ACQUISITIONS] (SQLite legacy)
[SCHEMA_VERSION] (audit, no FK)
```

Esempi (3 righe per tabella):
```text
DEVICE_MASTER
+-----------+--------------+------------+----------+
| device_id | device_label | device_type| platform |
+-----------+--------------+------------+----------+
| 1         | ANDR_IO_S24  | phone      | Android  |
| 2         | PC_ALE_01    | PC         | Windows  |
| 3         | LAP_MAR_01   | laptop     | Windows  |
+-----------+--------------+------------+----------+

ACCOUNT_MASTER
+-----------+---------------+----------+-------------+
| account_id| account_label | provider | owner_label |
+-----------+---------------+----------+-------------+
| 1         | ACC_OMI_MAIN  | google   | Omi         |
| 2         | ACC_ALE_WORK  | google   | Ale         |
| 3         | ACC_TEST_01   | generic  | Lab         |
+-----------+---------------+----------+-------------+

SCHEMA_VERSION
+--------------+--------------+---------------------+---------------+
| module_name  | version_label| applied_at_utc      | applied_by    |
+--------------+--------------+---------------------+---------------+
| core-bootstrap | v2         | 2025-01-10 10:15:00 | safenet_admin |
| m01-android  | v1           | 2025-01-12 09:30:00 | safenet_admin |
| m02-windows  | v1           | 2025-01-12 10:00:00 | safenet_admin |
+--------------+--------------+---------------------+---------------+

ANDROID_ACQUISITIONS
+----------------+----------+---------------+-----------------------+---------------------+
| acquisition_id | device_id| run_id        | script_name           | acquisition_time_utc|
+----------------+----------+---------------+-----------------------+---------------------+
| 1              | 1        | 20250110_1015 | android_log_dump_0.2  | 2025-01-10 10:20:00 |
| 2              | 1        | 20250111_0830 | android_log_dump_0.2  | 2025-01-11 08:35:00 |
| 3              | 1        | 20250112_0905 | android_log_dump_0.2  | 2025-01-12 09:10:00 |
+----------------+----------+---------------+-----------------------+---------------------+

EVENTI_ANDROID
+-----------------+---------------------+----------+-----------+---------+-----------+------------------------+
| android_event_id| timestamp_utc       | device_id| account_id| product | app       | title                  |
+-----------------+---------------------+----------+-----------+---------+-----------+------------------------+
| 1               | 2025-01-10 10:21:10 | 1        | 1         | SYSTEM  | logcat    | ActivityManager start  |
| 2               | 2025-01-10 10:22:05 | 1        | 1         | SYSTEM  | logcat    | Network change         |
| 3               | 2025-01-11 08:40:12 | 1        | 2         | PLAY    | com.app.x | App install            |
+-----------------+---------------------+----------+-----------+---------+-----------+------------------------+

WINDOWS_ACQUISITIONS
+----------------------+----------+--------------+----------+-----------+---------------------+
| windows_acquisition_id| device_id| run_id       | log_type | tool_name | acquisition_time_utc|
+----------------------+----------+--------------+----------+-----------+---------------------+
| 1                    | 2        | 20250110_1200| Security | wevtutil  | 2025-01-10 12:05:00 |
| 2                    | 2        | 20250110_1200| System   | wevtutil  | 2025-01-10 12:05:00 |
| 3                    | 3        | 20250111_0745| Security | wevtutil  | 2025-01-11 07:50:00 |
+----------------------+----------+--------------+----------+-----------+---------------------+

EVENTI_PC
+-------------+---------------------+----------+-----------+-----------+------------+
| pc_event_id | timestamp_utc       | device_id| account_id| source_log| event_code |
+-------------+---------------------+----------+-----------+-----------+------------+
| 1           | 2025-01-10 12:10:01 | 2        | 2         | Security  | 4624       |
| 2           | 2025-01-10 12:12:44 | 2        | 2         | Security  | 4634       |
| 3           | 2025-01-11 08:02:10 | 3        | 3         | System    | 7001       |
+-------------+---------------------+----------+-----------+-----------+------------+

TAKEOUT_ACQUISITIONS (SQLite legacy)
+-----------+-----------+---------------+---------------------+-------------+
| takeout_id| account_id| takeout_label | acquisition_ts_utc  | tool_version|
+-----------+-----------+---------------+---------------------+-------------+
| 1         | 1         | takeout_202501| 2025-01-10 18:00:00 | v1          |
| 2         | 1         | takeout_202502| 2025-02-15 09:30:00 | v1          |
| 3         | 2         | takeout_202503| 2025-03-01 14:20:00 | v1          |
+-----------+-----------+---------------+---------------------+-------------+
`" + 
 + 
 + 
- MySQL: `myScript/m01_android_adb_01_init.mysql.sql`
- SQLite legacy: `m01_android_adb_01_init.sql`

Esempi:

```bash
python C:\SAFENET\Tools\m01_android_adb_02_extract_to_safenet.py ^
  --android-logs-root "D:\Evidence\ANDROID_Mobile\android_logs" ^
  --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs"
```

```bash
python C:\SAFENET\Tools\m01_android_adb_02b_validate_safenet.py ^
  --android-logs-root "D:\Evidence\ANDROID_Mobile\android_logs" ^
  --dataset-root "C:\SAFENET\DataSetGlobal\android_adb_logs"
```

Loader attuale:
- `m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py` e' SQLite legacy.
  Porting MySQL richiesto per allinearsi allo standard.

Post-check:
- `m01_android_adb_04_validate_coherence.py`
## 4. M02 - Windows logs
DDL:
- MySQL: `myScript/m02_windows_logs_01_init.mysql.sql`
- SQLite legacy: `m02_windows_logs_01_init.sql`

Triage locale:

```bash
python C:\SAFENET\Tools\m02_windows_logs_01_log_dump.py ^
  --source "D:\Evidence\WINDOWS_Logs" ^
  --out "C:\SAFENET\Reports\windows_logs"
```

Extract:

```bash
python C:\SAFENET\Tools\m02_windows_logs_02_extract_to_safenet.py ^
  --source "D:\Evidence\WINDOWS_Logs" ^
  --target "C:\SAFENET\DataSetGlobal\windows_logs"
```

Load (MySQL):

```bash
python C:\SAFENET\Tools\m02_windows_logs_03_probe_load_to_EVENTI_PC.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\windows_logs" ^
  --mysql-host 127.0.0.1 ^
  --mysql-port 3306 ^
  --mysql-user forensic ^
  --mysql-password "..." ^
  --mysql-database forensic ^
  --source-log Security ^
  --limit-per-run 100 ^
  --dry-run
```

Post-check:
- `m02_windows_logs_04_build_event_type_pipelines_pre.py`

## 5. M03 - Takeout
DDL:
- `m03_takeout_01_init.sql` (porting MySQL in progress)

Runner:
- `m03_takeout_00_interactive_runner.py`

Extract/Validate/Load:
- `m03_takeout_02_extract_to_safenet.py`
- `m03_takeout_02b_validate_safenet.py`
- `m03_takeout_03_probe_load_to_EVENTI_ANDROID.py` (SQLite legacy)

## 6. Milestone future
- M04 Edge Local Forensic (da riallineare al contratto standard)
- M05 Gmail
- M06 TIMELINE_MASTER

## 7. UI runner (opzionale)
Per eseguire gli step da UI:
- `milestone_ui_mysql_runner.py`
- Configurazione: `forensic_config.json`













