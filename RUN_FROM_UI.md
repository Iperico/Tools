# Run SAFENET from UI (MySQL)

## Use this UI runner
- `milestone_ui_mysql_runner.py`

## Use this config
- `forensic_config_mysql_ui.json`  (rename to `forensic_config.json` next to the UI runner)

## Where to put files on your PC
Copy to `C:\SAFENET\Tools\`:
- milestone_ui_mysql_runner.py
- forensic_config.json  (renamed from forensic_config_mysql_ui.json)
- mysql_forensic_init_optimized.sql
- m01_*.py/.sql
- m02_*.py/.sql

## Run
```powershell
cd C:\SAFENET\Tools
python .\milestone_ui_mysql_runner.py
```

## In the UI
1) Settings → set Workspace folder = `C:\SAFENET`
2) Set mysql.exe path (if not in PATH):
   `C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe`
3) Credentials:
   - For Stage 0 (Bootstrap) you need a MySQL admin capable of CREATE DATABASE/USER.
   - After Bootstrap, switch to `safenet_ingest` for loaders, `safenet_admin` for schema updates.

## Known limitation (next step)
`m02_windows_logs_03_probe_load_to_EVENTI_PC.py` is SQLite-first.
Next step: port to MySQL (mysql-connector, %s placeholders, ON DUPLICATE KEY, dedup fingerprint).