-- m03_takeout_01_init.sql
--
-- Inizializza la tabella TAKEOUT_ACQUISITIONS per la pipeline Google Takeout.
-- Eseguire, ad esempio:
--   cd C:\SAFENET\DB
--   sqlite3 forensic.db ".read C:/SAFENET/Tools/m03_takeout_01_init.sql"

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
