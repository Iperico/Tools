-- m01_android_adb_01_init.sql
--
-- Inizializzazione DB per la pipeline Android ADB:
--  - Tabella ANDROID_ACQUISITIONS (meta delle acquisizioni ADB)
--  - Tabella EVENTI_ANDROID (contenitore eventi logici Android)
--
-- Nota: si assume che DEVICE_MASTER e ACCOUNT_MASTER esistano già.

PRAGMA foreign_keys = ON;

-- ============================================================================
-- 1) Tabella ANDROID_ACQUISITIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS ANDROID_ACQUISITIONS (
    acquisition_id       INTEGER PRIMARY KEY,
    device_id            INTEGER NOT NULL,      -- FK -> DEVICE_MASTER(device_id)
    run_id               VARCHAR(32) NOT NULL,  -- es. 20251129_031934
    script_name          VARCHAR(80),          -- es. 'android_log_dump'
    script_version       VARCHAR(20),          -- es. '0.2'
    source_run_dir       TEXT,                 -- path sorgente android_logs\...
    target_run_base      TEXT,                 -- path base in DataSetGlobal\...
    acquisition_time_utc TIMESTAMP,            -- se disponibile (nome run o meta)
    notes                TEXT,
    FOREIGN KEY (device_id) REFERENCES DEVICE_MASTER(device_id)
);

-- Evita duplicati logici: stessa run, stesso script e device.
CREATE UNIQUE INDEX IF NOT EXISTS ux_android_acq_device_run_script
ON ANDROID_ACQUISITIONS (device_id, run_id, script_name, script_version);


-- ============================================================================
-- 2) Tabella EVENTI_ANDROID
-- ============================================================================

CREATE TABLE IF NOT EXISTS EVENTI_ANDROID (
    android_event_id     INTEGER PRIMARY KEY,
    timestamp_utc        TIMESTAMP NOT NULL,   -- timestamp evento (UTC)
    device_id            INTEGER NOT NULL,     -- FK -> DEVICE_MASTER
    account_id           INTEGER,              -- FK -> ACCOUNT_MASTER (se noto)
    product              VARCHAR(80),          -- es. 'Android', 'YouTube', 'Chrome'
    app                  VARCHAR(80),          -- package / nome app
    title                TEXT,                 -- titolo evento (es. da My Activity / log)
    title_url            TEXT,                 -- URL associato (se esiste)
    source_file          VARCHAR(260),         -- file sorgente (logcat_xxx, dumpsys_yyy, ...)
    ip_remoto            VARCHAR(64),          -- IP remoto se estratto (es. da log connettività)
    extra_details        TEXT,                 -- JSON o testo con info extra
    sospetto_flag        BOOLEAN DEFAULT 0,
    motivazione_sospetto TEXT,
    FOREIGN KEY (device_id)  REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id)
);

-- Indici utili per le query forensi
CREATE INDEX IF NOT EXISTS idx_android_evt_timestamp
    ON EVENTI_ANDROID (timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_android_evt_device
    ON EVENTI_ANDROID (device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_android_evt_account
    ON EVENTI_ANDROID (account_id, timestamp_utc);

