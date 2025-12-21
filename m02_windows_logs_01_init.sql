-- m02_windows_logs_01_init.sql
-- Inizializzazione DB per pipeline Windows logs
--  - Tabella WINDOWS_ACQUISITIONS (meta acquisizioni EVTX/CSV)
--  - Tabella EVENTI_PC (eventi logici da Security/System/Application/PowerShell/AMSI)
-- Richiede DEVICE_MASTER e ACCOUNT_MASTER già presenti.

PRAGMA foreign_keys = ON;

-- ============================================================================
-- 1) Tabella WINDOWS_ACQUISITIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS WINDOWS_ACQUISITIONS (
    windows_acquisition_id INTEGER PRIMARY KEY,
    device_id            INTEGER NOT NULL,   -- FK -> DEVICE_MASTER(device_id)
    run_id               VARCHAR(20) NOT NULL,  -- es. 20251123_233251
    log_type             VARCHAR(40) NOT NULL,  -- Security/System/Application/PowerShell/AMSI
    tool_name            VARCHAR(80) NOT NULL,  -- es. wevtutil_export
    tool_version         VARCHAR(20),
    source_path          TEXT,                 -- path sorgente dump evtx/csv
    target_run_base      TEXT,                 -- path SAFENET DataSetGlobal/windows_logs/.../run_id
    acquisition_time_utc TIMESTAMP,            -- se ricavabile da run_id o meta
    validation_status    VARCHAR(20),          -- PENDING/OK/FAIL
    notes                TEXT,
    FOREIGN KEY (device_id) REFERENCES DEVICE_MASTER(device_id)
);

-- Evita duplicati: stessa run, stesso log_type e tool_name per device.
CREATE UNIQUE INDEX IF NOT EXISTS ux_win_acq_device_run_log_tool
ON WINDOWS_ACQUISITIONS (device_id, run_id, log_type, tool_name);

-- ============================================================================
-- 2) Tabella EVENTI_PC
-- ============================================================================
CREATE TABLE IF NOT EXISTS EVENTI_PC (
    pc_event_id          INTEGER PRIMARY KEY,
    timestamp_utc        TIMESTAMP NOT NULL,   -- timestamp evento (UTC o string grezza)
    device_id            INTEGER NOT NULL,     -- FK -> DEVICE_MASTER
    account_id           INTEGER,              -- FK -> ACCOUNT_MASTER (se noto)
    account_name         VARCHAR(120),         -- eventuale nome account testuale
    source_log           VARCHAR(40),          -- Security/System/Application/PowerShell/AMSI
    event_code           INTEGER,              -- EventID
    logon_type           VARCHAR(20),          -- per eventi di logon
    process_name         VARCHAR(260),         -- processo coinvolto
    command_line         TEXT,                 -- cmdline se nota
    ip_src               VARCHAR(64),          -- ip sorgente (se dedotto)
    ip_dst               VARCHAR(64),          -- ip destinazione (se dedotto)
    ip_remoto            VARCHAR(64),          -- compatibilità con altri loader
    description          TEXT,                 -- messaggio evento
    extra_details        TEXT,                 -- JSON/text libero per arricchimenti
    sospetto_flag        BOOLEAN DEFAULT 0,
    motivazione_sospetto TEXT,
    time_created         TIMESTAMP,            -- eventuale timestamp originale
    FOREIGN KEY (device_id)  REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id)
);

-- Indici per interrogazioni rapide
CREATE INDEX IF NOT EXISTS idx_pc_evt_timestamp
    ON EVENTI_PC (timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_pc_evt_device_time
    ON EVENTI_PC (device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_pc_evt_code
    ON EVENTI_PC (event_code);

CREATE INDEX IF NOT EXISTS idx_pc_evt_source
    ON EVENTI_PC (source_log, event_code);
