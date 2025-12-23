-- m02_windows_logs_01_init.sql
-- Inizializzazione DB per pipeline Windows logs (MySQL)
--  - Tabella WINDOWS_ACQUISITIONS (meta acquisizioni EVTX/CSV)
--  - Tabella EVENTI_PC (eventi logici da Security/System/Application/PowerShell/AMSI)
-- Richiede DEVICE_MASTER e ACCOUNT_MASTER gia' presenti.

-- ============================================================================
-- 1) Tabella WINDOWS_ACQUISITIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS WINDOWS_ACQUISITIONS (
  windows_acquisition_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id            INT UNSIGNED NOT NULL,      -- FK -> DEVICE_MASTER(device_id)
  run_id               VARCHAR(20) NOT NULL,       -- es. 20251123_233251
  log_type             VARCHAR(40) NOT NULL,       -- Security/System/Application/PowerShell/AMSI
  tool_name            VARCHAR(80) NOT NULL,       -- es. wevtutil_export
  tool_version         VARCHAR(20) NULL,
  source_path          TEXT NULL,                  -- path sorgente dump evtx/csv
  target_run_base      TEXT NULL,                  -- path SAFENET DataSetGlobal/windows_logs/.../run_id
  acquisition_time_utc TIMESTAMP NULL,             -- se ricavabile da run_id o meta
  validation_status    VARCHAR(20) NULL,           -- PENDING/OK/FAIL
  notes                TEXT NULL,
  PRIMARY KEY (windows_acquisition_id),
  UNIQUE KEY ux_win_acq_device_run_log_tool (device_id, run_id, log_type, tool_name),
  KEY idx_win_acq_device (device_id),
  CONSTRAINT fk_win_acq_device
    FOREIGN KEY (device_id) REFERENCES DEVICE_MASTER(device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 2) Tabella EVENTI_PC
-- ============================================================================
CREATE TABLE IF NOT EXISTS EVENTI_PC (
  pc_event_id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  timestamp_utc        TIMESTAMP NOT NULL,         -- timestamp evento (UTC o string grezza)
  device_id            INT UNSIGNED NOT NULL,      -- FK -> DEVICE_MASTER
  account_id           INT UNSIGNED NULL,          -- FK -> ACCOUNT_MASTER (se noto)
  account_name         VARCHAR(120) NULL,          -- eventuale nome account testuale
  source_log           VARCHAR(40) NULL,           -- Security/System/Application/PowerShell/AMSI
  event_code           INT NULL,                   -- EventID
  logon_type           VARCHAR(20) NULL,           -- per eventi di logon
  process_name         VARCHAR(260) NULL,          -- processo coinvolto
  command_line         TEXT NULL,                  -- cmdline se nota
  ip_src               VARCHAR(64) NULL,           -- ip sorgente (se dedotto)
  ip_dst               VARCHAR(64) NULL,           -- ip destinazione (se dedotto)
  ip_remoto            VARCHAR(64) NULL,           -- compatibilita' con altri loader
  description          TEXT NULL,                  -- messaggio evento
  extra_details        TEXT NULL,                  -- JSON/text libero per arricchimenti
  sospetto_flag        TINYINT(1) NOT NULL DEFAULT 0,
  motivazione_sospetto TEXT NULL,
  time_created         TIMESTAMP NULL,             -- eventuale timestamp originale
  PRIMARY KEY (pc_event_id),
  KEY idx_pc_evt_timestamp (timestamp_utc),
  KEY idx_pc_evt_device_time (device_id, timestamp_utc),
  KEY idx_pc_evt_code (event_code),
  KEY idx_pc_evt_source (source_log, event_code),
  CONSTRAINT fk_pc_evt_device
    FOREIGN KEY (device_id) REFERENCES DEVICE_MASTER(device_id),
  CONSTRAINT fk_pc_evt_account
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
