-- m1_windows_logs_01_init.mysql.sql
-- Clean Windows Logs milestone with fast-search separation.
-- Requires bootstrap tables: DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION.

SET NAMES utf8mb4;
USE forensic;

-- ============================================================================
-- 1) Evidence catalog (per-file)
-- ============================================================================
CREATE TABLE IF NOT EXISTS WIN_EVIDENCE_FILE (
  evidence_id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  evidence_type      VARCHAR(40) NOT NULL,     -- evtx, log, json, csv
  file_path          VARCHAR(600) NOT NULL,
  file_hash_sha256   CHAR(64) NULL,
  file_size_bytes    BIGINT UNSIGNED NULL,
  collected_at_utc   DATETIME NULL,
  tool_name          VARCHAR(80) NULL,
  tool_version       VARCHAR(40) NULL,
  notes              TEXT NULL,
  created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (evidence_id),
  UNIQUE KEY ux_win_evidence_hash (file_hash_sha256),
  KEY idx_win_evidence_type (evidence_type),
  KEY idx_win_evidence_path (file_path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 2) Acquisition runs (one row per channel per run)
-- ============================================================================
CREATE TABLE IF NOT EXISTS WIN_LOG_ACQUISITION (
  win_acq_id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id          INT UNSIGNED NOT NULL,
  run_id             VARCHAR(24) NOT NULL,     -- e.g. 20251223_120501
  channel_name       VARCHAR(80) NOT NULL,     -- Security/System/Application
  tool_name          VARCHAR(80) NOT NULL,
  tool_version       VARCHAR(40) NULL,
  evidence_id        BIGINT UNSIGNED NULL,
  source_path        TEXT NULL,
  collected_at_utc   DATETIME NULL,
  validation_status  VARCHAR(20) NULL,         -- PENDING/OK/FAIL
  notes              TEXT NULL,
  created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (win_acq_id),
  UNIQUE KEY ux_win_acq_device_run_channel_tool (device_id, run_id, channel_name, tool_name),
  KEY idx_win_acq_device_time (device_id, collected_at_utc),
  CONSTRAINT fk_m1_win_acq_device FOREIGN KEY (device_id)
    REFERENCES DEVICE_MASTER(device_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT fk_m1_win_acq_evidence FOREIGN KEY (evidence_id)
    REFERENCES WIN_EVIDENCE_FILE(evidence_id)
    ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 3) Lookup tables for compact indexing
-- ============================================================================
CREATE TABLE IF NOT EXISTS WIN_LOG_CHANNEL (
  channel_id   SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  channel_name VARCHAR(80) NOT NULL,
  PRIMARY KEY (channel_id),
  UNIQUE KEY ux_win_channel_name (channel_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS WIN_EVENT_PROVIDER (
  provider_id   SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  provider_name VARCHAR(120) NOT NULL,
  PRIMARY KEY (provider_id),
  UNIQUE KEY ux_win_provider_name (provider_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS WIN_IP_ADDR (
  ip_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip_text    VARCHAR(64) NOT NULL,
  ip_bin     VARBINARY(16) NOT NULL,
  ip_version TINYINT UNSIGNED NOT NULL,
  PRIMARY KEY (ip_id),
  UNIQUE KEY ux_win_ip_bin (ip_bin),
  KEY idx_win_ip_text (ip_text)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 4) Fast-search core (compact, indexed)
-- ============================================================================
CREATE TABLE IF NOT EXISTS WIN_EVENT_CORE (
  win_event_id      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  timestamp_utc     DATETIME NOT NULL,
  device_id         INT UNSIGNED NOT NULL,
  account_id        INT UNSIGNED NULL,
  account_name      VARCHAR(120) NULL,
  win_acq_id        BIGINT UNSIGNED NULL,
  channel_id        SMALLINT UNSIGNED NULL,
  provider_id       SMALLINT UNSIGNED NULL,
  event_code        INT NULL,
  event_level       TINYINT NULL,
  task_code         INT NULL,
  opcode            INT NULL,
  record_id         BIGINT UNSIGNED NULL,
  process_id        INT NULL,
  thread_id         INT NULL,
  ip_src_id         BIGINT UNSIGNED NULL,
  ip_dst_id         BIGINT UNSIGNED NULL,
  port_src          INT NULL,
  port_dst          INT NULL,
  evidence_id       BIGINT UNSIGNED NULL,
  evidence_locator  VARCHAR(120) NULL,         -- line number, record id, etc.
  event_fingerprint CHAR(64) NULL,             -- sha256 hex (optional)
  is_suspect        TINYINT(1) NOT NULL DEFAULT 0,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (win_event_id),
  KEY idx_win_evt_time (timestamp_utc),
  KEY idx_win_evt_device_time (device_id, timestamp_utc),
  KEY idx_win_evt_account_time (account_id, timestamp_utc),
  KEY idx_win_evt_channel_code (channel_id, event_code),
  KEY idx_win_evt_ip_src (ip_src_id, timestamp_utc),
  KEY idx_win_evt_ip_dst (ip_dst_id, timestamp_utc),
  KEY idx_win_evt_evidence (evidence_id),
  KEY idx_win_evt_suspect (is_suspect, timestamp_utc),
  UNIQUE KEY ux_win_evt_dedup (device_id, channel_id, event_code, timestamp_utc, event_fingerprint),
  CONSTRAINT fk_m1_win_evt_device FOREIGN KEY (device_id)
    REFERENCES DEVICE_MASTER(device_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT fk_m1_win_evt_account FOREIGN KEY (account_id)
    REFERENCES ACCOUNT_MASTER(account_id)
    ON UPDATE RESTRICT ON DELETE SET NULL,
  CONSTRAINT fk_m1_win_evt_acq FOREIGN KEY (win_acq_id)
    REFERENCES WIN_LOG_ACQUISITION(win_acq_id)
    ON UPDATE RESTRICT ON DELETE SET NULL,
  CONSTRAINT fk_m1_win_evt_channel FOREIGN KEY (channel_id)
    REFERENCES WIN_LOG_CHANNEL(channel_id)
    ON UPDATE RESTRICT ON DELETE SET NULL,
  CONSTRAINT fk_m1_win_evt_provider FOREIGN KEY (provider_id)
    REFERENCES WIN_EVENT_PROVIDER(provider_id)
    ON UPDATE RESTRICT ON DELETE SET NULL,
  CONSTRAINT fk_m1_win_evt_ip_src FOREIGN KEY (ip_src_id)
    REFERENCES WIN_IP_ADDR(ip_id)
    ON UPDATE RESTRICT ON DELETE SET NULL,
  CONSTRAINT fk_m1_win_evt_ip_dst FOREIGN KEY (ip_dst_id)
    REFERENCES WIN_IP_ADDR(ip_id)
    ON UPDATE RESTRICT ON DELETE SET NULL,
  CONSTRAINT fk_m1_win_evt_evidence FOREIGN KEY (evidence_id)
    REFERENCES WIN_EVIDENCE_FILE(evidence_id)
    ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 5) Slow/verbose text payload (joined only when needed)
-- ============================================================================
CREATE TABLE IF NOT EXISTS WIN_EVENT_TEXT (
  win_event_id  BIGINT UNSIGNED NOT NULL,
  message       MEDIUMTEXT NULL,
  process_name  VARCHAR(260) NULL,
  command_line  MEDIUMTEXT NULL,
  details_text  MEDIUMTEXT NULL,
  details_json  JSON NULL,
  suspect_reason TEXT NULL,
  PRIMARY KEY (win_event_id),
  FULLTEXT KEY ft_win_evt_text (message, command_line, details_text),
  CONSTRAINT fk_m1_win_evt_text FOREIGN KEY (win_event_id)
    REFERENCES WIN_EVENT_CORE(win_event_id)
    ON UPDATE RESTRICT ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================================
-- 6) Schema tracker
-- ============================================================================
INSERT INTO SCHEMA_VERSION (module_name, version_label, applied_at_utc, applied_by, script_checksum)
SELECT 'm1-windows-logs-fast', 'v1', CURRENT_TIMESTAMP, CURRENT_USER(), NULL
ON DUPLICATE KEY UPDATE
  version_label = VALUES(version_label);
