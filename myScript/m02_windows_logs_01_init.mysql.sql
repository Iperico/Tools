-- m02_windows_logs_01_init.mysql.sql
-- MySQL 8+ version of the SQLite init for Milestone M02 (Windows logs).
-- Requires the bootstrap layer (DEVICE_MASTER, ACCOUNT_MASTER) already created.

SET NAMES utf8mb4;
USE forensic;

-- ============================================================================
-- 1) WINDOWS_ACQUISITIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS WINDOWS_ACQUISITIONS (
    windows_acquisition_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id              INT UNSIGNED NOT NULL,
    run_id                 VARCHAR(20) NOT NULL,   -- es. 20251123_233251
    log_type               VARCHAR(40) NOT NULL,   -- Security/System/Application/PowerShell/AMSI
    tool_name              VARCHAR(80) NOT NULL,   -- es. wevtutil_export
    tool_version           VARCHAR(20) NULL,
    source_path            TEXT NULL,
    target_run_base        TEXT NULL,
    acquisition_time_utc   DATETIME NULL,
    validation_status      VARCHAR(20) NULL,       -- PENDING/OK/FAIL
    notes                  TEXT NULL,
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (windows_acquisition_id),
    UNIQUE KEY ux_win_acq_device_run_log_tool (device_id, run_id, log_type, tool_name),
    KEY idx_win_acq_device_time (device_id, acquisition_time_utc),
    CONSTRAINT fk_win_acq_device FOREIGN KEY (device_id)
        REFERENCES DEVICE_MASTER(device_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 2) EVENTI_PC
-- Notes:
--  - include an optional event_fingerprint (sha256 hex) to allow dedup with UNIQUE.
-- ============================================================================
CREATE TABLE IF NOT EXISTS EVENTI_PC (
    pc_event_id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    timestamp_utc          DATETIME NOT NULL,
    device_id              INT UNSIGNED NOT NULL,
    account_id             INT UNSIGNED NULL,
    account_name           VARCHAR(120) NULL,
    source_log             VARCHAR(40) NULL,
    event_code             INT NULL,
    logon_type             VARCHAR(20) NULL,
    process_name           VARCHAR(260) NULL,
    command_line           MEDIUMTEXT NULL,
    ip_src                 VARCHAR(64) NULL,
    ip_dst                 VARCHAR(64) NULL,
    ip_remoto              VARCHAR(64) NULL,
    description            MEDIUMTEXT NULL,
    extra_details          MEDIUMTEXT NULL,
    sospetto_flag          TINYINT(1) NOT NULL DEFAULT 0,
    motivazione_sospetto   TEXT NULL,
    time_created           DATETIME NULL,
    event_fingerprint      CHAR(64) NULL, -- sha256 hex (optional)
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pc_event_id),
    KEY idx_pc_evt_timestamp (timestamp_utc),
    KEY idx_pc_evt_device_time (device_id, timestamp_utc),
    KEY idx_pc_evt_code (event_code),
    KEY idx_pc_evt_source (source_log, event_code),
    UNIQUE KEY ux_pc_evt_dedup (device_id, source_log, event_code, timestamp_utc, event_fingerprint),
    CONSTRAINT fk_pc_evt_device FOREIGN KEY (device_id)
        REFERENCES DEVICE_MASTER(device_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_pc_evt_account FOREIGN KEY (account_id)
        REFERENCES ACCOUNT_MASTER(account_id)
        ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
