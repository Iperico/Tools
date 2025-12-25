-- m00_eventi_raw.mysql.sql
-- Shared raw events table (MySQL 8+). Lossless storage for any milestone.
-- Requires bootstrap layer (DEVICE_MASTER, ACCOUNT_MASTER).
-- No FK to milestone acquisition tables to avoid ordering constraints.

SET NAMES utf8mb4;
USE forensic;

CREATE TABLE IF NOT EXISTS EVENTI_RAW (
    raw_event_id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    milestone_code         VARCHAR(20) NOT NULL,   -- e.g. M01, M02, M03
    device_id              INT UNSIGNED NOT NULL,
    account_id             INT UNSIGNED NULL,
    windows_acquisition_id BIGINT UNSIGNED NULL,
    android_acquisition_id BIGINT UNSIGNED NULL,
    takeout_acquisition_id BIGINT UNSIGNED NULL,
    source_log             VARCHAR(64) NULL,       -- Security/System/Application/...
    event_time_utc         DATETIME NULL,
    event_code             INT NULL,
    event_type             VARCHAR(64) NULL,       -- provider/category if available
    raw_format             VARCHAR(16) NOT NULL,   -- json
    raw_payload            LONGTEXT NOT NULL,      -- full raw row as json
    source_path            TEXT NULL,              -- dataset path to the raw file
    inserted_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (raw_event_id),
    KEY idx_raw_device_time (device_id, event_time_utc),
    KEY idx_raw_milestone (milestone_code),
    KEY idx_raw_source (source_log, event_code),
    KEY idx_raw_windows_acq (windows_acquisition_id),
    KEY idx_raw_android_acq (android_acquisition_id),
    KEY idx_raw_takeout_acq (takeout_acquisition_id),
    CONSTRAINT fk_raw_device FOREIGN KEY (device_id)
        REFERENCES DEVICE_MASTER(device_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_raw_account FOREIGN KEY (account_id)
        REFERENCES ACCOUNT_MASTER(account_id)
        ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
