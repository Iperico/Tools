-- m01_android_adb_01_init.mysql.sql
-- MySQL 8+ version of the SQLite init for Milestone M01 (Android ADB).
-- Requires the bootstrap layer (DEVICE_MASTER, ACCOUNT_MASTER) already created.

SET NAMES utf8mb4;
USE forensic;

-- ============================================================================
-- 1) ANDROID_ACQUISITIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS ANDROID_ACQUISITIONS (
    acquisition_id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id            INT UNSIGNED NOT NULL,
    run_id               VARCHAR(32) NOT NULL,
    script_name          VARCHAR(80) NULL,
    script_version       VARCHAR(20) NULL,
    source_run_dir       TEXT NULL,
    target_run_base      TEXT NULL,
    acquisition_time_utc DATETIME NULL,
    notes                TEXT NULL,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (acquisition_id),
    UNIQUE KEY ux_android_acq_device_run_script (device_id, run_id, script_name, script_version),
    KEY idx_android_acq_device_time (device_id, acquisition_time_utc),
    CONSTRAINT fk_android_acq_device FOREIGN KEY (device_id)
        REFERENCES DEVICE_MASTER(device_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 2) EVENTI_ANDROID
-- ============================================================================
CREATE TABLE IF NOT EXISTS EVENTI_ANDROID (
    android_event_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    timestamp_utc        DATETIME NOT NULL,
    device_id            INT UNSIGNED NOT NULL,
    account_id           INT UNSIGNED NULL,
    product              VARCHAR(80) NULL,
    app                  VARCHAR(80) NULL,
    title                TEXT NULL,
    title_url            TEXT NULL,
    source_file          VARCHAR(260) NULL,
    ip_remoto            VARCHAR(64) NULL,
    extra_details        MEDIUMTEXT NULL,
    sospetto_flag        TINYINT(1) NOT NULL DEFAULT 0,
    motivazione_sospetto TEXT NULL,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (android_event_id),
    KEY idx_android_evt_timestamp (timestamp_utc),
    KEY idx_android_evt_device_time (device_id, timestamp_utc),
    KEY idx_android_evt_account_time (account_id, timestamp_utc),
    CONSTRAINT fk_android_evt_device FOREIGN KEY (device_id)
        REFERENCES DEVICE_MASTER(device_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_android_evt_account FOREIGN KEY (account_id)
        REFERENCES ACCOUNT_MASTER(account_id)
        ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
