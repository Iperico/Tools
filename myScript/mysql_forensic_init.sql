-- Bootstrap MySQL environment for the SAFENET forensic platform.
-- Responsibilities:
--   * create the core database with UTF-8 defaults
--   * provision application users and privileges
--   * ensure shared master tables exist (used by every milestone)
--
-- Milestone-specific tables (EVENTI_*, *_ACQUISITIONS, etc.) belong in
-- their dedicated scripts under Tools/Milestones.

SET NAMES utf8mb4;

-- ---------------------------------------------------------------------------
-- 1. Create / configure database
-- ---------------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS forensic
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

ALTER DATABASE forensic
    CHARACTER SET = utf8mb4
    COLLATE = utf8mb4_unicode_ci;

USE forensic;

-- ---------------------------------------------------------------------------
-- 2. Create application users and privileges
--    Adjust passwords/hosts before running in production.
-- ---------------------------------------------------------------------------

CREATE USER IF NOT EXISTS 'safenet_admin'@'localhost'
    IDENTIFIED BY 'ChangeMe!2025';

CREATE USER IF NOT EXISTS 'safenet_admin'@'%'
    IDENTIFIED BY 'ChangeMe!2025';

GRANT ALL PRIVILEGES ON forensic.* TO 'safenet_admin'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON forensic.* TO 'safenet_admin'@'%';

FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------------
-- 3. Shared master tables
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS DEVICE_MASTER (
        device_id     INT UNSIGNED NOT NULL AUTO_INCREMENT,
        device_label  VARCHAR(80) NOT NULL,
        device_type   VARCHAR(40) NOT NULL DEFAULT 'generic',
        owner_label   VARCHAR(120),
        platform      VARCHAR(60),
        notes         TEXT,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (device_id),
        UNIQUE KEY ux_device_label (device_label)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ACCOUNT_MASTER (
        account_id    INT UNSIGNED NOT NULL AUTO_INCREMENT,
        account_label VARCHAR(80) NOT NULL,
        provider      VARCHAR(60) NOT NULL DEFAULT 'generic',
        display_name  VARCHAR(120),
        owner_label   VARCHAR(120),
        notes         TEXT,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (account_id),
        UNIQUE KEY ux_account_label (account_label)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- Tracks which milestone modules have been applied to this database.
CREATE TABLE IF NOT EXISTS SCHEMA_VERSION (
        module_name   VARCHAR(80) NOT NULL,
        version_label VARCHAR(40) NOT NULL,
        applied_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (module_name)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT IGNORE INTO SCHEMA_VERSION (module_name, version_label)
VALUES ('core-bootstrap', 'v1');
