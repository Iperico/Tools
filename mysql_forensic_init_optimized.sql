-- mysql_forensic_init_optimized.sql
-- Bootstrap MySQL environment for the SAFENET forensic platform.
-- Stage 0 (bootstrap) is intentionally small and stable:
--   * creates the core database with UTF‑8 defaults
--   * provisions service accounts (admin / ingest / read-only)
--   * installs shared master tables used by every milestone
--   * installs SCHEMA_VERSION tracker for auditability
--
-- Security stance (opinionated defaults):
--   - No wildcard host ('%') users by default.
--   - Loader pipelines should NOT run as admin; use safenet_ingest.
--   - Keep milestone DDL out of bootstrap (lives in milestone folders).
--
-- Tested for MySQL 8.0+

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

-- ---------------------------------------------------------------------------
-- 1) Create / configure database
-- ---------------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS forensic
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

ALTER DATABASE forensic
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

USE forensic;

-- Optional: make data quality failures loud (avoid silent truncations)
-- (comment out if you have legacy loads that rely on permissive behavior)
SET SESSION sql_mode = CONCAT_WS(',',
  'STRICT_TRANS_TABLES',
  'ERROR_FOR_DIVISION_BY_ZERO',
  'NO_ZERO_DATE',
  'NO_ZERO_IN_DATE',
  'ONLY_FULL_GROUP_BY'
);

-- ---------------------------------------------------------------------------
-- 2) Create service accounts (adjust passwords before use!)
-- ---------------------------------------------------------------------------
-- IMPORTANT:
-- - safenet_admin: DDL / migrations / bootstrap only
-- - safenet_ingest: used by Python loaders (INSERT/UPDATE/SELECT)
-- - safenet_ro: read-only reporting

CREATE USER IF NOT EXISTS 'safenet_admin'@'localhost'
  IDENTIFIED BY 'ChangeMe!2025';

CREATE USER IF NOT EXISTS 'safenet_ingest'@'localhost'
  IDENTIFIED BY 'ChangeMe!2025';

CREATE USER IF NOT EXISTS 'safenet_ro'@'localhost'
  IDENTIFIED BY 'ChangeMe!2025';

-- If you REALLY need remote connections, prefer a specific host/IP instead of '%'.
-- Example:
--   CREATE USER IF NOT EXISTS 'safenet_ingest'@'127.0.0.1' IDENTIFIED BY 'ChangeMe!2025';
--   CREATE USER IF NOT EXISTS 'safenet_ro'@'127.0.0.1' IDENTIFIED BY 'ChangeMe!2025';
-- Or a fixed LAN IP:
--   CREATE USER IF NOT EXISTS 'safenet_ingest'@'192.168.1.10' IDENTIFIED BY 'ChangeMe!2025';

-- Privileges
-- Admin can do everything on the schema (including DDL).
GRANT ALL PRIVILEGES ON forensic.* TO 'safenet_admin'@'localhost' WITH GRANT OPTION;

-- Ingest can read/write but not do schema changes.
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE TEMPORARY TABLES
  ON forensic.* TO 'safenet_ingest'@'localhost';

-- Read-only for dashboards/queries.
GRANT SELECT, SHOW VIEW
  ON forensic.* TO 'safenet_ro'@'localhost';

FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------------
-- 3) Shared master tables (canonical references for all milestones)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS DEVICE_MASTER (
  device_id     INT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_label  VARCHAR(80)  NOT NULL,
  device_type   VARCHAR(40)  NOT NULL DEFAULT 'generic',
  owner_label   VARCHAR(120) NULL,
  platform      VARCHAR(60)  NULL,
  notes         TEXT         NULL,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP    NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (device_id),
  UNIQUE KEY ux_device_label (device_label),
  KEY ix_device_type (device_type),
  KEY ix_owner_label (owner_label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS ACCOUNT_MASTER (
  account_id    INT UNSIGNED NOT NULL AUTO_INCREMENT,
  account_label VARCHAR(80)  NOT NULL,
  provider      VARCHAR(60)  NOT NULL DEFAULT 'generic',
  display_name  VARCHAR(120) NULL,
  owner_label   VARCHAR(120) NULL,
  notes         TEXT         NULL,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP    NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (account_id),
  UNIQUE KEY ux_account_label (account_label),
  KEY ix_provider (provider),
  KEY ix_owner_label (owner_label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Tracks which modules have been applied to this database.
-- Extras for audit:
--   applied_by: current MySQL user running the script
--   script_checksum: optional SHA256 of the SQL script (fill externally if desired)
CREATE TABLE IF NOT EXISTS SCHEMA_VERSION (
  module_name     VARCHAR(80)  NOT NULL,
  version_label   VARCHAR(40)  NOT NULL,
  applied_at_utc  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  applied_by      VARCHAR(128) NULL,
  script_checksum CHAR(64)     NULL,
  PRIMARY KEY (module_name),
  KEY ix_applied_at (applied_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Idempotent insert (if already present, keep history consistent)
INSERT INTO SCHEMA_VERSION (module_name, version_label, applied_at_utc, applied_by, script_checksum)
SELECT 'core-bootstrap', 'v2', CURRENT_TIMESTAMP, CURRENT_USER(), NULL
ON DUPLICATE KEY UPDATE
  version_label = VALUES(version_label);

-- Restore session settings
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
