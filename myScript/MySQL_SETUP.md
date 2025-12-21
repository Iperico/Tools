# MySQL Setup Guide

This guide explains how to bootstrap the SAFENET MySQL environment with the `mysql_forensic_init.sql` script. The script provisions the database, creates service accounts, and installs shared master tables while milestone-specific DDL stays in the milestone folders.

---

## 1. Prerequisites

- MySQL Server 8.0 (or compatible) installed and running.
- Administrative credentials (for example `root`) to create databases and users.
- MySQL Shell or the classic `mysql` CLI available in `PATH`.
- Ability to run commands as a privileged account (for example `root`).

---

## 2. Run the Bootstrap Script (as root)

```bash
mysql -u root -p < C:\SAFENET\Tools\myScript\mysql_forensic_init.sql
```

The script performs the following:
- Creates/updates the `forensic` database with UTF-8 defaults.
- Creates the service account `safenet_admin` (both `localhost` and `%` hosts) with a placeholder password `ChangeMe!2025`.
- Grants full privileges on the `forensic` schema to that account.
- Creates shared tables `DEVICE_MASTER`, `ACCOUNT_MASTER`, and the `SCHEMA_VERSION` tracker.

Change the password before deploying to production. Adjust host patterns if the application connects from fixed IPs only.

---

## 3. Verify the Baseline

From a terminal, execute:

```bash
mysql -u safenet_admin -p forensic
```


Inside the prompt:

```sql
SHOW TABLES;
SELECT * FROM SCHEMA_VERSION;
DESCRIBE DEVICE_MASTER;
DESCRIBE ACCOUNT_MASTER;
```

You should see the `core-bootstrap` entry in `SCHEMA_VERSION` and the master tables available. Each milestone script (for example `m01_android_adb_01_init.sql`) can now append its own objects.

---

## 4. Python Connection Snippet

```python
import mysql.connector

cnx = mysql.connector.connect(
    host="localhost",
    user="safenet_admin",
    password="ChangeMe!2025",
    database="forensic",
    charset="utf8mb4"
)

try:
    with cnx.cursor(dictionary=True) as cur:
        cur.execute("SELECT COUNT(*) AS total FROM DEVICE_MASTER")
        print(cur.fetchone())
finally:
    cnx.close()
```

Install the driver with `pip install mysql-connector-python` if it is not already available.

---

## 5. Migrating Data from SQLite (Outline)

1. Export the data you need from SQLite, for example using `.mode csv` and `.once`.
2. Import the CSV into MySQL using `LOAD DATA INFILE` or the MySQL Workbench import wizard.
3. Verify foreign keys and constraints after the load.

This migration step should be scripted once the production workflow is defined.

---

## 6. Next Steps

- Run the milestone-specific SQL scripts after this bootstrap to install their tables.
- Document credential storage (dotenv, secret manager) before deploying automation scripts.
