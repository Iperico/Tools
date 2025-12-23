# Agents

## safenet-db-forensic
Purpose:
- Maintain the DB schema and event model for the SAFENET forensic pipeline.

Scope:
- Core bootstrap (DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION).
- Milestone tables (ACQUISITIONS + EVENTI_*).
- Timeline and evidence index concepts.

Inputs:
- mysql_forensic_init_optimized.sql
- myScript/m01_android_adb_01_init.mysql.sql
- myScript/m02_windows_logs_01_init.mysql.sql
- README.md
- 00_TUTORIAL_DB_FORENSIC.md

Rules:
- Prefer MySQL for new work.
- Treat SQLite as legacy or migration-only.
- Keep milestone DDL separate from bootstrap.

Outputs:
- SQL DDL and migration notes.
- ASCII diagrams of schema and milestones.
- Updates to docs under Tools/.
