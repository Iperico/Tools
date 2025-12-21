# MySQL Schema Strategy

This folder holds the MySQL bootstrap assets shared across the SAFENET project.

## Goals
- Provision the `forensic` database with UTF-8 defaults and baseline configuration.
- Create service accounts with the least effort (admins can harden credentials afterwards).
- Install common master tables (`DEVICE_MASTER`, `ACCOUNT_MASTER`) and the `SCHEMA_VERSION` tracker used by every milestone.

## Workflow Pattern
1. Execute `mysql_forensic_init.sql` with a privileged account to create the database, users, and shared tables.
2. Follow `MySQL_SETUP.md` to validate the baseline and switch to the application account.
3. Apply milestone-specific SQL (for example `m01_android_adb_01_init.sql`) to introduce acquisition or event tables relevant to that pipeline.
4. Keep milestone scripts responsible for their full lifecycle—Dump, Create Table, Load Data, Validate—so each data source remains encapsulated.

Future bootstrap changes should extend this approach without duplicating milestone logic.
