# UI Database Settings Overview

The milestone UI exposes a set of MySQL connection parameters inside the **Settings** modal. All fields are pre-populated with working defaults so the viewer immediately reflects the active configuration.

## Fields
- **Workspace folder** – root path for DataSetGlobal, Tools, and DbScripts. Default: `C:\SAFENET`.
- **MySQL host / port** – connection endpoint for the forensic database. Defaults: `127.0.0.1:3306`.
- **MySQL user / password / database** – credentials used by Python pipelines and SQL clients. Defaults: `forensic / forensic / forensic`.

Change any value and press **Save** to persist `forensic_config.json`; the UI refreshes the milestone list automatically. Use **Cancel** to exit without writing changes.

## Milestone Consistency
Each milestone card lists four core steps—Dump, Create Table, Load Data, Validate—mirroring the SQLite pipeline. When scripts move into dedicated folders, update the `script_path` fields so the UI keeps parity across all milestones.
