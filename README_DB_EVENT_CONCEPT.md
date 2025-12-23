# SAFENET DB and Event Table Concept

## Purpose
This document explains the forensic database model and the event table pattern used by milestones.

## Core database layers (MySQL target)
- Stage 0 bootstrap creates: DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION.
- Each milestone adds one ACQUISITIONS table and one EVENTI_* table.
- Event tables are normalized, source-specific, and keyed by timestamp and device/account.
- A unified timeline can be built by linking EVENTI_* into TIMELINE_MASTER.
- EVIDENCE_INDEX ties evidence files to hosts/users and can enrich timeline views.


## DB architecture overview (graph)
```text
                 +------------------------------+
                 |          STAGE 0             |
                 | DEVICE_MASTER  ACCOUNT_MASTER|
                 |         SCHEMA_VERSION       |
                 +---------------+--------------+
                                 |
     +---------------------------+---------------------------+
     |                           |                           |
+----+-----------------+ +-------+----------------+ +--------+-----------------+
| ANDROID_ACQUISITIONS | | WINDOWS_ACQUISITIONS   | |  OTHER ACQUISITIONS...   |
+----------+-----------+ +-----------+------------+ +-----------+--------------+
           |                         |                          |
           v                         v                          v
+----------+-----------+ +-----------+------------+ +-----------+--------------+
|    EVENTI_ANDROID    | |     EVENTI_PC          | |  EVENTI_* (planned)       |
+----------+-----------+ +-----------+------------+ +-----------+--------------+
           |                         |                          |
           +-----------+-------------+-------------+------------+
                       v                           v
                 +-----+-------------------------------+
                 |         TIMELINE_MASTER (planned)   |
                 +-----+-------------------------------+
                       |
                       v
                 +-----+-------------------------------+
                 |            EVIDENCE_INDEX           |
                 +-------------------------------------+
```

## Event table pattern (common columns)
- timestamp_utc
- device_id
- account_id (nullable)
- ip_remoto (nullable)
- description or title
- extra_details (free text or JSON)
- sospetto_flag, motivazione_sospetto

## Milestone map (current and planned)
- Stage 0: mysql_forensic_init_optimized.sql -> DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION
- M01 Android ADB: myScript/m01_android_adb_01_init.mysql.sql -> ANDROID_ACQUISITIONS, EVENTI_ANDROID
- M02 Windows Logs: myScript/m02_windows_logs_01_init.mysql.sql -> WINDOWS_ACQUISITIONS, EVENTI_PC
- M03 Takeout (legacy SQLite scripts): m03_takeout_01_init.sql, m03_takeout_03_probe_load_to_EVENTI_ANDROID.py
- M04 Edge evidence (legacy SQLite schema): EVIDENCE_INDEX, TIMELINE views
- M05 Cloud (planned): EVENTI_CLOUD
- M06 Network (planned): EVENTI_RETE
- M07 Timeline (planned): TIMELINE_MASTER

## DB concept (ASCII)
```text
+-------------------+      +-------------------+
| DEVICE_MASTER     |      | ACCOUNT_MASTER    |
+-------------------+      +-------------------+
          |                        |
          |                        |
          v                        v
+-------------------+      +-------------------+
| ANDROID_ACQ       |      | WINDOWS_ACQ       |
+-------------------+      +-------------------+
          |                        |
          v                        v
+-------------------+      +-------------------+
| EVENTI_ANDROID    |      | EVENTI_PC         |
+-------------------+      +-------------------+
          |                        |
          |        +-------------------------------+
          +------> | TIMELINE_MASTER (planned)     | <------+
                   +-------------------------------+        |
          |                        |                        |
+-------------------+      +-------------------+            |
| EVENTI_CLOUD      |      | EVENTI_RETE       |            |
+-------------------+      +-------------------+            |
                   \           /                            |
                    v         v                             |
                 +-------------------+                      |
                 | EVIDENCE_INDEX    | (joins via views) ----+
                 +-------------------+
```

## Milestone pipeline (ASCII)
```text
Raw sources -> _02_extract_to_safenet -> DataSetGlobal -> _02b_validate
        -> _03_load_to_EVENTI_* -> EVENTI_* tables -> (optional) TIMELINE_MASTER

Stage 0 (bootstrap)
  |
  +-- M01 Android ADB -> EVENTI_ANDROID
  |
  +-- M02 Windows Logs -> EVENTI_PC
  |
  +-- M03 Takeout -> EVENTI_ANDROID (legacy SQLite)
  |
  +-- M04 Edge Evidence -> EVIDENCE_INDEX (legacy SQLite)
  |
  +-- M05 Cloud -> EVENTI_CLOUD (planned)
  |
  +-- M06 Network -> EVENTI_RETE (planned)
  |
  +-- M07 Timeline -> TIMELINE_MASTER (planned)
```

## Notes
- MySQL is the primary target for new development.
- SQLite artifacts remain as legacy or migration references until fully ported.
