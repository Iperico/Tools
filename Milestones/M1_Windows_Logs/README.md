# M1 Windows Logs (fast-search schema)

This milestone introduces a clean Windows Logs schema with functional names
and a fast-search separation between indexed fields and verbose payloads.

## Strategy (fast search)
- Keep `WIN_EVENT_CORE` compact and highly indexed for time/device/code filters.
- Store verbose text and JSON in `WIN_EVENT_TEXT` and join only when needed.
- Use lookup tables for channel/provider/IP to keep indexes small.
- Keep evidence files in a dedicated table and link events to raw sources.

## Apply
1) Run bootstrap: `mysql_forensic_init_optimized.sql`
2) Run milestone DDL: `Milestones/M1_Windows_Logs/m1_windows_logs_01_init.mysql.sql`

## Operations plan (runbook)
1) Register evidence files in `WIN_EVIDENCE_FILE` (path, hash, size, tool).
2) Insert acquisition runs in `WIN_LOG_ACQUISITION` (per channel/run).
3) Upsert lookup rows in `WIN_LOG_CHANNEL`, `WIN_EVENT_PROVIDER`, `WIN_IP_ADDR`.
4) Insert compact fields into `WIN_EVENT_CORE` (fast search).
5) Insert verbose payload into `WIN_EVENT_TEXT` (message/details JSON).
6) Validate coverage: counts per channel, evidence linkage, suspect flags.

## Extractor + ingestion skeleton
Script: `Milestones/M1_Windows_Logs/m1_windows_logs_ingest_skeleton.py`

Example (dry-run):
```bash
python Milestones/M1_Windows_Logs/m1_windows_logs_ingest_skeleton.py ^
  --csv-path "C:\SAFENET\DataSetGlobal\windows_logs\DEVICE\TOOL\RUN\LOGS\Security\Security.csv" ^
  --device-label "PC_ALE_01" ^
  --channel-name "Security" ^
  --run-id "20251223_120501" ^
  --evidence-path "C:\Evidence\Windows\Security.evtx" ^
  --compute-hash ^
  --dry-run
```

Notes:
- The extractor is a minimal CSV parser. Extend `_row_to_event` for your format.
- The MySQL writer uses `mysql-connector-python` (`pip install mysql-connector-python`).
- Use `--limit` to test small batches.

## Batch runner (read-only on dataset)
Script: `Milestones/M1_Windows_Logs/m1_windows_logs_batch_runner.py`

Example (dry-run + report):
```bash
python Milestones/M1_Windows_Logs/m1_windows_logs_batch_runner.py ^
  --hash-evidence ^
  --report-path "C:\SAFENET\Reports\m1_windows_logs_ingest.json" ^
  --dry-run
```

Notes:
- Scans `LOGS/<channel>` and ingests CSV files without modifying dataset files.
- All CSV files under each channel folder are ingested (provider-specific exports included).
- `--dataset-root` defaults to the path in `forensic_config.json` (or `C:\SAFENET\DataSetGlobal\windows_logs`).
- MySQL connection defaults to `forensic_config.json` when CLI flags are omitted.
- `--evidence-prefer auto` picks EVTX if available, otherwise the CSV file.
- Use `--continue-on-error` to keep processing if one file fails.

## Validate counts (CSV rows vs DB rows)
Script: `Milestones/M1_Windows_Logs/m1_windows_logs_validate_counts.py`

Example:
```bash
python Milestones/M1_Windows_Logs/m1_windows_logs_validate_counts.py ^
  --channel-name Security ^
  --report-path "C:\SAFENET\Reports\m1_windows_logs_validate.json"
```

Notes:
- Counts CSV rows (header excluded) and compares to `WIN_EVENT_CORE` rows per acquisition.
- Uses `WIN_LOG_ACQUISITION` to map (device, run, channel, tool) -> DB rows.
- `--strict` returns exit code 2 if mismatches are found.

## Tables (summary)
- `WIN_EVIDENCE_FILE`: catalog of raw evidence files (path, hash, size).
- `WIN_LOG_ACQUISITION`: one row per channel per acquisition run.
- `WIN_LOG_CHANNEL`: lookup for channel names (Security/System/...).
- `WIN_EVENT_PROVIDER`: lookup for provider names.
- `WIN_IP_ADDR`: lookup for IPs (text + binary).
- `WIN_EVENT_CORE`: fast-search event core (indexed, compact).
- `WIN_EVENT_TEXT`: verbose text payload (FULLTEXT).

## ASCII diagram
```text
DEVICE_MASTER ----< WIN_LOG_ACQUISITION >---- WIN_EVIDENCE_FILE
DEVICE_MASTER ----< WIN_EVENT_CORE >---- WIN_EVENT_TEXT
ACCOUNT_MASTER ----< WIN_EVENT_CORE
WIN_LOG_CHANNEL ----< WIN_EVENT_CORE
WIN_EVENT_PROVIDER ----< WIN_EVENT_CORE
WIN_IP_ADDR ----< WIN_EVENT_CORE (ip_src_id, ip_dst_id)
WIN_EVIDENCE_FILE ----< WIN_EVENT_CORE
```

## Notes
- Use `WIN_EVENT_CORE` for fast timeline queries.
- Join `WIN_EVENT_TEXT` only for message/details views or fulltext search.
- Evidence traceability is via `WIN_EVIDENCE_FILE` + `evidence_id`.
