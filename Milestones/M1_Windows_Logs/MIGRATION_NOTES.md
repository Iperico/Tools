# Migration notes (M02 -> M1 Windows Logs fast schema)

Source DDL: `myScript/m02_windows_logs_01_init.mysql.sql`
Target DDL: `Milestones/M1_Windows_Logs/m1_windows_logs_01_init.mysql.sql`

## Table mapping
- `WINDOWS_ACQUISITIONS` -> `WIN_LOG_ACQUISITION`
- `EVENTI_PC` -> `WIN_EVENT_CORE` + `WIN_EVENT_TEXT`

## Field mapping (core)
- `WINDOWS_ACQUISITIONS.device_id` -> `WIN_LOG_ACQUISITION.device_id`
- `WINDOWS_ACQUISITIONS.run_id` -> `WIN_LOG_ACQUISITION.run_id`
- `WINDOWS_ACQUISITIONS.log_type` -> `WIN_LOG_ACQUISITION.channel_name`
- `WINDOWS_ACQUISITIONS.tool_name` -> `WIN_LOG_ACQUISITION.tool_name`
- `WINDOWS_ACQUISITIONS.tool_version` -> `WIN_LOG_ACQUISITION.tool_version`
- `WINDOWS_ACQUISITIONS.source_path` -> `WIN_LOG_ACQUISITION.source_path`
- `WINDOWS_ACQUISITIONS.acquisition_time_utc` -> `WIN_LOG_ACQUISITION.collected_at_utc`
- `WINDOWS_ACQUISITIONS.validation_status` -> `WIN_LOG_ACQUISITION.validation_status`

- `EVENTI_PC.timestamp_utc` -> `WIN_EVENT_CORE.timestamp_utc`
- `EVENTI_PC.device_id` -> `WIN_EVENT_CORE.device_id`
- `EVENTI_PC.account_id` -> `WIN_EVENT_CORE.account_id`
- `EVENTI_PC.account_name` -> `WIN_EVENT_CORE.account_name`
- `EVENTI_PC.source_log` -> `WIN_LOG_CHANNEL.channel_name` -> `WIN_EVENT_CORE.channel_id`
- `EVENTI_PC.event_code` -> `WIN_EVENT_CORE.event_code`
- `EVENTI_PC.time_created` -> `WIN_EVENT_CORE.record_id` (if this is a record id) or `details_json.time_created`
- `EVENTI_PC.ip_src/ip_dst` -> `WIN_IP_ADDR` -> `WIN_EVENT_CORE.ip_src_id/ip_dst_id`
- `EVENTI_PC.ip_remoto` -> `WIN_IP_ADDR` -> `WIN_EVENT_CORE.ip_dst_id` (if remote) or `details_json.ip_remoto`
- `EVENTI_PC.sospetto_flag` -> `WIN_EVENT_CORE.is_suspect`
- `EVENTI_PC.event_fingerprint` -> `WIN_EVENT_CORE.event_fingerprint`

## Field mapping (text)
- `EVENTI_PC.description` -> `WIN_EVENT_TEXT.message`
- `EVENTI_PC.process_name` -> `WIN_EVENT_TEXT.process_name`
- `EVENTI_PC.command_line` -> `WIN_EVENT_TEXT.command_line`
- `EVENTI_PC.extra_details` -> `WIN_EVENT_TEXT.details_text` or `details_json`
- `EVENTI_PC.logon_type` -> `WIN_EVENT_TEXT.details_json.logon_type`
- `EVENTI_PC.motivazione_sospetto` -> `WIN_EVENT_TEXT.suspect_reason`

## Evidence mapping
- If you have per-file hashes for EVTX/log files, create rows in
  `WIN_EVIDENCE_FILE` and link via `WIN_LOG_ACQUISITION.evidence_id` and
  `WIN_EVENT_CORE.evidence_id`.

## Notes
- `WIN_EVENT_CORE` is the fast-search table; keep it compact.
- `WIN_EVENT_TEXT` is optional for queries that need verbose payloads.
- Populate `WIN_LOG_CHANNEL` and `WIN_EVENT_PROVIDER` as part of ingest.
