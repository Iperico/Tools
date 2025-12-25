#!/usr/bin/env python3
"""
M1 Windows Logs ingestion skeleton (fast-search schema).

This script provides:
- Base extractor interface.
- Example CSV extractor (Windows log export).
- Ingestion manager wiring.
- MySQL writer skeleton for the M1 schema.

It is intentionally minimal and meant to be extended.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional


# -----------------------------------------------------------------------------
# Data records
# -----------------------------------------------------------------------------


@dataclass
class EvidenceFileRecord:
    evidence_type: str
    file_path: str
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    collected_at_utc: Optional[datetime] = None
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class AcquisitionRecord:
    device_label: str
    run_id: str
    channel_name: str
    tool_name: str
    tool_version: Optional[str] = None
    evidence_id: Optional[int] = None
    source_path: Optional[str] = None
    collected_at_utc: Optional[datetime] = None
    validation_status: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class EventCoreRecord:
    timestamp_utc: datetime
    device_label: Optional[str] = None
    device_id: Optional[int] = None
    account_label: Optional[str] = None
    account_id: Optional[int] = None
    account_name: Optional[str] = None
    channel_name: Optional[str] = None
    provider_name: Optional[str] = None
    event_code: Optional[int] = None
    event_level: Optional[int] = None
    task_code: Optional[int] = None
    opcode: Optional[int] = None
    record_id: Optional[int] = None
    process_id: Optional[int] = None
    thread_id: Optional[int] = None
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    port_src: Optional[int] = None
    port_dst: Optional[int] = None
    win_acq_id: Optional[int] = None
    evidence_id: Optional[int] = None
    evidence_locator: Optional[str] = None
    event_fingerprint: Optional[str] = None
    is_suspect: bool = False


@dataclass
class EventTextRecord:
    message: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    details_text: Optional[str] = None
    details_json: Optional[dict] = None
    suspect_reason: Optional[str] = None


@dataclass
class EventBundle:
    core: EventCoreRecord
    text: Optional[EventTextRecord] = None


# -----------------------------------------------------------------------------
# Extractors
# -----------------------------------------------------------------------------


class BaseExtractor:
    name: str = "base"

    def extract(self) -> Iterable[EventBundle]:
        raise NotImplementedError


class WindowsCsvExtractor(BaseExtractor):
    name = "windows_csv"

    def __init__(
        self,
        csv_path: Path,
        device_label: str,
        default_channel: Optional[str] = None,
        default_provider: Optional[str] = None,
        account_label: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> None:
        self.csv_path = csv_path
        self.device_label = device_label
        self.default_channel = default_channel
        self.default_provider = default_provider
        self.account_label = account_label
        self.limit = limit

    def extract(self) -> Iterator[EventBundle]:
        with self.csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for idx, row in enumerate(reader):
                if self.limit and idx >= self.limit:
                    break
                event = self._row_to_event(row)
                if event:
                    yield event

    def _row_to_event(self, row: Dict[str, str]) -> Optional[EventBundle]:
        ts_value = (
            row.get("TimeCreated")
            or row.get("TimeCreatedUtc")
            or row.get("Date")
            or row.get("Timestamp")
            or ""
        )
        ts = parse_datetime(ts_value)
        if not ts:
            return None

        event_code = safe_int(row.get("EventID") or row.get("EventId") or row.get("Id"))
        channel = row.get("Channel") or row.get("LogName") or self.default_channel
        provider = row.get("ProviderName") or row.get("Provider") or self.default_provider
        account_name = (
            row.get("TargetUserName")
            or row.get("SubjectUserName")
            or row.get("User")
            or row.get("AccountName")
        )

        ip_src = row.get("SourceAddress") or row.get("SourceIp") or row.get("IpAddress")
        ip_dst = row.get("DestinationAddress") or row.get("DestIp") or row.get("IpAddress2")
        port_src = safe_int(row.get("SourcePort") or row.get("SrcPort"))
        port_dst = safe_int(row.get("DestinationPort") or row.get("DestPort") or row.get("IpPort"))

        core = EventCoreRecord(
            timestamp_utc=ts,
            device_label=self.device_label,
            account_label=self.account_label,
            account_name=account_name,
            channel_name=channel,
            provider_name=provider,
            event_code=event_code,
            event_level=safe_int(row.get("Level")),
            task_code=safe_int(row.get("Task")),
            opcode=safe_int(row.get("Opcode")),
            record_id=safe_int(row.get("RecordId") or row.get("RecordID")),
            process_id=safe_int(row.get("ProcessId") or row.get("ProcessID")),
            thread_id=safe_int(row.get("ThreadId") or row.get("ThreadID")),
            ip_src=ip_src,
            ip_dst=ip_dst,
            port_src=port_src,
            port_dst=port_dst,
            evidence_locator=row.get("RecordId") or row.get("RecordID"),
        )

        text = EventTextRecord(
            message=row.get("Message") or row.get("Description"),
            process_name=row.get("ProcessName"),
            command_line=row.get("CommandLine"),
            details_text=row.get("Details") or row.get("Payload"),
        )

        return EventBundle(core=core, text=text)


# -----------------------------------------------------------------------------
# Writer interfaces
# -----------------------------------------------------------------------------


class BaseWriter:
    def insert_evidence(self, record: EvidenceFileRecord) -> Optional[int]:
        raise NotImplementedError

    def insert_acquisition(self, record: AcquisitionRecord) -> Optional[int]:
        raise NotImplementedError

    def insert_event(self, core: EventCoreRecord, text: Optional[EventTextRecord]) -> Optional[int]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class DryRunWriter(BaseWriter):
    def __init__(self) -> None:
        self.counts: Dict[str, int] = {}

    def _bump(self, key: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1

    def insert_evidence(self, record: EvidenceFileRecord) -> Optional[int]:
        self._bump("WIN_EVIDENCE_FILE")
        return 0

    def insert_acquisition(self, record: AcquisitionRecord) -> Optional[int]:
        self._bump("WIN_LOG_ACQUISITION")
        return 0

    def insert_event(self, core: EventCoreRecord, text: Optional[EventTextRecord]) -> Optional[int]:
        self._bump("WIN_EVENT_CORE")
        if text:
            self._bump("WIN_EVENT_TEXT")
        return 0

    def close(self) -> None:
        print("[DRY-RUN] Insert counts:")
        for key in sorted(self.counts):
            print(f"  {key}: {self.counts[key]}")


class MysqlWriter(BaseWriter):
    def __init__(self, host: str, port: int, user: str, password: str, database: str) -> None:
        mysql = import_mysql_connector()
        self.conn = mysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            autocommit=True,
        )
        self.device_cache: Dict[str, int] = {}
        self.account_cache: Dict[str, int] = {}
        self.channel_cache: Dict[str, int] = {}
        self.provider_cache: Dict[str, int] = {}
        self.ip_cache: Dict[str, int] = {}

    def close(self) -> None:
        self.conn.close()

    def insert_evidence(self, record: EvidenceFileRecord) -> Optional[int]:
        sql = """
        INSERT INTO WIN_EVIDENCE_FILE (
            evidence_type, file_path, file_hash_sha256, file_size_bytes,
            collected_at_utc, tool_name, tool_version, notes
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE evidence_id = LAST_INSERT_ID(evidence_id),
            file_path = VALUES(file_path)
        """
        values = (
            record.evidence_type,
            record.file_path,
            record.file_hash_sha256,
            record.file_size_bytes,
            record.collected_at_utc,
            record.tool_name,
            record.tool_version,
            record.notes,
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, values)
            return int(cur.lastrowid) if cur.lastrowid else None

    def insert_acquisition(self, record: AcquisitionRecord) -> Optional[int]:
        device_id = self._ensure_device_id(record.device_label)
        sql = """
        INSERT INTO WIN_LOG_ACQUISITION (
            device_id, run_id, channel_name, tool_name, tool_version,
            evidence_id, source_path, collected_at_utc, validation_status, notes
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE win_acq_id = LAST_INSERT_ID(win_acq_id)
        """
        values = (
            device_id,
            record.run_id,
            record.channel_name,
            record.tool_name,
            record.tool_version,
            record.evidence_id,
            record.source_path,
            record.collected_at_utc,
            record.validation_status,
            record.notes,
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, values)
            return int(cur.lastrowid) if cur.lastrowid else None

    def insert_event(self, core: EventCoreRecord, text: Optional[EventTextRecord]) -> Optional[int]:
        device_id = core.device_id or self._ensure_device_id(core.device_label)
        account_id = None
        if core.account_id:
            account_id = core.account_id
        elif core.account_label:
            account_id = self._ensure_account_id(core.account_label, core.account_name)

        channel_id = self._upsert_channel(core.channel_name) if core.channel_name else None
        provider_id = self._upsert_provider(core.provider_name) if core.provider_name else None
        ip_src_id = self._upsert_ip(core.ip_src) if core.ip_src else None
        ip_dst_id = self._upsert_ip(core.ip_dst) if core.ip_dst else None

        sql = """
        INSERT INTO WIN_EVENT_CORE (
            timestamp_utc, device_id, account_id, account_name, win_acq_id,
            channel_id, provider_id, event_code, event_level, task_code, opcode,
            record_id, process_id, thread_id, ip_src_id, ip_dst_id, port_src,
            port_dst, evidence_id, evidence_locator, event_fingerprint, is_suspect
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s
        )
        ON DUPLICATE KEY UPDATE win_event_id = LAST_INSERT_ID(win_event_id)
        """
        values = (
            core.timestamp_utc,
            device_id,
            account_id,
            core.account_name,
            core.win_acq_id,
            channel_id,
            provider_id,
            core.event_code,
            core.event_level,
            core.task_code,
            core.opcode,
            core.record_id,
            core.process_id,
            core.thread_id,
            ip_src_id,
            ip_dst_id,
            core.port_src,
            core.port_dst,
            core.evidence_id,
            core.evidence_locator,
            core.event_fingerprint,
            1 if core.is_suspect else 0,
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, values)
            event_id = int(cur.lastrowid) if cur.lastrowid else None

        if text and event_id:
            self._insert_event_text(event_id, text)
        return event_id

    def _insert_event_text(self, event_id: int, text: EventTextRecord) -> None:
        sql = """
        INSERT INTO WIN_EVENT_TEXT (
            win_event_id, message, process_name, command_line,
            details_text, details_json, suspect_reason
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            message = VALUES(message),
            process_name = VALUES(process_name),
            command_line = VALUES(command_line),
            details_text = VALUES(details_text),
            details_json = VALUES(details_json),
            suspect_reason = VALUES(suspect_reason)
        """
        details_json = json.dumps(text.details_json) if text.details_json else None
        values = (
            event_id,
            text.message,
            text.process_name,
            text.command_line,
            text.details_text,
            details_json,
            text.suspect_reason,
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, values)

    def _ensure_device_id(self, device_label: Optional[str]) -> int:
        if not device_label:
            raise ValueError("device_label is required for WIN_EVENT_CORE")
        if device_label in self.device_cache:
            return self.device_cache[device_label]
        sql = "SELECT device_id FROM DEVICE_MASTER WHERE device_label = %s"
        with self.conn.cursor() as cur:
            cur.execute(sql, (device_label,))
            row = cur.fetchone()
            if row:
                device_id = int(row[0])
            else:
                cur.execute(
                    """
                    INSERT INTO DEVICE_MASTER (device_label, device_type, platform)
                    VALUES (%s, %s, %s)
                    """,
                    (device_label, "PC", "Windows"),
                )
                device_id = int(cur.lastrowid)
        self.device_cache[device_label] = device_id
        return device_id

    def _ensure_account_id(self, account_label: str, display_name: Optional[str]) -> int:
        if account_label in self.account_cache:
            return self.account_cache[account_label]
        sql = "SELECT account_id FROM ACCOUNT_MASTER WHERE account_label = %s"
        with self.conn.cursor() as cur:
            cur.execute(sql, (account_label,))
            row = cur.fetchone()
            if row:
                account_id = int(row[0])
            else:
                cur.execute(
                    """
                    INSERT INTO ACCOUNT_MASTER (account_label, provider, display_name)
                    VALUES (%s, %s, %s)
                    """,
                    (account_label, "generic", display_name),
                )
                account_id = int(cur.lastrowid)
        self.account_cache[account_label] = account_id
        return account_id

    def _upsert_channel(self, channel_name: str) -> int:
        if channel_name in self.channel_cache:
            return self.channel_cache[channel_name]
        sql = """
        INSERT INTO WIN_LOG_CHANNEL (channel_name)
        VALUES (%s)
        ON DUPLICATE KEY UPDATE channel_id = LAST_INSERT_ID(channel_id)
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, (channel_name,))
            channel_id = int(cur.lastrowid)
        self.channel_cache[channel_name] = channel_id
        return channel_id

    def _upsert_provider(self, provider_name: str) -> int:
        if provider_name in self.provider_cache:
            return self.provider_cache[provider_name]
        sql = """
        INSERT INTO WIN_EVENT_PROVIDER (provider_name)
        VALUES (%s)
        ON DUPLICATE KEY UPDATE provider_id = LAST_INSERT_ID(provider_id)
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, (provider_name,))
            provider_id = int(cur.lastrowid)
        self.provider_cache[provider_name] = provider_id
        return provider_id

    def _upsert_ip(self, ip_text: str) -> Optional[int]:
        if ip_text in self.ip_cache:
            return self.ip_cache[ip_text]
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            return None
        ip_bin = ip_obj.packed
        ip_version = ip_obj.version
        sql = """
        INSERT INTO WIN_IP_ADDR (ip_text, ip_bin, ip_version)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE ip_id = LAST_INSERT_ID(ip_id)
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, (ip_text, ip_bin, ip_version))
            ip_id = int(cur.lastrowid)
        self.ip_cache[ip_text] = ip_id
        return ip_id


# -----------------------------------------------------------------------------
# Ingestion manager
# -----------------------------------------------------------------------------


class IngestionManager:
    def __init__(self, writer: BaseWriter) -> None:
        self.writer = writer

    def ingest(
        self,
        extractor: BaseExtractor,
        acquisition: Optional[AcquisitionRecord] = None,
        evidence: Optional[EvidenceFileRecord] = None,
        existing_evidence_id: Optional[int] = None,
        existing_win_acq_id: Optional[int] = None,
    ) -> int:
        evidence_id = existing_evidence_id
        if evidence_id is None and evidence:
            evidence_id = self.writer.insert_evidence(evidence)

        win_acq_id = existing_win_acq_id
        if win_acq_id is None and acquisition:
            if evidence_id is not None and not acquisition.evidence_id:
                acquisition.evidence_id = evidence_id
            win_acq_id = self.writer.insert_acquisition(acquisition)

        total = 0
        for bundle in extractor.extract():
            if evidence_id is not None and not bundle.core.evidence_id:
                bundle.core.evidence_id = evidence_id
            if win_acq_id is not None and not bundle.core.win_acq_id:
                bundle.core.win_acq_id = win_acq_id
            self.writer.insert_event(bundle.core, bundle.text)
            total += 1
        return total


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def import_mysql_connector():
    try:
        import mysql.connector  # type: ignore
    except Exception as exc:
        raise SystemExit(
            "Missing mysql-connector-python. Install with: pip install mysql-connector-python\n"
            f"Details: {exc}"
        )
    return mysql.connector


def parse_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="M1 Windows Logs ingest skeleton")
    parser.add_argument("--csv-path", required=True, help="Path to Windows log CSV")
    parser.add_argument("--device-label", required=True, help="DEVICE_MASTER label")
    parser.add_argument("--account-label", help="ACCOUNT_MASTER label (optional)")
    parser.add_argument("--run-id", help="Acquisition run id (YYYYMMDD_HHMMSS)")
    parser.add_argument("--channel-name", help="Default channel name")
    parser.add_argument("--tool-name", default="wevtutil_export", help="Tool name")
    parser.add_argument("--tool-version", help="Tool version")
    parser.add_argument("--evidence-path", help="Raw evidence file path")
    parser.add_argument("--evidence-type", default="evtx", help="Evidence type")
    parser.add_argument("--evidence-hash", help="SHA256 hash (optional)")
    parser.add_argument("--compute-hash", action="store_true", help="Compute SHA256")
    parser.add_argument("--limit", type=int, help="Limit rows for test runs")
    parser.add_argument("--dry-run", action="store_true", help="No DB writes")
    parser.add_argument("--mysql-host", default="127.0.0.1")
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--mysql-user", default="safenet_ingest")
    parser.add_argument("--mysql-password", default="")
    parser.add_argument("--mysql-database", default="forensic")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    csv_path = Path(args.csv_path)
    if not csv_path.exists():
        raise SystemExit(f"CSV path not found: {csv_path}")

    evidence = None
    if args.evidence_path:
        evidence_path = Path(args.evidence_path)
        if not evidence_path.exists():
            raise SystemExit(f"Evidence path not found: {evidence_path}")
        file_hash = args.evidence_hash
        if args.compute_hash:
            file_hash = compute_sha256(evidence_path)
        stat = evidence_path.stat()
        evidence = EvidenceFileRecord(
            evidence_type=args.evidence_type,
            file_path=str(evidence_path),
            file_hash_sha256=file_hash,
            file_size_bytes=stat.st_size,
            collected_at_utc=datetime.utcfromtimestamp(stat.st_mtime),
            tool_name=args.tool_name,
            tool_version=args.tool_version,
        )

    acquisition = None
    if args.run_id and args.channel_name:
        acquisition = AcquisitionRecord(
            device_label=args.device_label,
            run_id=args.run_id,
            channel_name=args.channel_name,
            tool_name=args.tool_name,
            tool_version=args.tool_version,
            source_path=str(csv_path),
            collected_at_utc=datetime.utcnow(),
        )

    extractor = WindowsCsvExtractor(
        csv_path=csv_path,
        device_label=args.device_label,
        default_channel=args.channel_name,
        account_label=args.account_label,
        limit=args.limit,
    )

    writer: BaseWriter
    if args.dry_run:
        writer = DryRunWriter()
    else:
        writer = MysqlWriter(
            host=args.mysql_host,
            port=args.mysql_port,
            user=args.mysql_user,
            password=args.mysql_password,
            database=args.mysql_database,
        )

    manager = IngestionManager(writer)
    total = manager.ingest(extractor=extractor, acquisition=acquisition, evidence=evidence)
    writer.close()
    print(f"Inserted events: {total}")


if __name__ == "__main__":
    main()
