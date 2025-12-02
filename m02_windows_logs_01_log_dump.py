#!/usr/bin/env python3
"""
m02_windows_logs_02_extract_to_safenet.py

This script analyses Windows event logs exported either as CSV files or as raw
.evtx event log files and produces a comprehensive report summarising
activity within a given date range. The intent is to to support forensic
investigations by quickly assembling the most relevant information into a
single place. It creates a report directory and writes multiple CSV and
markdown files detailing counts of events, login attempts, and other
interesting statistics.

The script was designed for Python 3.11 and should run on a Windows system
where the logs originate, although it will also work on other platforms as
long as the input files are CSVs. When processing raw .evtx files it
invokes PowerShell via subprocess to extract the relevant events into
temporary CSVs before analysis. If PowerShell is unavailable the script
will still work for CSV inputs but will skip .evtx files.

Typical usage from PowerShell:

    python .\\m02_windows_logs_02_extract_to_safenet.py --log-dir "logY\\Forensics\\WIN_PCAle_Old_logs" `
        --from-date 2025-11-01 --to-date 2025-12-01 `
        --max-files 300 --report-dir "report_win_2025_11_all"

Usage examples:

    # Analyse all logs in a directory for a given date range, using an
    # automatically generated report directory name.
    python m02_windows_logs_02_extract_to_safenet.py --log-dir logY/Forensics/WIN_PCAle_Old_logs \
        --from-date 2025-01-01 --to-date 2025-02-01

    # Analyse only Security and System logs exported as CSVs for a single
    # day and specify a custom report directory name.
    python m02_windows_logs_02_extract_to_safenet.py --log-dir logs --from-date 2025-01-25 \
        --to-date 2025-01-26 --report-dir report_20250125

    # Analyse only the first three log files in a directory (quick test):
    python m02_windows_logs_02_extract_to_safenet.py --log-dir logs --max-files 3 \
        --from-date 2025-01-01 --to-date 2025-02-01

The report directory will contain:

* summary.md – a human-readable markdown summary of key findings;
* one CSV file per input log containing the filtered events within the date
  range;
* one CSV file per log summarising counts by event ID, provider and level;
* an overall summary CSV combining counts from all logs.

Example PowerShell command to export a single .evtx log to CSV manually:

    Get-WinEvent -Path "C:\\Windows\\System32\\winevt\\Logs\\System.evtx" |
      Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, MachineName, Message |
      Export-Csv -Path ".\\System.csv" -NoTypeInformation -Encoding UTF8

Author: OpenAI Assistant
"""

import argparse
import csv
import datetime as dt
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def parse_date(value: Optional[str]) -> Optional[dt.datetime]:
    """Parse a date string (YYYY-MM-DD or ISO8601) to a timezone-aware
    datetime at midnight UTC. Returns None if parsing fails or value is
    None. Accepts both date and datetime strings; if the string has no
    timezone information it is assumed to be UTC.
    """
    if not value:
        return None
    value = value.strip()
    try:
        # If only a date is provided, interpret it as midnight UTC.
        if re.match(r"^\\d{4}-\\d{2}-\\d{2}$", value):
            d = dt.datetime.strptime(value, "%Y-%m-%d")
            return d.replace(tzinfo=dt.timezone.utc)
        # Otherwise let fromisoformat handle it.
        d = dt.datetime.fromisoformat(value)
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        else:
            d = d.astimezone(dt.timezone.utc)
        return d
    except Exception:
        return None


def ensure_report_dir(report_dir: Optional[str], prefix: str = "windows_report") -> Path:
    """Ensure that the report directory exists. If report_dir is provided
    explicitly, it will be created if it does not exist. Otherwise a
    directory is generated with the prefix and a timestamp. The returned
    Path object is guaranteed to exist on disk.
    """
    if report_dir:
        path = Path(report_dir).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"{prefix}_{timestamp}").resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def powershell_available() -> bool:
    """Return True if the powershell executable is available on the system."""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except Exception:
        return False


def extract_evtx_to_csv(evtx_path: Path, tmp_dir: Path) -> Optional[Path]:
    """Given a path to an .evtx file, use PowerShell Get-WinEvent to export
    it to a CSV in tmp_dir and return the CSV path. Returns None on failure.
    """
    if not powershell_available():
        sys.stderr.write(
            f"Warning: PowerShell not available, skipping EVTX file: {evtx_path}\n"
        )
        return None

    csv_path = tmp_dir / (evtx_path.stem + ".csv")
    ps_script = f"""
    $log = "{evtx_path}"
    Get-WinEvent -Path $log | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, MachineName, Message |
    Export-Csv -Path "{csv_path}" -NoTypeInformation -Encoding UTF8
    """
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            # Common case: empty log → NoMatchingEventsFound
            if "NoMatchingEventsFound" in completed.stderr:
                sys.stderr.write(
                    f"Info: {evtx_path.name}: nessun evento nel log, skip.\n"
                )
                return None
            # Other errors
            sys.stderr.write(
                f"Error: failed to extract {evtx_path} with PowerShell: {completed.stderr}\n"
            )
            return None
        return csv_path
    except Exception as e:
        sys.stderr.write(f"Exception running PowerShell on {evtx_path}: {e}\n")
        return None


def parse_event_time(ts: str) -> Optional[dt.datetime]:
    """
    Try to convert a Windows timestamp string (also in local formats like
    19/11/2025 21:17:29) into a UTC datetime. Returns None if parsing fails.
    """
    if not ts:
        return None

    ts_clean = ts.strip().strip('"').replace("\xa0", " ")

    # 1) Try ISO / quasi-ISO
    v = ts_clean
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"

    dt_obj: Optional[dt.datetime] = None
    try:
        dt_obj = dt.datetime.fromisoformat(v)
    except Exception:
        dt_obj = None

    # 2) Try common Windows / Export-Csv local formats
    if dt_obj is None:
        for fmt in (
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %H.%M.%S",
            "%d/%m/%Y %H:%M",
            "%d/%m/%Y %H.%M",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M",
        ):
            try:
                dt_obj = dt.datetime.strptime(ts_clean, fmt)
                break
            except Exception:
                continue

    if dt_obj is None:
        return None

    # Normalize to UTC
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(dt.timezone.utc)
    return dt_obj


def read_csv_events(
    csv_path: Path, start: Optional[dt.datetime], end: Optional[dt.datetime]
) -> List[Dict[str, str]]:
    """
    Read a CSV of events exported from Get-WinEvent and apply (if possible)
    the date filter. Supports local timestamps like 19/11/2025 21:17:29.

    If the timestamp cannot be parsed, the event is STILL KEPT (without
    additional Python-side date filtering) so we don't lose information.
    """
    events: List[Dict[str, str]] = []
    parse_warning_shown = False

    with csv_path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = row.get("TimeCreated") or row.get("timeCreated") or row.get("Date")

            # No timestamp column → keep the event anyway
            if not ts:
                events.append(row)
                continue

            dt_obj = parse_event_time(ts)

            # If we can't parse the timestamp, keep event without enforcing date filter
            if dt_obj is None:
                if not parse_warning_shown:
                    sys.stderr.write(
                        f"Warning: TimeCreated format not recognised in {csv_path.name}; "
                        "events will be included without Python-side date filtering.\n"
                    )
                    parse_warning_shown = True
                events.append(row)
                continue

            # Apply date range filter
            if start and dt_obj < start:
                continue
            if end and dt_obj >= end:
                continue

            events.append(row)

    return events


def summarise_events(events: List[Dict[str, str]]) -> Dict[str, Dict[str, int]]:
    """Given a list of event rows, return dictionaries summarising
    counts by event ID, provider name and level. The result is a dict
    with keys 'id', 'provider', 'level' mapping to Counter objects.
    """
    by_id = Counter()
    by_provider = Counter()
    by_level = Counter()
    for row in events:
        event_id = row.get("Id") or row.get("EventID") or row.get("EventId")
        provider = row.get("ProviderName") or row.get("Source")
        level = row.get("LevelDisplayName") or row.get("Level")
        if event_id:
            by_id[str(event_id)] += 1
        if provider:
            by_provider[str(provider)] += 1
        if level:
            by_level[str(level)] += 1
    return {"id": by_id, "provider": by_provider, "level": by_level}


def write_events_csv(events: List[Dict[str, str]], out_path: Path) -> None:
    """Write the list of event rows to a CSV file."""
    if not events:
        with out_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["No events in specified date range or log is empty"])
        return

    fieldnames = list(events[0].keys())
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in events:
            writer.writerow(row)


def write_summary_csv(summary: Dict[str, Dict[str, int]], out_path: Path) -> None:
    """Given summary counters for a single log, write them to a CSV file.
    The CSV will have rows: category, key, count.
    """
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "key", "count"])
        for category, counter in summary.items():
            for key, count in counter.most_common():
                writer.writerow([category, key, count])


def generate_overall_summary(
    log_summaries: Dict[str, Dict[str, Dict[str, int]]]
) -> Dict[str, int]:
    """Aggregate per-log summaries into a single Counter of overall counts.
    Returns a dict mapping "category:key" to counts.
    """
    overall = Counter()
    for summary in log_summaries.values():
        for category, counter in summary.items():
            for key, count in counter.items():
                overall[f"{category}:{key}"] += count
    return dict(overall)


def write_markdown_summary(
    log_summaries: Dict[str, Dict[str, Dict[str, int]]],
    overall_counts: Dict[str, int],
    report_dir: Path,
    start: Optional[dt.datetime],
    end: Optional[dt.datetime],
) -> None:
    """Write a human-readable markdown file summarising the analysis."""
    md_path = report_dir / "summary.md"
    with md_path.open("w", encoding="utf-8") as f:
        f.write("# Windows Event Log Forensic Report\n\n")
        f.write(f"Generated on: {dt.datetime.now().isoformat()}\n\n")
        if start or end:
            f.write("**Time range analysed:** ")
            if start:
                f.write(start.isoformat())
            else:
                f.write("beginning")
            f.write(" to ")
            if end:
                f.write(end.isoformat())
            else:
                f.write("end")
            f.write("\n\n")

        total_events = 0
        for summary in log_summaries.values():
            for counter in summary.values():
                total_events += sum(counter.values())

        f.write(f"**Total events analysed:** {total_events}\n\n")
        f.write("## Per-log summaries\n\n")

        def top_n(counter: Dict[str, int], n: int = 10):
            return sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:n]

        for log_name, summary in log_summaries.items():
            f.write(f"### Log: {log_name}\n\n")
            ids = summary.get("id", {})
            providers = summary.get("provider", {})
            levels = summary.get("level", {})

            f.write("**Top event IDs:**\n\n")
            f.write("| Event ID | Count |\n|---------|-------|\n")
            for key, count in top_n(ids):
                f.write(f"| {key} | {count} |\n")
            f.write("\n")

            f.write("**Top providers:**\n\n")
            f.write("| Provider | Count |\n|----------|-------|\n")
            for key, count in top_n(providers):
                f.write(f"| {key} | {count} |\n")
            f.write("\n")

            f.write("**Levels:**\n\n")
            f.write("| Level | Count |\n|-------|-------|\n")
            for key, count in top_n(levels):
                f.write(f"| {key} | {count} |\n")
            f.write("\n")

        f.write("## Overall event counts (selected)\n\n")
        interesting_ids = ["4624", "4625", "4634", "4647", "4672"]
        descriptions = {
            "4624": "An account was successfully logged on",
            "4625": "An account failed to log on",
            "4634": "An account was logged off",
            "4647": "User initiated logoff",
            "4672": "Special privileges assigned to new logon",
        }
        f.write("| Event ID | Description              | Count |\n")
        f.write("|----------|--------------------------|-------|\n")
        for event_id in interesting_ids:
            key = f"id:{event_id}"
            count = overall_counts.get(key, 0)
            desc = descriptions.get(event_id, "")
            f.write(f"| {event_id} | {desc} | {count} |\n")
        f.write("\n")
        f.write(
            "This report is intended as a starting point for deeper forensic "
            "analysis. You can open the CSV files in a spreadsheet or other "
            "analysis tools to perform more targeted queries.\n"
        )


def analyse_log(
    log_path: Path, start: Optional[dt.datetime], end: Optional[dt.datetime], tmp_dir: Path
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, int]]]:
    """Given a path to either a .csv or .evtx log, extract events within
    the specified date range and return both the list of events and a
    summary Counter dict.
    """
    if log_path.suffix.lower() == ".csv":
        csv_path = log_path
    elif log_path.suffix.lower() == ".evtx":
        csv_path = extract_evtx_to_csv(log_path, tmp_dir)
        if csv_path is None:
            return [], {"id": Counter(), "provider": Counter(), "level": Counter()}
    else:
        return [], {"id": Counter(), "provider": Counter(), "level": Counter()}

    events = read_csv_events(csv_path, start, end)
    summary = summarise_events(events)
    return events, summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a comprehensive report from Windows event logs (CSV or EVTX)"
    )
    parser.add_argument(
        "--log-dir", required=True, help="Directory containing .csv or .evtx log files"
    )
    parser.add_argument(
        "--from-date", default=None, help="Start date/time in ISO format (inclusive)"
    )
    parser.add_argument(
        "--to-date", default=None, help="End date/time in ISO format (exclusive)"
    )
    parser.add_argument(
        "--report-dir",
        default=None,
        help="Directory to write the report (if omitted, uses a timestamped name)",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of log files to process (for quick tests)",
    )
    args = parser.parse_args()

    log_dir = Path(args.log_dir).expanduser().resolve()
    if not log_dir.is_dir():
        print(f"Error: log directory {log_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    start = parse_date(args.from_date)
    end = parse_date(args.to_date)
    if start and end and end < start:
        print("Error: --to-date must be after --from-date", file=sys.stderr)
        sys.exit(1)

    report_dir = ensure_report_dir(args.report_dir)
    tmp_dir = report_dir / "_tmp_evtx"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    log_summaries: Dict[str, Dict[str, Dict[str, int]]] = {}

    processed = 0
    for entry in sorted(log_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in (".evtx", ".csv"):
            continue
        if args.max_files is not None and processed >= args.max_files:
            break

        log_name = entry.stem
        print(f"Processing {entry.name}…")
        events, summary = analyse_log(entry, start, end, tmp_dir)

        events_csv_path = report_dir / f"{log_name}_events.csv"
        write_events_csv(events, events_csv_path)

        summary_csv_path = report_dir / f"{log_name}_summary.csv"
        write_summary_csv(summary, summary_csv_path)

        log_summaries[log_name] = summary
        processed += 1

    # Clean temporary directory
    try:
        for p in tmp_dir.iterdir():
            p.unlink()
        tmp_dir.rmdir()
    except Exception:
        pass

    overall_counts = generate_overall_summary(log_summaries)
    overall_csv = report_dir / "overall_summary.csv"
    with overall_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "count"])
        writer.writeheader()
        for key, value in overall_counts.items():
            writer.writerow({"category": key, "count": value})

    write_markdown_summary(log_summaries, overall_counts, report_dir, start, end)
    print(f"Report written to {report_dir}")


if __name__ == "__main__":
    main()
