# EvenTypePipelineBuilder.py
import argparse
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple

KEY_FIELDS = [
    "time_created",
    "account_name",
    "logon_type",
    "process_name",
    "ip_src",
    "ip_dst",
    "device_id",
]

def get_event_types(conn, min_events: int) -> List[Tuple[str, int, int]]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT source_log, event_code, COUNT(*) as c
        FROM EVENTI_PC
        GROUP BY source_log, event_code
        HAVING c >= ?
        ORDER BY source_log, event_code
        """,
        (min_events,),
    )
    return cur.fetchall()  # (source_log, event_code, count)

def coverage_for_event_type(conn, source_log: str, event_code: int, sample_limit: int = 1000) -> Dict[str, float]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT {fields}
        FROM EVENTI_PC
        WHERE source_log = ? AND event_code = ?
        LIMIT ?
        """.format(fields=", ".join(KEY_FIELDS)),
        (source_log, event_code, sample_limit),
    )
    rows = cur.fetchall()
    if not rows:
        return {k: 0.0 for k in KEY_FIELDS}

    total = len(rows)
    coverage = {k: 0 for k in KEY_FIELDS}

    for row in rows:
        for idx, field in enumerate(KEY_FIELDS):
            val = row[idx]
            if val is not None and str(val).strip() != "":
                coverage[field] += 1

    return {k: coverage[k] / total for k in KEY_FIELDS}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--min-events", type=int, default=100)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    event_types = get_event_types(conn, args.min_events)

    pipelines = []
    for source_log, event_code, count in event_types:
        cov = coverage_for_event_type(conn, source_log, event_code)
        field_score = sum(cov.values()) / len(cov) if cov else 0.0

        pipelines.append(
            {
                "source_log": source_log,
                "event_code": event_code,
                "pipeline_name": f"{source_log.lower()}_{event_code}",
                "events_count": count,
                "field_coverage": cov,
                "field_score": field_score,
            }
        )

    out_json = outdir / "event_type_pipelines.json"
    out_json.write_text(json.dumps(pipelines, indent=2), encoding="utf-8")

    conn.close()

if __name__ == "__main__":
    main()
