#!/usr/bin/env python3
"""
Live MySQL schema + tail view (read-only).

Shows:
- Tables and columns (optional filters).
- Foreign key relationships (graph-like list).
- Last N rows from a "raw" table (EVENTI_RAW by default).
"""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


CONFIG_FILE = Path(__file__).with_name("forensic_config.json")

TABLE_EXPLANATIONS: Dict[str, str] = {
    "DEVICE_MASTER": "Device registry (shared master).",
    "ACCOUNT_MASTER": "Account registry (shared master).",
    "SCHEMA_VERSION": "Schema audit tracker.",
    "EVENTI_RAW": "Lossless raw events (shared).",
    "WIN_EVIDENCE_FILE": "Evidence file catalog (Windows logs).",
    "WIN_LOG_ACQUISITION": "Windows log acquisition runs.",
    "WIN_EVENT_CORE": "Fast-search event core (Windows logs).",
    "WIN_EVENT_TEXT": "Verbose event payload (Windows logs).",
    "WIN_LOG_CHANNEL": "Log channel dictionary.",
    "WIN_EVENT_PROVIDER": "Provider dictionary.",
    "WIN_IP_ADDR": "IP registry (binary + text).",
    "ANDROID_ACQUISITIONS": "Android acquisition runs (M01).",
    "WINDOWS_ACQUISITIONS": "Legacy Windows acquisitions (M02).",
    "EVENTI_ANDROID": "Android events (legacy).",
    "EVENTI_PC": "Windows events (legacy).",
}


@dataclass
class MysqlConfig:
    host: str
    port: int
    user: str
    password: str
    database: str


def load_config(path: Path) -> Optional[MysqlConfig]:
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    globals_cfg = data.get("globals", {})
    return MysqlConfig(
        host=globals_cfg.get("mysql_host", "127.0.0.1"),
        port=int(globals_cfg.get("mysql_port", 3306)),
        user=globals_cfg.get("mysql_user", "root"),
        password=globals_cfg.get("mysql_password", ""),
        database=globals_cfg.get("mysql_database", "forensic"),
    )


def apply_overrides(cfg: MysqlConfig, args: argparse.Namespace) -> MysqlConfig:
    return MysqlConfig(
        host=args.mysql_host or cfg.host,
        port=args.mysql_port or cfg.port,
        user=args.mysql_user or cfg.user,
        password=args.mysql_password if args.mysql_password is not None else cfg.password,
        database=args.mysql_database or cfg.database,
    )


def import_mysql_connector():
    try:
        import mysql.connector  # type: ignore
    except Exception as exc:
        raise SystemExit(
            "Missing mysql-connector-python. Install with: pip install mysql-connector-python\n"
            f"Details: {exc}"
        )
    return mysql.connector


def connect_mysql(cfg: MysqlConfig):
    mysql = import_mysql_connector()
    return mysql.connect(
        host=cfg.host,
        port=cfg.port,
        user=cfg.user,
        password=cfg.password,
        database=cfg.database,
        autocommit=True,
    )


def quote_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def fetch_tables(conn, db: str) -> List[str]:
    sql = """
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = %s
    ORDER BY table_name
    """
    with conn.cursor() as cur:
        cur.execute(sql, (db,))
        return [row[0] for row in cur.fetchall()]


def fetch_columns(conn, db: str, table: str) -> List[Tuple[str, str, str]]:
    sql = """
    SELECT column_name, data_type, is_nullable
    FROM information_schema.columns
    WHERE table_schema = %s AND table_name = %s
    ORDER BY ordinal_position
    """
    with conn.cursor() as cur:
        cur.execute(sql, (db, table))
        return [(r[0], r[1], r[2]) for r in cur.fetchall()]


def fetch_foreign_keys(conn, db: str) -> List[Tuple[str, str, str, str]]:
    sql = """
    SELECT table_name, column_name, referenced_table_name, referenced_column_name
    FROM information_schema.key_column_usage
    WHERE table_schema = %s AND referenced_table_name IS NOT NULL
    ORDER BY table_name, column_name
    """
    with conn.cursor() as cur:
        cur.execute(sql, (db,))
        return [(r[0], r[1], r[2], r[3]) for r in cur.fetchall()]


def filter_tables(
    tables: Iterable[str],
    prefix: Optional[str],
    contains: Optional[str],
) -> List[str]:
    filtered = []
    for name in tables:
        if prefix and not name.startswith(prefix):
            continue
        if contains and contains not in name:
            continue
        filtered.append(name)
    return filtered


def pick_tail_table(tables: List[str], tail_table: Optional[str]) -> Optional[str]:
    if tail_table:
        return tail_table if tail_table in tables else None
    if "EVENTI_RAW" in tables:
        return "EVENTI_RAW"
    if "WIN_EVENT_CORE" in tables:
        return "WIN_EVENT_CORE"
    return tables[0] if tables else None


def pick_order_column(columns: List[str]) -> str:
    candidates = [
        "inserted_at",
        "created_at",
        "timestamp_utc",
        "event_time_utc",
        "time_created",
        "win_event_id",
        "raw_event_id",
        "pc_event_id",
        "id",
    ]
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return columns[0]


def pick_tail_columns(table: str, columns: List[str], custom: Optional[str]) -> List[str]:
    if custom:
        requested = [c.strip() for c in custom.split(",") if c.strip()]
        return [c for c in requested if c in columns] or columns[:8]
    if table == "EVENTI_RAW":
        wanted = [
            "raw_event_id",
            "milestone_code",
            "event_time_utc",
            "device_id",
            "event_code",
            "source_log",
            "inserted_at",
            "raw_payload",
        ]
        return [c for c in wanted if c in columns]
    if table == "WIN_EVENT_CORE":
        wanted = [
            "win_event_id",
            "timestamp_utc",
            "device_id",
            "event_code",
            "channel_id",
            "provider_id",
            "ip_src_id",
            "ip_dst_id",
            "evidence_id",
            "is_suspect",
        ]
        return [c for c in wanted if c in columns]
    return columns[:8]


def explain_table(name: str, cols: List[Tuple[str, str, str]]) -> str:
    if name in TABLE_EXPLANATIONS:
        return TABLE_EXPLANATIONS[name]
    if name.endswith("_MASTER"):
        return "Master reference table."
    if name.endswith("_ACQUISITION"):
        return "Acquisition runs table."
    if name.startswith("WIN_"):
        return "Windows logs milestone table."
    if name.startswith("EVENTI_"):
        return "Event table."
    return f"{len(cols)} columns."


def render_table_explanations(
    tables: List[str],
    columns_map: Dict[str, List[Tuple[str, str, str]]],
) -> List[str]:
    lines = ["Tables (explained):"]
    for table in tables:
        cols = columns_map.get(table, [])
        explanation = explain_table(table, cols)
        lines.append(f"- {table}: {explanation} (cols: {len(cols)})")
    return lines


def render_graph_section(fks: List[Tuple[str, str, str, str]]) -> List[str]:
    lines = ["Graph (table-level):"]
    if not fks:
        lines.append("- (no foreign keys)")
        return lines
    edges: Dict[str, List[str]] = {}
    for table, _column, ref_table, _ref_column in fks:
        edges.setdefault(table, [])
        if ref_table not in edges[table]:
            edges[table].append(ref_table)
    for table in sorted(edges):
        targets = ", ".join(sorted(edges[table]))
        lines.append(f"- {table} -> {targets}")
    return lines


def select_table_from_hint(tables: List[str], hint: str) -> Optional[str]:
    if not hint:
        return None
    lowered = hint.lower().strip()
    if not lowered:
        return None
    for name in tables:
        if name.lower() == lowered:
            return name
    for name in tables:
        if lowered in name.lower():
            return name
    return None


def fetch_tail_rows(
    conn,
    table: str,
    columns: List[str],
    order_column: str,
    limit: int,
) -> List[Dict[str, object]]:
    cols_sql = ", ".join(quote_ident(c) for c in columns)
    sql = f"""
    SELECT {cols_sql}
    FROM {quote_ident(table)}
    ORDER BY {quote_ident(order_column)} DESC
    LIMIT %s
    """
    with conn.cursor(dictionary=True) as cur:
        cur.execute(sql, (limit,))
        return list(cur.fetchall())


def format_value(value: object, max_len: int) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def render_schema_section(tables: List[str], columns_map: Dict[str, List[Tuple[str, str, str]]]) -> List[str]:
    lines = ["Schema:"]
    for table in tables:
        cols = columns_map.get(table, [])
        col_names = ", ".join(c[0] for c in cols[:12])
        suffix = "..." if len(cols) > 12 else ""
        lines.append(f"- {table} ({len(cols)} cols): {col_names}{suffix}")
    return lines


def render_fk_section(fks: List[Tuple[str, str, str, str]]) -> List[str]:
    lines = ["Relationships:"]
    if not fks:
        lines.append("- (no foreign keys)")
        return lines
    for table, column, ref_table, ref_column in fks:
        lines.append(f"- {table}.{column} -> {ref_table}.{ref_column}")
    return lines


def render_tail_section(
    table: Optional[str],
    order_column: Optional[str],
    rows: List[Dict[str, object]],
    columns: List[str],
    max_len: int,
) -> List[str]:
    if not table:
        return ["Tail: (no tables found)"]
    lines = [f"Tail: {table} (order by {order_column}, last {len(rows)})"]
    if not rows:
        lines.append("- (no rows)")
        return lines
    for row in rows:
        parts = []
        for col in columns:
            value = row.get(col)
            parts.append(f"{col}={format_value(value, max_len)}")
        lines.append("- " + ", ".join(parts))
    return lines


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def build_view_text(cfg: MysqlConfig, args: argparse.Namespace) -> str:
    table_prefix = getattr(args, "table_prefix", None)
    table_contains = getattr(args, "table_contains", None)
    hint = getattr(args, "hint", None)
    smart_mode = bool(getattr(args, "smart_mode", False))
    tail_table_arg = getattr(args, "tail_table", None)
    tail_columns_arg = getattr(args, "tail_columns", None)
    tail_count = int(getattr(args, "tail_count", 0) or 0)
    raw_preview_chars = int(getattr(args, "raw_preview_chars", 0) or 0)
    if tail_count <= 0:
        tail_count = 7 if smart_mode else 5
    if raw_preview_chars <= 0:
        raw_preview_chars = 200

    conn = connect_mysql(cfg)
    try:
        tables = fetch_tables(conn, cfg.database)
        tables = filter_tables(tables, table_prefix, table_contains)
        columns_map = {t: fetch_columns(conn, cfg.database, t) for t in tables}
        fks = fetch_foreign_keys(conn, cfg.database)
        if table_prefix or table_contains:
            fks = [fk for fk in fks if fk[0] in tables and fk[2] in tables]

        tail_table = pick_tail_table(tables, tail_table_arg)
        if smart_mode and hint:
            hinted = select_table_from_hint(tables, hint)
            if hinted:
                tail_table = hinted
        tail_columns: List[str] = []
        tail_rows: List[Dict[str, object]] = []
        order_column: Optional[str] = None
        if tail_table:
            col_names = [c[0] for c in columns_map.get(tail_table, [])]
            if col_names:
                order_column = pick_order_column(col_names)
                tail_columns = pick_tail_columns(tail_table, col_names, tail_columns_arg)
                tail_rows = fetch_tail_rows(conn, tail_table, tail_columns, order_column, tail_count)

        header = [
            f"Live MySQL view @ {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"DB: {cfg.database} @ {cfg.host}:{cfg.port} (user: {cfg.user})",
            "",
        ]
        output = []
        output.extend(header)
        if smart_mode:
            output.append("Smart view:")
            output.extend(render_table_explanations(tables, columns_map))
            output.append("")
            output.extend(render_graph_section(fks))
            output.append("")
            output.extend(render_fk_section(fks))
            output.append("")
        else:
            output.extend(render_schema_section(tables, columns_map))
            output.append("")
            output.extend(render_fk_section(fks))
            output.append("")
        output.extend(render_tail_section(tail_table, order_column, tail_rows, tail_columns, raw_preview_chars))
        return "\n".join(output)
    finally:
        conn.close()


def run_once(cfg: MysqlConfig, args: argparse.Namespace) -> None:
    print(build_view_text(cfg, args))


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Live MySQL schema + tail viewer")
    ap.add_argument("--config-path", default=str(CONFIG_FILE), help="forensic_config.json path")
    ap.add_argument("--mysql-host", help="Override MySQL host")
    ap.add_argument("--mysql-port", type=int, help="Override MySQL port")
    ap.add_argument("--mysql-user", help="Override MySQL user")
    ap.add_argument("--mysql-password", help="Override MySQL password")
    ap.add_argument("--mysql-database", help="Override MySQL database")
    ap.add_argument("--table-prefix", help="Filter tables by prefix")
    ap.add_argument("--table-contains", help="Filter tables by substring")
    ap.add_argument("--hint", help="Smart hint to pick a tail table")
    ap.add_argument("--tail-table", help="Tail table name (default EVENTI_RAW)")
    ap.add_argument("--tail-columns", help="Comma-separated column list for tail output")
    ap.add_argument("--tail-count", type=int, default=0, help="Rows to show (smart default 7)")
    ap.add_argument("--raw-preview-chars", type=int, default=0, help="Max chars per value")
    ap.add_argument("--refresh-seconds", type=int, default=5, help="Refresh interval")
    ap.add_argument("--once", action="store_true", help="Run once and exit")
    ap.add_argument("--no-clear", action="store_true", help="Do not clear screen")
    ap.add_argument("--smart-mode", action="store_true", help="Smart view with explanations and graph")
    return ap


def main() -> None:
    args = build_arg_parser().parse_args()
    cfg = load_config(Path(args.config_path)) or MysqlConfig(
        host="127.0.0.1",
        port=3306,
        user="root",
        password="",
        database="forensic",
    )
    cfg = apply_overrides(cfg, args)

    if args.once:
        run_once(cfg, args)
        return

    while True:
        if not args.no_clear:
            clear_screen()
        try:
            run_once(cfg, args)
        except Exception as exc:
            print(f"Error: {exc}")
        time.sleep(max(1, args.refresh_seconds))


if __name__ == "__main__":
    main()
