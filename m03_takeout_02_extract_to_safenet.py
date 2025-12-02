#!/usr/bin/env python3
import argparse, datetime as dt, json, os, shutil, sqlite3, subprocess, sys
from pathlib import Path

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--account-label", required=True)
    p.add_argument("--from-date")
    p.add_argument("--to-date")
    return p.parse_args()

def resolve_account_id(conn, label):
    cur = conn.cursor()
    cur.execute("SELECT account_id FROM ACCOUNT_MASTER WHERE account_label=?", (label,))
    row = cur.fetchone()
    if not row: raise SystemExit(f"[ERROR] Account '{label}' non trovato.")
    return int(row[0])

def insert_takeout_acquisition(conn, account_id, tlabel, src, dst, tool_ver):
    cur = conn.cursor()
    ts = dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    cur.execute("""
        INSERT INTO TAKEOUT_ACQUISITIONS
        (account_id,takeout_label,source_root_path,safenet_root_path,acquisition_ts_utc,tool_version)
        VALUES (?,?,?,?,?,?)
    """, (account_id,tlabel,str(src),str(dst),ts,tool_ver))
    conn.commit()
    return cur.lastrowid

def main():
    a = parse_args()
    source = Path(a.source).resolve()
    target = Path(a.target).resolve()
    db = Path(a.db).resolve()

    conn = sqlite3.connect(db)
    account_id = resolve_account_id(conn, a.account_label)
    conn.close()

    run_id = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    tlabel = f"TAKEOUT_{run_id}"

    run_dir = target / a.account_label / f"takeout_{run_id}"
    raw_dir = run_dir / "RAW_ALL"
    rep_dir = run_dir / "REPORT"
    meta_dir = run_dir / "META"

    raw_dir.mkdir(parents=True, exist_ok=True)
    rep_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    print("[INFO] Copy RAW_ALL...")
    for item in source.iterdir():
        dest = raw_dir / item.name
        if item.is_dir(): shutil.copytree(item, dest, dirs_exist_ok=True)
        else: shutil.copy2(item, dest)

    report_script = Path(__file__).parent / "generate_takeout_report.py"
    cmd = [sys.executable, str(report_script), "--takeout-dir", str(raw_dir), "--report-dir", str(rep_dir)]
    if a.from_date: cmd += ["--from-date", a.from_date]
    if a.to_date:   cmd += ["--to-date", a.to_date]

    print("[INFO] Running generate_takeout_report.py...")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout); print(r.stderr); raise SystemExit("Errore report")
    print(r.stdout)

    meta = {
        "takeout_label": tlabel,
        "run_id": run_id,
        "account_label": a.account_label,
        "account_id": account_id,
        "source_root_path": str(source),
        "safenet_root_path": str(run_dir),
        "report_dir": str(rep_dir),
        "created_utc": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "from_date": a.from_date,
        "to_date": a.to_date
    }

    conn = sqlite3.connect(db)
    tid = insert_takeout_acquisition(conn, account_id, tlabel, source, run_dir, "generate_takeout_report.py")
    conn.close()

    meta["takeout_id"] = tid
    (meta_dir/"acquisition_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[INFO] takeout_id={tid} scritto.")
    
if __name__ == "__main__":
    main()
