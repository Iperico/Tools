#!/usr/bin/env python3
import argparse, csv, sqlite3, json
from pathlib import Path

SRC=["PLAY_INSTALLS","PLAY_ORDERS","PLAY_PURCHASES","PLAY_SUBSCRIPTIONS","ACCESS_LOG"]

def parse():
    p=argparse.ArgumentParser()
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--account-label", required=True)
    p.add_argument("--takeout-label")
    p.add_argument("--source-type", required=True, choices=SRC)
    p.add_argument("--limit-per-run", type=int, default=1000)
    return p.parse_args()

def resolve_account_id(conn, label):
    cur=conn.cursor()
    cur.execute("SELECT account_id FROM ACCOUNT_MASTER WHERE account_label=?", (label,))
    r=cur.fetchone()
    if not r: raise SystemExit("Account non trovato")
    return r[0]

def get_run(dataset,acc,lab):
    accdir=dataset/acc
    if lab:
        return accdir/lab
    r=[p for p in accdir.iterdir() if p.is_dir() and p.name.startswith("takeout_")]
    if not r: raise SystemExit("No takeout_*")
    return sorted(r)[-1]

def insert_event(cur,ts,acc,prod,app,title,sub,file,ip=None,amt=None,curr=None,extra=None):
    cur.execute("""
        INSERT INTO EVENTI_ANDROID
        (timestamp_utc,account_id,product,app,title,source,source_subtype,
         source_file,ip_remoto,amount,currency_code,extra_details)
        VALUES (?,?,?,?,?,?,?, ?,?,?,?,?)
    """,(ts,acc,prod,app,title,"TAKEOUT",sub,file,ip,amt,curr,extra))

def load_generic(path, limit, handler):
    with path.open() as f:
        r=csv.DictReader(f)
        for idx,row in enumerate(r,1):
            yield idx,row
            if idx>=limit: break

def main():
    a=parse()
    dataset=Path(a.dataset-root)  # FIX BELOW in final message
