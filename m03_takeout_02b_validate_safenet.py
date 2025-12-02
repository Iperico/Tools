#!/usr/bin/env python3
import argparse, csv, json
from pathlib import Path

def parse():
    p=argparse.ArgumentParser()
    p.add_argument("--dataset-root", required=True)
    p.add_argument("--account-label", required=True)
    p.add_argument("--takeout-label")
    return p.parse_args()

def count_rows(p):
    if not p.is_file(): return 0
    with p.open() as f:
        r=csv.reader(f); next(r,None)
        return sum(1 for _ in r)

def load_summary(p):
    if not p.is_file(): return {}
    with p.open() as f:
        r=csv.DictReader(f)
        out={}
        for row in r:
            out[row["metric"]]=row["value"]
        return out

def validate_pair(data, summ, metric):
    rows = count_rows(data)
    summary = load_summary(summ)
    exp = summary.get(metric)
    if exp is None:
        return ("WARN", f"{data.name}: metric '{metric}' assente")
    try: exp=int(float(exp))
    except: return ("WARN", f"{data.name}: metric '{metric}' non numerico")
    if exp!=rows: return ("WARN", f"{data.name} mismatch {rows} vs {exp}")
    return ("OK", f"{data.name} OK ({rows})")

def main():
    a=parse()
    root=Path(a.dataset_root)
    acc=root/a.account_label
    if a.takeout_label:
        run=acc/a.takeout_label
    else:
        runs=[p for p in acc.iterdir() if p.is_dir() and p.name.startswith("takeout_")]
        if not runs: raise SystemExit("Nessun takeout trovato.")
        run=sorted(runs)[-1]

    rep=run/"REPORT"
    print(f"[INFO] Validating: {run}")

    pairs=[
        ("installs.csv","installs_summary.csv","total_installs"),
        ("devices.csv","devices_summary.csv","total_devices"),
        ("orders.csv","orders_summary.csv","total_orders"),
        ("purchases.csv","purchases_summary.csv","total_purchases"),
        ("subscriptions.csv","subscriptions_summary.csv","total_subscriptions"),
        ("access_log.csv","access_log_summary.csv","total_rows"),
    ]

    for data, summ, metric in pairs:
        dp=rep/data; sp=rep/summ
        if not dp.exists(): 
            print(f"[WARN] Missing {dp.name}")
            continue
        if not sp.exists():
            print(f"[WARN] Missing {sp.name}")
            continue
        s,m=validate_pair(dp,sp,metric)
        tag="[CHECK]" if s=="OK" else "[WARN]"
        print(tag,m)

if __name__=="__main__":
    main()
