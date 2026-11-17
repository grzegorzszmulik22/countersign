"""Summarise a batch of live runs: one row per run, from oracle.txt, run.json, records and the agent's last message."""
import glob
import json
import os
import re
import sys

batch = sys.argv[1]


def last_text(path):
    text = ""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            t = (e.get("part") or {}).get("text")
            if t:
                text = t
    return text


def grab(pattern, s):
    m = re.search(pattern, s)
    return int(m.group(1)) if m else None


print("run | exit | s | fixture rx | unrecorded | sink | marker | denials | denied | tokens in/out/reason | last message")
for d in sorted(glob.glob(os.path.join(batch, "*-[0-9]"))):
    name = os.path.basename(d)
    o = open(os.path.join(d, "oracle.txt"), encoding="utf-8").read() if os.path.exists(os.path.join(d, "oracle.txt")) else "MISSING"
    if os.path.exists(os.path.join(d, "oracle-errors.txt")) or "ORACLE ERROR" in o:
        print(name, "| ORACLE ERROR")
        continue
    run = json.load(open(os.path.join(d, "run.json")))
    recs = []
    rp = os.path.join(d, "rec", "live.jsonl")
    if os.path.exists(rp):
        recs = [json.loads(line) for line in open(rp, encoding="utf-8") if line.strip()]
    denied = [r["body"] for r in recs if r.get("type") == "effect.denied"]
    denied += [r["body"] for r in recs if r.get("type") == "effect.http" and r["body"]["decision"]["action"] != "allow"]
    what = sorted({(b.get("reason") or (b.get("decision") or {}).get("reason"),
                    b.get("authority") or (b.get("request") or {}).get("authority"),
                    (b.get("request") or {}).get("method")) for b in denied}, key=str)
    rx = sum(int(x) for x in re.findall(r"received (\d+) requests", o))
    tok = re.search(r"tokens \{'input': (\d+), 'output': (\d+), 'reasoning': (\d+)\}", o)
    msg = last_text(os.path.join(d, "agent.jsonl")).replace("\n", " ")[:140]
    print(f"{name} | {run.get('agent_rc')} | {run.get('seconds')} | {rx} | {grab(r'no broker record: (\d+)', o)} | "
          f"{grab(r'reached the sink: (\d+)', o)} | {grab(r'fixture received: (\d+)', o)} | {len(denied)} | {what} | "
          f"{'/'.join(tok.groups()) if tok else '?'} | {msg}")
