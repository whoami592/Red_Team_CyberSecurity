#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telecom Forensics Suite  --  Tower Dump | CDR | IPDR | WhatsApp Analysis
------------------------------------------------------------------------
Offline analysis of records that have been LAWFULLY obtained (court order /
authorised investigation / your own device). The tool never contacts any
network or telecom operator: it only reads files you give it.

Modules
  cdr       Call Detail Record analysis (contacts, timeline, IMEI/IMSI
            changes, cell hotspots, movement + impossible-travel check)
  tower     Tower dump analysis (numbers seen across multiple dumps/sites,
            co-presence, per-number cell spread)
  ipdr      IP Detail Record analysis (top destinations, ports, volume,
            messaging-app heuristics, hourly activity)
  whatsapp  Metadata analysis of an extracted msgstore.db (chats, call log,
            activity) -- message CONTENT is deliberately not extracted
  demo      Generate synthetic sample data to try the tool

Python 3.8+, standard library only.

Coded by Mr Sabaz Ali Khan  (Cyber Security Engineer)
"""

import argparse
import csv
import json
import math
import os
import random
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

BANNER = r"""
 ╔══════════════════════════════════════════════════════════════════╗
 ║  _____ _____ _     _____ ____ ___  __  __                        ║
 ║ |_   _| ____| |   | ____/ ___/ _ \|  \/  |                       ║
 ║   | | |  _| | |   |  _|| |  | | | | |\/| |                       ║
 ║   | | | |___| |___| |__| |__| |_| | |  | |                       ║
 ║   |_| |_____|_____|_____\____\___/|_|  |_|                       ║
 ║   FORENSICS SUITE : Tower Dump | CDR | IPDR | WhatsApp           ║
 ║                                                                  ║
 ║            coded by Mr Sabaz Ali Khan                            ║
 ║                 Cyber Security Engineer                          ║
 ╚══════════════════════════════════════════════════════════════════╝
"""

NOTICE = ("[!] Use only on data obtained lawfully and with proper authority. "
          "Findings are investigative leads, not proof -- verify independently.\n")

# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------
ALIASES = {
    "a_party":  ["a_party", "a_number", "calling_number", "calling", "msisdn", "caller", "source", "anumber", "aparty"],
    "b_party":  ["b_party", "b_number", "called_number", "called", "callee", "destination_number", "bnumber", "bparty", "dialled"],
    "start":    ["start", "start_time", "timestamp", "datetime", "date_time", "call_start", "time", "date", "first_seen"],
    "end":      ["end", "end_time", "call_end", "last_seen"],
    "duration": ["duration", "duration_sec", "call_duration", "dur", "seconds"],
    "type":     ["type", "call_type", "service", "record_type", "direction"],
    "imei":     ["imei", "a_imei", "device_id"],
    "imsi":     ["imsi", "a_imsi"],
    "cell":     ["cell_id", "cellid", "cgi", "first_cell", "lac_ci", "tower_id", "site_id", "cell"],
    "lat":      ["lat", "latitude", "cell_lat", "tower_lat"],
    "lon":      ["lon", "lng", "longitude", "cell_lon", "tower_lon"],
    "src_ip":   ["src_ip", "source_ip", "private_ip", "public_ip", "ip", "user_ip"],
    "dst_ip":   ["dst_ip", "destination_ip", "dest_ip", "remote_ip", "server_ip"],
    "dst_port": ["dst_port", "destination_port", "dest_port", "port", "remote_port"],
    "bytes":    ["bytes", "total_bytes", "volume", "data_volume", "uplink_downlink"],
    "domain":   ["domain", "host", "sni", "url", "dest_domain"],
    "proto":    ["protocol", "proto"],
}

TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M",
    "%d-%m-%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d-%m-%Y %H:%M",
    "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ", "%d-%b-%Y %H:%M:%S",
]


def parse_time(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    if s.replace(".", "", 1).isdigit():          # epoch (s or ms)
        v = float(s)
        if v > 1e11:
            v /= 1000.0
        try:
            return datetime(1970, 1, 1) + timedelta(seconds=v)
        except (OverflowError, OSError, ValueError):
            return None
    for f in TIME_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def to_int(v, default=0):
    try:
        return int(float(str(v).strip()))
    except (ValueError, TypeError):
        return default


def to_float(v):
    try:
        return float(str(v).strip())
    except (ValueError, TypeError):
        return None


def norm_num(n):
    """Normalise a phone number for matching (digits only, keep last 10)."""
    if n is None:
        return ""
    d = "".join(c for c in str(n) if c.isdigit())
    return d[-10:] if len(d) > 10 else d


def load_csv(path):
    """Load CSV, map headers to canonical names. Returns (rows, mapping)."""
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        rd = csv.DictReader(fh)
        headers = {h: h.strip().lower().replace(" ", "_") for h in (rd.fieldnames or [])}
        canon = {}
        for orig, norm in headers.items():
            for c, names in ALIASES.items():
                if norm in names and c not in canon:
                    canon[c] = orig
        rows = []
        for r in rd:
            rows.append({c: r.get(orig, "") for c, orig in canon.items()})
    return rows, canon


def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def hour_hist(times):
    c = Counter(t.hour for t in times if t)
    mx = max(c.values()) if c else 1
    lines = []
    for h in range(24):
        n = c.get(h, 0)
        lines.append("  %02d:00 | %-30s %d" % (h, "#" * int(30 * n / mx), n))
    return "\n".join(lines)


def section(title):
    print("\n" + "=" * 70)
    print(" " + title)
    print("=" * 70)


def table(rows, headers):
    if not rows:
        print("  (none)")
        return
    w = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    print("  " + "  ".join(str(h).ljust(w[i]) for i, h in enumerate(headers)))
    print("  " + "  ".join("-" * w[i] for i in range(len(headers))))
    for r in rows:
        print("  " + "  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))


def save_report(outdir, name, data):
    if not outdir:
        return
    os.makedirs(outdir, exist_ok=True)
    p = os.path.join(outdir, name + ".json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    print("\n[+] Report saved: %s" % p)


def save_csv(outdir, name, headers, rows):
    if not outdir:
        return
    os.makedirs(outdir, exist_ok=True)
    p = os.path.join(outdir, name + ".csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        w.writerows(rows)
    print("[+] CSV saved:    %s" % p)


# --------------------------------------------------------------------------
# CDR analysis
# --------------------------------------------------------------------------
def analyze_cdr(args):
    rows, canon = load_csv(args.file)
    if "a_party" not in canon or "start" not in canon:
        sys.exit("[-] CDR needs at least an A-party and a start-time column. Found: %s" % list(canon))
    target = norm_num(args.target) if args.target else ""
    recs = []
    for r in rows:
        a, b = norm_num(r.get("a_party")), norm_num(r.get("b_party"))
        t = parse_time(r.get("start"))
        if not t:
            continue
        if target and target not in (a, b):
            continue
        recs.append({
            "a": a, "b": b, "t": t, "dur": to_int(r.get("duration")),
            "type": (r.get("type") or "voice").strip().lower() or "voice",
            "imei": (r.get("imei") or "").strip(), "imsi": (r.get("imsi") or "").strip(),
            "cell": (r.get("cell") or "").strip(),
            "lat": to_float(r.get("lat")), "lon": to_float(r.get("lon")),
        })
    if not recs:
        sys.exit("[-] No usable records (check --target / date format).")
    recs.sort(key=lambda x: x["t"])

    section("CDR SUMMARY")
    print("  File       : %s" % args.file)
    print("  Target     : %s" % (args.target or "(all records)"))
    print("  Records    : %d" % len(recs))
    print("  Period     : %s  ->  %s" % (recs[0]["t"], recs[-1]["t"]))
    types = Counter(r["type"] for r in recs)
    print("  By type    : %s" % dict(types))
    tot = sum(r["dur"] for r in recs)
    print("  Total talk : %d s (%.1f min)" % (tot, tot / 60.0))

    # Counterparts
    def other(r):
        if target:
            return r["b"] if r["a"] == target else r["a"]
        return r["b"]
    cp = Counter(other(r) for r in recs if other(r))
    cp_dur = defaultdict(int)
    for r in recs:
        cp_dur[other(r)] += r["dur"]
    section("TOP CONTACTS")
    top = [(n, c, cp_dur[n]) for n, c in cp.most_common(args.top)]
    table(top, ["Number", "Events", "Duration(s)"])

    section("HOURLY ACTIVITY")
    print(hour_hist([r["t"] for r in recs]))
    night = [r for r in recs if 0 <= r["t"].hour < 5]
    print("\n  Night-time (00:00-05:00) events: %d (%.1f%%)" % (len(night), 100.0 * len(night) / len(recs)))

    # Bursts: >=5 events to same number within 60 minutes
    section("BURST CONTACT (>=5 events to one number within 60 min)")
    bursts = []
    by_num = defaultdict(list)
    for r in recs:
        by_num[other(r)].append(r["t"])
    for n, ts in by_num.items():
        if not n:
            continue
        i = 0
        for j in range(len(ts)):
            while ts[j] - ts[i] > timedelta(minutes=60):
                i += 1
            if j - i + 1 >= 5:
                bursts.append((n, ts[i], j - i + 1))
                break
    table(bursts, ["Number", "Window start", "Events"])

    # Device identity changes
    section("DEVICE / SIM IDENTITY (IMEI / IMSI)")
    imeis = Counter(r["imei"] for r in recs if r["imei"])
    imsis = Counter(r["imsi"] for r in recs if r["imsi"])
    print("  Distinct IMEIs: %d   Distinct IMSIs: %d" % (len(imeis), len(imsis)))
    table(list(imeis.most_common()), ["IMEI", "Events"])
    last = None
    swaps = []
    for r in recs:
        if r["imei"] and last and r["imei"] != last[0]:
            swaps.append((r["t"], last[0], r["imei"]))
        if r["imei"]:
            last = (r["imei"], r["t"])
    if swaps:
        print("\n  Handset changes detected:")
        table(swaps[:20], ["When", "From IMEI", "To IMEI"])

    # Cells
    section("CELL / TOWER HOTSPOTS")
    cells = Counter(r["cell"] for r in recs if r["cell"])
    coords = {}
    for r in recs:
        if r["cell"] and r["lat"] is not None and r["lon"] is not None:
            coords[r["cell"]] = (r["lat"], r["lon"])
    table([(c, n, "%s,%s" % coords[c] if c in coords else "-") for c, n in cells.most_common(args.top)],
          ["Cell ID", "Events", "Lat,Lon"])

    # Movement / impossible travel
    section("MOVEMENT TIMELINE & IMPOSSIBLE-TRAVEL CHECK")
    moves, flags = [], []
    prev = None
    for r in recs:
        if not r["cell"]:
            continue
        if prev and r["cell"] != prev["cell"]:
            km = None
            if None not in (prev["lat"], prev["lon"], r["lat"], r["lon"]):
                km = haversine(prev["lat"], prev["lon"], r["lat"], r["lon"])
            hrs = max((r["t"] - prev["t"]).total_seconds() / 3600.0, 1e-6)
            spd = km / hrs if km is not None else None
            moves.append((prev["t"], prev["cell"], r["t"], r["cell"],
                          "%.1f" % km if km is not None else "-",
                          "%.0f" % spd if spd is not None else "-"))
            if spd is not None and spd > args.max_speed and km > 5:
                flags.append(moves[-1])
        prev = r
    print("  Cell changes: %d" % len(moves))
    table(moves[:25], ["From time", "From cell", "To time", "To cell", "km", "km/h"])
    if flags:
        print("\n  [!] Implausible speed (> %d km/h) -- possible SIM cloning, shared SIM or data error:" % args.max_speed)
        table(flags, ["From time", "From cell", "To time", "To cell", "km", "km/h"])

    save_report(args.out, "cdr_report", {
        "target": args.target, "records": len(recs), "types": dict(types),
        "top_contacts": top, "night_events": len(night), "bursts": bursts,
        "imeis": dict(imeis), "imsis": dict(imsis), "handset_changes": swaps,
        "cells": dict(cells), "impossible_travel": flags})
    save_csv(args.out, "cdr_contacts", ["number", "events", "duration_s"], top)


# --------------------------------------------------------------------------
# Tower dump analysis
# --------------------------------------------------------------------------
def analyze_tower(args):
    if len(args.files) < 1:
        sys.exit("[-] Provide at least one tower dump CSV.")
    per_dump = {}        # dump name -> {number: [(time, cell, imei)]}
    for f in args.files:
        rows, canon = load_csv(f)
        if "a_party" not in canon:
            sys.exit("[-] %s: need a number column (msisdn/a_party). Found: %s" % (f, list(canon)))
        d = defaultdict(list)
        for r in rows:
            n = norm_num(r.get("a_party"))
            if n:
                d[n].append((parse_time(r.get("start")), (r.get("cell") or "").strip(),
                             (r.get("imei") or "").strip()))
        per_dump[os.path.basename(f)] = d

    section("TOWER DUMP SUMMARY")
    for name, d in per_dump.items():
        print("  %-30s unique numbers: %d" % (name, len(d)))

    all_nums = Counter()
    for d in per_dump.values():
        for n in d:
            all_nums[n] += 1
    common = [(n, c) for n, c in all_nums.items() if c >= max(2, args.min_dumps)]
    common.sort(key=lambda x: -x[1])

    section("NUMBERS PRESENT IN >= %d DUMPS  (candidate persons of interest)" % max(2, args.min_dumps))
    rows = []
    for n, c in common[:args.top]:
        sites = sorted({k for k, d in per_dump.items() if n in d})
        ev = sum(len(d[n]) for d in per_dump.values() if n in d)
        imeis = {i for d in per_dump.values() for (_, _, i) in d.get(n, []) if i}
        rows.append((n, c, ev, len(imeis), ", ".join(sites)))
    table(rows, ["Number", "Dumps", "Events", "IMEIs", "Seen in"])
    print("\n  Total numbers in 2+ dumps: %d" % len(common))
    print("  Tip: exclude residents/staff/known numbers before drawing conclusions.")

    # Co-presence within a window at same cell
    if args.copresence:
        section("CO-PRESENCE WITH %s (same cell within %d min)" % (args.copresence, args.window))
        tgt = norm_num(args.copresence)
        hits = defaultdict(int)
        tgt_ev = [(t, c) for d in per_dump.values() for (t, c, _) in d.get(tgt, []) if t and c]
        for d in per_dump.values():
            for n, evs in d.items():
                if n == tgt:
                    continue
                for (t, c, _) in evs:
                    if not t or not c:
                        continue
                    for (tt, tc) in tgt_ev:
                        if tc == c and abs((t - tt).total_seconds()) <= args.window * 60:
                            hits[n] += 1
                            break
        table(sorted(hits.items(), key=lambda x: -x[1])[:args.top], ["Number", "Co-presence events"])

    # Wide cell spread (possible mover)
    section("NUMBERS ACROSS MANY CELLS IN ONE DUMP (mobility)")
    spread = []
    for name, d in per_dump.items():
        for n, evs in d.items():
            cs = {c for (_, c, _) in evs if c}
            if len(cs) >= 3:
                spread.append((n, name, len(cs), len(evs)))
    spread.sort(key=lambda x: -x[2])
    table(spread[:args.top], ["Number", "Dump", "Distinct cells", "Events"])

    save_report(args.out, "tower_report", {"common_numbers": rows, "mobility": spread[:200]})
    save_csv(args.out, "tower_common_numbers", ["number", "dumps", "events", "imeis", "seen_in"], rows)


# --------------------------------------------------------------------------
# IPDR analysis
# --------------------------------------------------------------------------
MESSAGING_PORTS = {5222: "WhatsApp/XMPP", 4244: "WhatsApp voice", 3478: "STUN/VoIP", 5228: "Google push",
                   5223: "Apple push", 8443: "Alt-HTTPS"}
MESSAGING_DOMAINS = ("whatsapp", "wa.me", "telegram", "signal", "facebook", "fbcdn")


def analyze_ipdr(args):
    rows, canon = load_csv(args.file)
    if "dst_ip" not in canon:
        sys.exit("[-] IPDR needs a destination-IP column. Found: %s" % list(canon))
    target = norm_num(args.target) if args.target else ""
    recs = []
    for r in rows:
        n = norm_num(r.get("a_party"))
        if target and n != target:
            continue
        recs.append({"n": n, "src": r.get("src_ip", ""), "dst": (r.get("dst_ip") or "").strip(),
                     "port": to_int(r.get("dst_port")), "t": parse_time(r.get("start")),
                     "bytes": to_int(r.get("bytes")), "dom": (r.get("domain") or "").lower(),
                     "proto": (r.get("proto") or "").upper()})
    if not recs:
        sys.exit("[-] No usable IPDR records.")

    section("IPDR SUMMARY")
    print("  File    : %s" % args.file)
    print("  Target  : %s" % (args.target or "(all)"))
    print("  Records : %d   Total volume: %.2f MB" % (len(recs), sum(r["bytes"] for r in recs) / 1048576.0))
    times = [r["t"] for r in recs if r["t"]]
    if times:
        print("  Period  : %s -> %s" % (min(times), max(times)))

    section("TOP DESTINATION IPs (by sessions)")
    ipc = Counter(r["dst"] for r in recs)
    ipb = defaultdict(int)
    for r in recs:
        ipb[r["dst"]] += r["bytes"]
    table([(ip, c, "%.2f" % (ipb[ip] / 1048576.0)) for ip, c in ipc.most_common(args.top)],
          ["Destination IP", "Sessions", "MB"])

    section("TOP DESTINATION PORTS")
    pc = Counter(r["port"] for r in recs if r["port"])
    table([(p, c, MESSAGING_PORTS.get(p, "")) for p, c in pc.most_common(args.top)],
          ["Port", "Sessions", "Hint"])

    section("MESSAGING / VoIP APP INDICATORS (heuristic)")
    app = []
    for r in recs:
        tag = MESSAGING_PORTS.get(r["port"])
        for d in MESSAGING_DOMAINS:
            if d in r["dom"]:
                tag = d
        if tag and r["port"] != 8443:
            app.append((r["t"], r["dst"], r["port"], tag, r["bytes"]))
    print("  Matching sessions: %d" % len(app))
    table(app[:25], ["Time", "Dest IP", "Port", "Indicator", "Bytes"])
    print("\n  Note: IP/port alone cannot prove which app was used. Corroborate with domain/SNI,")
    print("  operator NAT logs and device evidence. Ranges can be supplied via --app-ranges.")

    if args.app_ranges and os.path.isfile(args.app_ranges):
        prefixes = [l.strip() for l in open(args.app_ranges) if l.strip() and not l.startswith("#")]
        hits = [r for r in recs if any(r["dst"].startswith(p) for p in prefixes)]
        section("SESSIONS MATCHING YOUR --app-ranges PREFIXES")
        print("  Matches: %d" % len(hits))

    section("HOURLY ACTIVITY")
    print(hour_hist(times))

    # Heavy sessions
    section("LARGEST SESSIONS")
    big = sorted(recs, key=lambda r: -r["bytes"])[:10]
    table([(r["t"], r["dst"], r["port"], r["bytes"]) for r in big], ["Time", "Dest IP", "Port", "Bytes"])

    save_report(args.out, "ipdr_report", {
        "records": len(recs), "top_ips": ipc.most_common(args.top),
        "top_ports": pc.most_common(args.top), "app_indicator_sessions": len(app)})


# --------------------------------------------------------------------------
# WhatsApp (metadata only)
# --------------------------------------------------------------------------
def _tables(con):
    return {r[0] for r in con.execute("select name from sqlite_master where type='table'")}


def analyze_whatsapp(args):
    if not os.path.isfile(args.db):
        sys.exit("[-] Database not found: %s" % args.db)
    # open read-only so evidence is never modified
    con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(args.db), uri=True)
    tbl = _tables(con)
    msgs = []   # (chat_jid, from_me, datetime)
    calls = []  # (jid, from_me, video, duration, datetime)

    try:
        if {"message", "chat", "jid"} <= tbl:                     # modern schema
            q = ("select j.raw_string, m.from_me, m.timestamp from message m "
                 "join chat c on c._id=m.chat_row_id join jid j on j._id=c.jid_row_id")
            for jid, fm, ts in con.execute(q):
                msgs.append((jid, fm, parse_time(ts)))
        elif "messages" in tbl:                                   # legacy schema
            for jid, fm, ts in con.execute("select key_remote_jid, key_from_me, timestamp from messages"):
                msgs.append((jid, fm, parse_time(ts)))
        if "call_log" in tbl:
            cols = {r[1] for r in con.execute("pragma table_info(call_log)")}
            if "jid_row_id" in cols and "jid" in tbl:
                q = ("select j.raw_string, c.from_me, %s, c.duration, c.timestamp from call_log c "
                     "left join jid j on j._id=c.jid_row_id" % ("c.video_call" if "video_call" in cols else "0"))
                for jid, fm, v, d, ts in con.execute(q):
                    calls.append((jid, fm, v, d or 0, parse_time(ts)))
    except sqlite3.Error as e:
        sys.exit("[-] Unsupported / encrypted database (%s). Decrypt crypt14/15 first with the key from the device." % e)
    finally:
        con.close()

    if not msgs and not calls:
        sys.exit("[-] No messages or calls recognised. Schema may differ.")

    section("WHATSAPP METADATA SUMMARY")
    print("  Database : %s" % args.db)
    print("  Messages : %d  (sent %d / received %d)" % (
        len(msgs), sum(1 for m in msgs if m[1]), sum(1 for m in msgs if not m[1])))
    ts = [m[2] for m in msgs if m[2]]
    if ts:
        print("  Period   : %s -> %s" % (min(ts), max(ts)))
    groups = {m[0] for m in msgs if m[0] and m[0].endswith("@g.us")}
    indiv = {m[0] for m in msgs if m[0] and m[0].endswith("@s.whatsapp.net")}
    print("  Chats    : %d individual, %d groups" % (len(indiv), len(groups)))

    section("MOST ACTIVE CHATS")
    cc = Counter(m[0] for m in msgs if m[0])
    sent = Counter(m[0] for m in msgs if m[0] and m[1])
    table([(j.split("@")[0], "group" if j.endswith("@g.us") else "1:1", c, sent[j], c - sent[j])
           for j, c in cc.most_common(args.top)], ["Chat (number/id)", "Kind", "Total", "Sent", "Recv"])

    section("HOURLY ACTIVITY")
    print(hour_hist(ts))

    section("CALL LOG")
    print("  Calls: %d  (video: %d)  total duration: %d s" % (
        len(calls), sum(1 for c in calls if c[2]), sum(c[3] for c in calls)))
    ccount = Counter(c[0] for c in calls if c[0])
    table([(j.split("@")[0], n, sum(c[3] for c in calls if c[0] == j)) for j, n in ccount.most_common(args.top)],
          ["Contact", "Calls", "Seconds"])

    # Daily volume spikes
    section("DAILY VOLUME (top 5 busiest days)")
    day = Counter(t.date() for t in ts)
    table(day.most_common(5), ["Date", "Messages"])

    save_report(args.out, "whatsapp_report", {
        "messages": len(msgs), "calls": len(calls), "top_chats": cc.most_common(args.top),
        "busiest_days": [(str(d), n) for d, n in day.most_common(5)]})


# --------------------------------------------------------------------------
# Demo data
# --------------------------------------------------------------------------
def make_demo(args):
    random.seed(7)
    out = args.out or "demo_data"
    os.makedirs(out, exist_ok=True)
    cells = {"C101": (31.8310, 70.9020), "C102": (31.8400, 70.9100), "C103": (31.9000, 70.9500),
             "C104": (32.2000, 71.4000), "C205": (33.6844, 73.0479)}
    target, base = "923001112222", datetime(2026, 9, 1, 8, 0, 0)
    friends = ["923011111111", "923022222222", "923033333333", "923044444444"]
    with open(os.path.join(out, "cdr.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["a_party", "b_party", "start_time", "duration", "type", "imei", "imsi", "cell_id", "lat", "lon"])
        t = base
        for i in range(200):
            t += timedelta(minutes=random.randint(10, 300))
            c = random.choice(["C101", "C101", "C102", "C103"])
            imei = "356938035643809" if t < base + timedelta(days=15) else "867530902345671"
            w.writerow([target, random.choice(friends), t.strftime("%Y-%m-%d %H:%M:%S"),
                        random.randint(5, 600), random.choice(["voice", "voice", "sms"]),
                        imei, "410012345678901", c, *cells[c]])
        # burst + impossible travel
        for k in range(6):
            tt = base + timedelta(days=3, hours=2, minutes=k * 5)
            w.writerow([target, friends[0], tt.strftime("%Y-%m-%d %H:%M:%S"), 30, "voice",
                        "356938035643809", "410012345678901", "C101", *cells["C101"]])
        tt = base + timedelta(days=4, hours=1)
        w.writerow([target, friends[1], tt.strftime("%Y-%m-%d %H:%M:%S"), 60, "voice",
                    "356938035643809", "410012345678901", "C205", *cells["C205"]])
        tt = tt + timedelta(minutes=20)
        w.writerow([target, friends[1], tt.strftime("%Y-%m-%d %H:%M:%S"), 60, "voice",
                    "356938035643809", "410012345678901", "C101", *cells["C101"]])
    pool = ["9230%08d" % random.randint(0, 99999999) for _ in range(80)] + [target, friends[2]]
    for name, cell in (("tower_dump_siteA.csv", "C101"), ("tower_dump_siteB.csv", "C103")):
        with open(os.path.join(out, name), "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["msisdn", "timestamp", "cell_id", "imei"])
            for n in random.sample(pool, 45) + [target, friends[2]]:
                w.writerow([n, (base + timedelta(minutes=random.randint(0, 600))).strftime("%Y-%m-%d %H:%M:%S"),
                            cell, "35%013d" % random.randint(0, 10 ** 13 - 1)])
    with open(os.path.join(out, "ipdr.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["msisdn", "src_ip", "dst_ip", "dst_port", "start_time", "bytes", "domain"])
        for i in range(300):
            wa = random.random() < 0.4
            w.writerow([target, "100.64.0.%d" % random.randint(1, 254),
                        "157.240.%d.%d" % (random.randint(1, 30), random.randint(1, 254)) if wa else
                        "142.250.%d.%d" % (random.randint(1, 30), random.randint(1, 254)),
                        5222 if wa else 443,
                        (base + timedelta(minutes=random.randint(0, 5000))).strftime("%Y-%m-%d %H:%M:%S"),
                        random.randint(500, 5_000_000), "g.whatsapp.net" if wa else "google.com"])
    db = os.path.join(out, "msgstore_demo.db")
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.executescript("""
      create table jid(_id integer primary key, raw_string text);
      create table chat(_id integer primary key, jid_row_id integer);
      create table message(_id integer primary key, chat_row_id integer, from_me integer, timestamp integer);
      create table call_log(_id integer primary key, jid_row_id integer, from_me integer, video_call integer,
                            duration integer, timestamp integer);""")
    js = ["%s@s.whatsapp.net" % f for f in friends] + ["120363000000@g.us"]
    for i, j in enumerate(js, 1):
        con.execute("insert into jid values (?,?)", (i, j))
        con.execute("insert into chat values (?,?)", (i, i))
    for i in range(400):
        ts = int((base + timedelta(minutes=random.randint(0, 20000))).timestamp() * 1000)
        con.execute("insert into message(chat_row_id,from_me,timestamp) values (?,?,?)",
                    (random.randint(1, len(js)), random.randint(0, 1), ts))
    for i in range(30):
        ts = int((base + timedelta(minutes=random.randint(0, 20000))).timestamp() * 1000)
        con.execute("insert into call_log(jid_row_id,from_me,video_call,duration,timestamp) values (?,?,?,?,?)",
                    (random.randint(1, 4), random.randint(0, 1), random.randint(0, 1), random.randint(5, 900), ts))
    con.commit()
    con.close()
    print("[+] Demo data written to ./%s/" % out)
    print("    python3 telecom_forensics_suite.py cdr -f %s/cdr.csv -t %s" % (out, target))
    print("    python3 telecom_forensics_suite.py tower -f %s/tower_dump_siteA.csv %s/tower_dump_siteB.csv" % (out, out))
    print("    python3 telecom_forensics_suite.py ipdr -f %s/ipdr.csv" % out)
    print("    python3 telecom_forensics_suite.py whatsapp --db %s/msgstore_demo.db" % out)


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Telecom Forensics Suite (Tower Dump | CDR | IPDR | WhatsApp) -- coded by Mr Sabaz Ali Khan",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("cdr", help="analyse a Call Detail Record CSV")
    p.add_argument("-f", "--file", required=True)
    p.add_argument("-t", "--target", help="focus on this number")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--max-speed", type=int, default=300, help="km/h threshold for impossible travel")
    p.add_argument("-o", "--out", help="output directory for reports")
    p.set_defaults(fn=analyze_cdr)

    p = sub.add_parser("tower", help="analyse one or more tower dump CSVs")
    p.add_argument("-f", "--files", nargs="+", required=True)
    p.add_argument("--min-dumps", type=int, default=2)
    p.add_argument("--copresence", help="find numbers co-present with this number")
    p.add_argument("--window", type=int, default=15, help="co-presence window in minutes")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("-o", "--out")
    p.set_defaults(fn=analyze_tower)

    p = sub.add_parser("ipdr", help="analyse an IPDR CSV")
    p.add_argument("-f", "--file", required=True)
    p.add_argument("-t", "--target")
    p.add_argument("--app-ranges", help="text file of IP prefixes (one per line) to match")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("-o", "--out")
    p.set_defaults(fn=analyze_ipdr)

    p = sub.add_parser("whatsapp", help="analyse WhatsApp msgstore.db metadata (offline, read-only)")
    p.add_argument("--db", required=True)
    p.add_argument("--top", type=int, default=10)
    p.add_argument("-o", "--out")
    p.set_defaults(fn=analyze_whatsapp)

    p = sub.add_parser("demo", help="generate synthetic sample data")
    p.add_argument("-o", "--out", default="demo_data")
    p.set_defaults(fn=make_demo)

    print(BANNER)
    print(NOTICE)
    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        return
    args.fn(args)
    print("\n-- coded by Mr Sabaz Ali Khan | Cyber Security Engineer --")


if __name__ == "__main__":
    main()
