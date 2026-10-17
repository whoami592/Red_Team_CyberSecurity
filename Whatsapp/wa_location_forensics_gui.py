#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhatsApp Location Forensics - GUI Edition
Offline analysis of location artifacts in a lawfully acquired, DECRYPTED
WhatsApp msgstore.db (Android). Evidence is opened READ-ONLY and hashed.

Coded by Cyber Security Engineer Mr Sabaz Ali Khan
Dependencies: Python 3.8+ standard library only (tkinter, sqlite3).
Use only on data you own or are legally authorised to examine.
"""

import csv
import datetime as dt
import hashlib
import html
import json
import os
import sqlite3
import sys
import tempfile
import webbrowser
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:  # headless / no tk
    tk = None

APP_NAME = "WhatsApp Location Forensics"
CREDIT = "Coded by Cyber Security Engineer Mr Sabaz Ali Khan"

BANNER = r"""
 ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
 ⣿⡇ __        ___    _     ___  ___   ___  ___   ⢸⣿
 ⣿⡇ \ \      / / \  | |   / _ \/ __| / _ \|  _ \  ⢸⣿
 ⣿⡇  \ \ /\ / / _ \ | |  | (_) | (__ | (_) | |_) | ⢸⣿
 ⣿⡇   \_/  \_/_/ \_\|_|   \___/ \___| \___/|____/  ⢸⣿
 ⣿⡇   WhatsApp Location Forensics  |  Cyber Investigation ⢸⣿
 ⣿⡇   Coded by Mr Sabaz Ali Khan - Cyber Security Engineer ⢸⣿
 ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
""".strip("\n")

LEGAL = (
    "This tool parses location artifacts from a WhatsApp database that you own "
    "or are legally authorised to examine (e.g. your own device backup, or "
    "evidence obtained with proper legal authority).\n\n"
    "It works fully offline on a decrypted msgstore.db. It does not access any "
    "account, server, or live device and cannot track anyone in real time.\n\n"
    "Do you confirm you are authorised to analyse the selected data?"
)

COLUMNS = ("id", "time_utc", "direction", "type", "chat", "sender",
           "latitude", "longitude", "place", "address")
HEADINGS = {"id": "ID", "time_utc": "Time (UTC)", "direction": "Dir",
            "type": "Type", "chat": "Chat", "sender": "Sender",
            "latitude": "Latitude", "longitude": "Longitude",
            "place": "Place", "address": "Address"}
WIDTHS = {"id": 60, "time_utc": 150, "direction": 70, "type": 70, "chat": 170,
          "sender": 170, "latitude": 95, "longitude": 95, "place": 150,
          "address": 220}


# --------------------------------------------------------------------------
# Core forensic logic (no GUI dependency)
# --------------------------------------------------------------------------
def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def is_sqlite(path):
    try:
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def open_readonly(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    return con


def table_cols(con, table):
    try:
        return [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
    except sqlite3.Error:
        return []


def ms_to_utc(ts):
    try:
        ts = int(ts)
        if ts <= 0:
            return ""
        if ts > 10 ** 11:  # milliseconds
            ts /= 1000.0
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError, TypeError):
        return ""


def valid_coord(lat, lon):
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return False
    if lat == 0.0 and lon == 0.0:
        return False
    return -90 <= lat <= 90 and -180 <= lon <= 180


def _pick(cols, alias, name):
    return f"{alias}.{name}" if name in cols else "NULL"


def parse_modern(con):
    """Current schema: message + message_location + chat + jid."""
    mc, lc = table_cols(con, "message"), table_cols(con, "message_location")
    cc, jc = table_cols(con, "chat"), table_cols(con, "jid")
    if not mc or not lc:
        return []
    sel = [
        "m._id", _pick(mc, "m", "timestamp"), _pick(mc, "m", "from_me"),
        _pick(mc, "m", "message_type"),
        _pick(lc, "l", "latitude"), _pick(lc, "l", "longitude"),
        _pick(lc, "l", "place_name"), _pick(lc, "l", "place_address"),
        _pick(lc, "l", "url"),
        _pick(lc, "l", "live_location_share_duration"),
        _pick(lc, "l", "live_location_final_latitude"),
        _pick(lc, "l", "live_location_final_longitude"),
        _pick(lc, "l", "live_location_final_timestamp"),
        _pick(cc, "c", "subject"),
        "cj.raw_string" if jc and "jid_row_id" in cc else "NULL",
        "sj.raw_string" if jc and "sender_jid_row_id" in mc else "NULL",
    ]
    joins = "LEFT JOIN chat c ON c._id = m.chat_row_id " if cc and "chat_row_id" in mc else ""
    if joins == "":
        sel[13] = "NULL"
    if jc and "jid_row_id" in cc and joins:
        joins += "LEFT JOIN jid cj ON cj._id = c.jid_row_id "
    if jc and "sender_jid_row_id" in mc:
        joins += "LEFT JOIN jid sj ON sj._id = m.sender_jid_row_id "
    sql = (f"SELECT {', '.join(sel)} FROM message_location l "
           f"JOIN message m ON m._id = l.message_row_id {joins}ORDER BY 2")
    out = []
    for r in con.execute(sql):
        (mid, ts, from_me, mtype, lat, lon, place, addr, url, dur,
         flat, flon, fts, subject, chat_jid, sender_jid) = r
        live = bool(dur) or mtype == 16
        if not valid_coord(lat, lon):
            if valid_coord(flat, flon):
                lat, lon = flat, flon
            else:
                continue
        extra = ""
        if live:
            extra = f"live share {dur or '?'}s"
            if valid_coord(flat, flon):
                extra += f"; final {flat},{flon} @ {ms_to_utc(fts)}"
        out.append({
            "id": mid, "time_utc": ms_to_utc(ts),
            "direction": "Sent" if from_me else "Received",
            "type": "Live" if live else "Static",
            "chat": subject or chat_jid or "", "sender": "Device owner" if from_me else (sender_jid or chat_jid or ""),
            "latitude": float(lat), "longitude": float(lon),
            "place": place or "", "address": addr or "",
            "url": url or "", "notes": extra,
        })
    return out


def parse_legacy(con):
    """Old schema: single 'messages' table with latitude/longitude."""
    mc = table_cols(con, "messages")
    if not mc or "latitude" not in mc or "longitude" not in mc:
        return []
    sel = [
        _pick(mc, "m", "_id"), _pick(mc, "m", "timestamp"),
        _pick(mc, "m", "key_from_me"), _pick(mc, "m", "latitude"),
        _pick(mc, "m", "longitude"), _pick(mc, "m", "media_name"),
        _pick(mc, "m", "data"), _pick(mc, "m", "key_remote_jid"),
        _pick(mc, "m", "remote_resource"),
    ]
    out = []
    for (mid, ts, from_me, lat, lon, name, data, chat, res) in con.execute(
            f"SELECT {', '.join(sel)} FROM messages m ORDER BY 2"):
        if not valid_coord(lat, lon):
            continue
        out.append({
            "id": mid, "time_utc": ms_to_utc(ts),
            "direction": "Sent" if from_me else "Received",
            "type": "Static", "chat": chat or "",
            "sender": "Device owner" if from_me else (res or chat or ""),
            "latitude": float(lat), "longitude": float(lon),
            "place": name or "", "address": data or "", "url": "", "notes": "",
        })
    return out


def analyse(path):
    """Return (records, schema_name, sha256). Evidence is never modified."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if not is_sqlite(path):
        raise ValueError(
            "Not a plain SQLite file. If this is msgstore.db.crypt12/14/15 it "
            "must first be decrypted with the owner's key file.")
    digest = sha256_file(path)
    con = open_readonly(path)
    try:
        recs = parse_modern(con)
        schema = "modern (message_location)"
        if not recs:
            leg = parse_legacy(con)
            if leg:
                recs, schema = leg, "legacy (messages)"
            elif not table_cols(con, "message_location") and not table_cols(con, "messages"):
                raise ValueError("No WhatsApp message tables found in this database.")
        return recs, schema, digest
    finally:
        con.close()


def map_url(lat, lon):
    return f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"


def summarise(recs):
    if not recs:
        return {"total": 0}
    times = [r["time_utc"] for r in recs if r["time_utc"]]
    return {
        "total": len(recs),
        "sent": sum(r["direction"] == "Sent" for r in recs),
        "received": sum(r["direction"] == "Received" for r in recs),
        "live": sum(r["type"] == "Live" for r in recs),
        "first": min(times) if times else "",
        "last": max(times) if times else "",
        "chats": len({r["chat"] for r in recs}),
    }


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------
def _safe(v):
    """Neutralise spreadsheet formula injection for text cells."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def export_csv(recs, path):
    keys = ["id", "time_utc", "direction", "type", "chat", "sender",
            "latitude", "longitude", "place", "address", "url", "notes"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(keys)
        for r in recs:
            w.writerow([_safe(r[k]) if k not in ("latitude", "longitude") else r[k] for k in keys])


def export_json(recs, path, meta):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "locations": recs}, f, indent=2, ensure_ascii=False)


def export_html(recs, path, meta):
    e = html.escape
    rows = "".join(
        "<tr>" + "".join(f"<td>{e(str(r[k]))}</td>" for k in
                         ("id", "time_utc", "direction", "type", "chat", "sender",
                          "latitude", "longitude", "place", "address"))
        + f'<td><a href="{e(map_url(r["latitude"], r["longitude"]))}">map</a></td></tr>'
        for r in recs)
    metas = "".join(f"<li><b>{e(k)}:</b> {e(str(v))}</li>" for k, v in meta.items())
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>{e(APP_NAME)} Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f1419;color:#d7dde4}}
h1{{color:#2ee6a6}}table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #2a3340;padding:6px 8px;text-align:left}}th{{background:#18212b;color:#2ee6a6}}
a{{color:#59b8ff}}footer{{margin-top:24px;color:#7d8a99}}</style></head><body>
<h1>{e(APP_NAME)} - Report</h1><ul>{metas}</ul>
<table><tr><th>ID</th><th>Time (UTC)</th><th>Dir</th><th>Type</th><th>Chat</th><th>Sender</th>
<th>Lat</th><th>Lon</th><th>Place</th><th>Address</th><th>Map</th></tr>{rows}</table>
<footer>{e(CREDIT)}</footer></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# --------------------------------------------------------------------------
# Demo database (synthetic data for testing the tool)
# --------------------------------------------------------------------------
def create_demo_db(path):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);
    CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
    CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER,
        sender_jid_row_id INTEGER, timestamp INTEGER, message_type INTEGER, text_data TEXT);
    CREATE TABLE message_location (message_row_id INTEGER, chat_row_id INTEGER,
        latitude REAL, longitude REAL, place_name TEXT, place_address TEXT, url TEXT,
        live_location_share_duration INTEGER, live_location_final_latitude REAL,
        live_location_final_longitude REAL, live_location_final_timestamp INTEGER);
    INSERT INTO jid VALUES (1,'15550001111@s.whatsapp.net'),(2,'15550002222@s.whatsapp.net');
    INSERT INTO chat VALUES (1,1,NULL),(2,2,'Demo Group');
    INSERT INTO message VALUES
      (1,1,0,1,1760000000000,5,NULL),(2,1,1,NULL,1760003600000,5,NULL),
      (3,2,0,2,1760007200000,16,NULL);
    INSERT INTO message_location VALUES
      (1,1,31.8313,70.9017,'Demo Cafe','Demo Street',NULL,NULL,NULL,NULL,NULL),
      (2,1,33.6844,73.0479,'Demo Park','Sample Road',NULL,NULL,NULL,NULL,NULL),
      (3,2,34.0151,71.5249,'','',NULL,900,34.0200,71.5300,1760008100000);
    """)
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
BG, PANEL, FG, ACCENT, MUTED = "#0f1419", "#18212b", "#d7dde4", "#2ee6a6", "#7d8a99"


class App:
    def __init__(self, root):
        self.root = root
        self.records, self.view = [], []
        self.db_path, self.sha, self.schema = "", "", ""
        root.title(f"{APP_NAME} - Mr Sabaz Ali Khan")
        root.geometry("1250x780")
        root.configure(bg=BG)
        self._style()
        self._build()
        self.log("Ready. " + CREDIT)

    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL)
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background="#1f2b38", foreground=ACCENT,
                    font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", "#245c4a")])
        s.configure("TButton", background="#1f2b38", foreground=FG, padding=6)
        s.map("TButton", background=[("active", "#2a3a4b")])
        s.configure("Accent.TButton", background="#1d8f6c", foreground="white")
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("TEntry", fieldbackground=PANEL, foreground=FG)

    def _build(self):
        r = self.root
        tk.Label(r, text=BANNER, font=("Consolas", 8), fg=ACCENT, bg=BG,
                 justify="left").pack(anchor="w", padx=10, pady=(6, 2))

        case = ttk.Frame(r)
        case.pack(fill="x", padx=10, pady=4)
        self.case_id, self.examiner, self.search = tk.StringVar(), tk.StringVar(), tk.StringVar()
        ttk.Label(case, text="Case ID:").pack(side="left")
        ttk.Entry(case, textvariable=self.case_id, width=18).pack(side="left", padx=(4, 12))
        ttk.Label(case, text="Examiner:").pack(side="left")
        ttk.Entry(case, textvariable=self.examiner, width=22).pack(side="left", padx=(4, 12))
        ttk.Label(case, text="Filter:").pack(side="left")
        e = ttk.Entry(case, textvariable=self.search, width=28)
        e.pack(side="left", padx=4)
        self.search.trace_add("write", lambda *_: self.apply_filter())

        bar = ttk.Frame(r)
        bar.pack(fill="x", padx=10, pady=4)
        for text, cmd, style in (
            ("Open msgstore.db", self.open_db, "Accent.TButton"),
            ("Re-scan", self.scan, "TButton"),
            ("Open in Map", self.open_map, "TButton"),
            ("Export CSV", lambda: self.export("csv"), "TButton"),
            ("Export JSON", lambda: self.export("json"), "TButton"),
            ("Export HTML Report", lambda: self.export("html"), "TButton"),
            ("Create Demo DB", self.demo, "TButton"),
        ):
            ttk.Button(bar, text=text, command=cmd, style=style).pack(side="left", padx=3)

        self.info = tk.StringVar(value="No evidence loaded.")
        ttk.Label(r, textvariable=self.info, foreground=MUTED).pack(anchor="w", padx=12)

        frame = ttk.Frame(r)
        frame.pack(fill="both", expand=True, padx=10, pady=4)
        self.tree = ttk.Treeview(frame, columns=COLUMNS, show="headings", selectmode="browse")
        for c in COLUMNS:
            self.tree.heading(c, text=HEADINGS[c], command=lambda c=c: self.sort_by(c))
            self.tree.column(c, width=WIDTHS[c], anchor="w")
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", lambda _e: self.open_map())

        self.logbox = tk.Text(r, height=7, bg=PANEL, fg=FG, relief="flat",
                              font=("Consolas", 9), state="disabled")
        self.logbox.pack(fill="x", padx=10, pady=(0, 4))
        tk.Label(r, text=CREDIT, fg=MUTED, bg=BG, font=("Segoe UI", 8)).pack(pady=(0, 6))
        self._sort_rev = {}

    # -- helpers
    def log(self, msg):
        ts = dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")
        self.logbox.configure(state="normal")
        self.logbox.insert("end", f"[{ts} UTC] {msg}\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def meta(self):
        return {
            "tool": APP_NAME, "author": "Mr Sabaz Ali Khan (Cyber Security Engineer)",
            "case_id": self.case_id.get(), "examiner": self.examiner.get(),
            "evidence_file": self.db_path, "sha256": self.sha, "schema": self.schema,
            "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "summary": summarise(self.records),
        }

    # -- actions
    def open_db(self):
        p = filedialog.askopenfilename(
            title="Select decrypted msgstore.db",
            filetypes=[("SQLite DB", "*.db *.sqlite *.sqlite3"), ("All files", "*.*")])
        if not p:
            return
        if not messagebox.askyesno("Authorisation required", LEGAL):
            self.log("Analysis cancelled: authorisation not confirmed.")
            return
        self.db_path = p
        self.scan()

    def scan(self):
        if not self.db_path:
            messagebox.showinfo(APP_NAME, "Open a database first.")
            return
        try:
            self.records, self.schema, self.sha = analyse(self.db_path)
        except Exception as ex:
            self.log(f"ERROR: {ex}")
            messagebox.showerror(APP_NAME, str(ex))
            return
        s = summarise(self.records)
        self.info.set(
            f"{os.path.basename(self.db_path)} | SHA-256 {self.sha[:24]}... | schema: {self.schema} | "
            f"{s['total']} locations ({s.get('sent', 0)} sent / {s.get('received', 0)} received / "
            f"{s.get('live', 0)} live)")
        self.log(f"Evidence hashed (SHA-256): {self.sha}")
        self.log(f"Opened read-only. Found {s['total']} location artifact(s). "
                 f"Range: {s.get('first', '-')} to {s.get('last', '-')}")
        self.apply_filter()

    def apply_filter(self):
        q = self.search.get().strip().lower()
        self.view = [r for r in self.records if not q or q in " ".join(
            str(r[k]) for k in COLUMNS).lower()]
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(self.view):
            self.tree.insert("", "end", iid=str(i), values=[
                f"{r[c]:.6f}" if c in ("latitude", "longitude") else r[c] for c in COLUMNS])

    def sort_by(self, col):
        rev = self._sort_rev.get(col, False)
        self.records.sort(key=lambda r: (r[col] is None, r[col]), reverse=rev)
        self._sort_rev[col] = not rev
        self.apply_filter()

    def open_map(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a row first.")
            return
        r = self.view[int(sel[0])]
        webbrowser.open(map_url(r["latitude"], r["longitude"]))
        self.log(f"Opened map for message {r['id']} ({r['latitude']}, {r['longitude']})")

    def export(self, kind):
        if not self.records:
            messagebox.showinfo(APP_NAME, "Nothing to export.")
            return
        ext = {"csv": ".csv", "json": ".json", "html": ".html"}[kind]
        p = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(kind.upper(), "*" + ext)])
        if not p:
            return
        try:
            if kind == "csv":
                export_csv(self.records, p)
            elif kind == "json":
                export_json(self.records, p, self.meta())
            else:
                export_html(self.records, p, self.meta())
        except OSError as ex:
            messagebox.showerror(APP_NAME, str(ex))
            return
        self.log(f"Exported {kind.upper()} -> {p}")

    def demo(self):
        p = os.path.join(tempfile.gettempdir(), "demo_msgstore.db")
        create_demo_db(p)
        self.db_path = p
        self.log(f"Synthetic demo database created: {p}")
        self.scan()


def main():
    if "--cli" in sys.argv or tk is None:
        print(BANNER)
        if len(sys.argv) < 3 or sys.argv[1] != "--cli":
            print("Usage: wa_location_forensics_gui.py            (GUI)\n"
                  "       wa_location_forensics_gui.py --cli msgstore.db")
            return
        recs, schema, digest = analyse(sys.argv[2])
        print(f"SHA-256: {digest}\nSchema: {schema}\nLocations: {len(recs)}")
        for r in recs:
            print(f"{r['time_utc']} {r['direction']:8} {r['type']:6} "
                  f"{r['latitude']:.6f},{r['longitude']:.6f} {r['place']}")
        return
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
