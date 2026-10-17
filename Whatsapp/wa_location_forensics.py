#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhatsApp Location Forensics  |  Legal Cyber Investigation
=========================================================
Coded by Mr Sabaz Ali Khan  (Cyber Security Engineer)

Offline forensic parser that extracts LOCATION ARTIFACTS (shared locations and
live-location shares) from a WhatsApp Android `msgstore.db` that has ALREADY been
lawfully acquired from a device (court order, warrant, corporate policy, or the
device owner's written consent).

What it does
  * Verifies evidence integrity (MD5 / SHA-256 before and after analysis)
  * Opens the database strictly READ-ONLY (immutable) - evidence is never modified
  * Auto-detects old (`messages`) and new (`message` + `message_location`) schemas
  * Resolves chat / sender JIDs, optional contact names from wa.db
  * Exports CSV, JSON, KML (Google Earth) and a self-contained HTML report
  * Writes a chain-of-custody log

What it does NOT do
  * It does not track anyone remotely, intercept traffic, or exploit WhatsApp.
  * It does not decrypt .crypt14/.crypt15 backups. Provide a decrypted SQLite DB
    obtained through lawful acquisition (your forensic suite, or the account owner's key).

Usage
  python3 wa_location_forensics.py --db msgstore.db --case-id CASE-001 \
      --examiner "Mr Sabaz Ali Khan" --authority "Warrant #1234" --confirm-authorized
  python3 wa_location_forensics.py --selftest
"""

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import sqlite3
import sys
import tempfile

BANNER = r"""
⠀⠀⣸⢀⡇⠀⢸⣿⠀⠀⡆⠀⢠⡟⢀⣼⠋⣾⠀⡆⣾⠀⢸⡟⣷⡀⠀⠀⢿⢻⣧⠀⠀⠀⠀⠀⢸⣿⠛⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⡏⣸⠁⠀⣸⣿⡆⠀⡇⢰⣾⢣⡾⠁⠀⡿⠀⣇⠸⡆⠈⣷⢹⣷⠀⠀⢹⠈⢿⣶⣶⣄⠀⢸⣯⢿⣗⠢⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⢃⢿⠀⠀⢹⡇⣿⣄⢳⣼⣿⠏⠀⠀⠀⠀⢠⣿⡆⣷⠀⣿⠸⡿⣧⠀⢸⣷⠾⢿⣿⣿⠀⡘⣿⣿⣯⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣾⣿⣾⣿⡆⠀⣸⣷⣧⣹⣾⣿⡧⣄⣼⡀⢀⣸⣾⣿⣿⡿⡄⢸⣀⣇⣹⡷⣤⣿⣷⡄⢻⣿⣷⠃⣸⡇⠘⣆⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣧⣀⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣏⣫⣿⣷⣌⣿⣿⣿⣿⣿⣿⣿⣿⡀⠻⣿⣷⣏⢹⣄⠹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⠟⠙⣧⣿⡇⢈⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⠀⠈⢽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠛⣟⢯⠻⣯⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⠏⢀⣀⣹⣿⣿⠏⢸⣿⣿⢿⣿⣿⠀⢻⣿⣿⡀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠿⣦⣀⢾⣬⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣾⣿⣿⣿⣿⣿⠀⠀⣾⣿⠘⣿⣿⠀⠘⢻⣿⣯⣦⣭⣉⣹⣿⣿⣿⣿⣿⣿⣿⣿⣻⣷⠀⠠⡖⡎⠻⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠟⠿⠿⠿⣩⠁⠀⠻⡄⢠⣿⣿⣧⢿⡏⠀⠀⠉⠛⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⢿⣿⠻⣧⣴⣷⠃⠀⠙⠧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡆⠀⠀⠀⠉⠁⠀⠀⠹⣾⠋⠘⣿⣼⣛⠀⠀⠀⠀⠾⠿⢭⡋⢙⣚⣿⣿⣿⣿⡯⠈⠻⣼⡀⣿⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡇⠀⠀⠀⠀⠀⠀⠀⣸⠟⠒⢀⠹⢹⣇⠀⠀⠀⠀⠀⠀⠀⠉⠀⠉⢹⣿⣿⣿⡗⠁⢠⣼⣧⣿⢸⠁⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠁⠰⣤⡆⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡿⣿⢿⡁⡶⣾⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠏⠀⣿⣿⣩⣿⢿⠿⣭⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⡿⣿⡟⠀⠙⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣟⣻⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡀⠀⠀⠀⢿⣿⣷⡶⠶⠶⠶⣶⣶⣾⣿⣿⣿⣿⣿⠀⠀⠀⠀⢀⣼⣿⣿⡏⠙⢻⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣷⡀⠀⠀⠀⠙⠳⠦⢤⣄⣀⣀⣀⣀⣀⣸⡿⠟⠁⠀⠀⠀⢀⣾⣿⣿⣿⡇⠀⠘⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣧⣀⠀⠀⠀⠀⠀⠀⠠⠤⠤⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⡉⠻⠿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠛⢿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣷⣿⣿⣿⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⣿⠋⠉⠙⠻⢶⣄⠀⠀⠀⠀⣀⣤⡶⣿⡿⠟⠋⢹⣿⢻⣟⠃⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢸⣿⡄⠀⠀⠀⠀⠛⠿⣶⣶⣴⣿⠟⠊⠁⠀⠀⣼⣾⠻⣏⣹⠀⣨⠿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡄⢰⠹⣿⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⣠⠞⢹⣿⢷⣿⣤⡟⠁⠀⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡃⡀⠀⠙⣆⠀⠀⠀⢀⣀⠀⠐⠀⠀⣀⡴⠛⠁⠀⢸⡟⠀⠘⣿⡀⠀⠀⠀⢿⣿⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠃⢹⡄⠀⢹⣷⡄⠀⠀⢘⣀⣠⠴⠛⠁⠀⠀⠀⠀⣼⣧⠀⢀⡿⠃⠀⠀⠀⠘⣿⣿⣿⡿⠓⠦⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢻⣀⣼⠿⣧⣤⡴⠛⠉⠁⠀⠀⠀⡄⠀⠀⠀⠙⠓⢠⡞⠀⠀⠀⠀⠀⠘⢿⡙⢿⣷⡄⠀⠀⠈⠳⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠹⢏⠀⠹⣇⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀⣰⠏⠀⣀⣤⣶⣤⡀⠀⢸⡷⣌⣿⣿⠀⠀⠀⠀⠀⠉⠓⠦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣾⣿⣿⣎⠀⢀⣽⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⢰⢇⣠⣾⣿⣿⣿⠻⣿⡄⢸⣷⠈⢹⣿⣆⡀⠀⠀⠀⠀⠀⠀⠀⠙⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⡏⢠⠀⢶⡿⡿⠀⠀⠀⠀⠀⢸⠏⠀⠀⣀⣴⢿⣿⣿⣿⣿⣿⡟⠀⠙⣿⣿⣿⡆⠈⣿⣿⠙⠲⢄⡀⠀⠀⠀⠀⠀⠀⠈⠳⣄⡀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⡏⣴⠶⠿⣥⡀⠀⠀⠀⠀⠀⠈⣠⠖⠋⠉⠀⣼⣿⣿⢻⣿⣿⣿⠀⢰⣿⣿⣿⡇⠴⢿⣿⠀⠀⠀⠙⠦⣄⠀⠀⠀⠀⠀⠀⠈⠙⢦⡀⠀⠀⠀⠀⠀
⢻⣿⡇⠀⠰⣶⡌⠙⢦⠀⠤⠄⣤⡎⠁⠀⠀⠀⣰⣿⠓⠁⠀⣿⣿⣿⣇⣼⣿⣿⣿⡇⠀⠀⠙⡆⠀⠀⠀⠀⠈⠰⣄⠀⠀⢀⣀⣤⠄⠀⠉⢳⡀⠀⠀⠀
⠀⠹⣿⡀⠈⠹⠅⠀⡼⠓⠶⠛⢻⠇⠀⠀⠀⣰⣿⠇⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⢀⠇⠀⢠⡀⠀⠀⠀⠘⣿⠞⠉⠀⠀⠀⠀⠀⠰⠙⣆⠀⠀
⠀⠙⢟⣿⣄⠀⠀⠸⠀⠀⠀⠀⣼⠁⣀⣴⣿⡿⠋⠀⠀⠀⣸⣿⣿⣿⡟⢿⣿⣿⡟⠀⠀⢸⣿⠀⠀⠈⣇⠀⠀⠀⠘⠋⠃⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀
⠒⢤⣀⣀⣙⣷⣦⣀⠳⣄⢀⣸⣁⣾⣿⡿⠉⠀⢀⡀⠀⢀⣿⣿⣿⠟⠀⠀⠉⣉⠀⠀⣠⣾⡟⠀⠀⠀⣼⠀⠀⠀⢀⣀⡀⣸⠃⠀⠀⠀⠀⠀⠀⠀⠘⢧
"""

CREDIT = "Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer"
TOOL = "WhatsApp Location Forensics | Legal Cyber Investigation"
VERSION = "1.0"

LEGAL_NOTICE = (
    "LEGAL NOTICE: Use only on evidence you are lawfully authorised to examine\n"
    "(warrant / court order / written owner consent / employer policy).\n"
    "Unauthorised analysis of another person's data may be a criminal offence."
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def now_utc():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def hash_file(path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def ts_to_iso(value):
    """WhatsApp stores ms since epoch (sometimes seconds). Returns UTC ISO string."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    if v > 1e11:  # milliseconds
        v /= 1000.0
    try:
        return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def valid_coord(lat, lon):
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return False
    if lat == 0.0 and lon == 0.0:
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def jid_to_number(jid):
    if not jid:
        return ""
    return jid.split("@")[0]


def open_ro(path):
    uri = "file:%s?mode=ro&immutable=1" % os.path.abspath(path).replace("\\", "/")
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    return con


def tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def columns(con, table):
    return {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}


def sel(alias, cols, name, as_name=None):
    """Select a column if it exists, else NULL."""
    as_name = as_name or name
    return ("%s.%s AS %s" % (alias, name, as_name)) if name in cols else ("NULL AS %s" % as_name)


# --------------------------------------------------------------------------- #
# Contact names (optional wa.db)
# --------------------------------------------------------------------------- #
def load_contacts(wa_db):
    names = {}
    if not wa_db or not os.path.isfile(wa_db):
        return names
    try:
        con = open_ro(wa_db)
        if "wa_contacts" in tables(con):
            for r in con.execute("SELECT jid, display_name, wa_name FROM wa_contacts"):
                names[r["jid"]] = r["display_name"] or r["wa_name"] or ""
        con.close()
    except sqlite3.Error as e:
        print("[!] Could not read contacts DB: %s" % e)
    return names


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def extract_new_schema(con):
    t = tables(con)
    mc, lc = columns(con, "message"), columns(con, "message_location")
    q = """
      SELECT m._id AS msg_id,
             %s, %s, %s, %s,
             %s, %s, %s, %s, %s, %s, %s, %s, %s
      FROM message m
      JOIN message_location ml ON ml.message_row_id = m._id
      %s
      %s
      ORDER BY m.timestamp
    """ % (
        sel("m", mc, "timestamp"), sel("m", mc, "from_me"),
        sel("m", mc, "message_type"), sel("m", mc, "key_id"),
        sel("ml", lc, "latitude"), sel("ml", lc, "longitude"),
        sel("ml", lc, "place_name"), sel("ml", lc, "place_address"), sel("ml", lc, "url"),
        sel("ml", lc, "live_location_share_duration"),
        sel("ml", lc, "live_location_sequence_number"),
        sel("ml", lc, "live_location_final_latitude"),
        sel("ml", lc, "live_location_final_longitude"),
        ("LEFT JOIN chat c ON c._id = m.chat_row_id LEFT JOIN jid cj ON cj._id = c.jid_row_id"
         if {"chat", "jid"} <= t and "chat_row_id" in mc else ""),
        ("LEFT JOIN jid sj ON sj._id = m.sender_jid_row_id"
         if "jid" in t and "sender_jid_row_id" in mc else ""),
    )
    # inject jid selections
    chat_sel = "cj.raw_string AS chat_jid" if {"chat", "jid"} <= t and "chat_row_id" in mc else "NULL AS chat_jid"
    send_sel = "sj.raw_string AS sender_jid" if "jid" in t and "sender_jid_row_id" in mc else "NULL AS sender_jid"
    q = q.replace("SELECT m._id AS msg_id,", "SELECT m._id AS msg_id, %s, %s," % (chat_sel, send_sel), 1)
    rows = []
    for r in con.execute(q):
        d = dict(r)
        d["schema"] = "new"
        d["kind"] = "live" if (d.get("message_type") == 16 or (d.get("live_location_share_duration") or 0) > 0) else "static"
        rows.append(d)
    return rows


def extract_old_schema(con):
    mc = columns(con, "messages")
    q = """
      SELECT _id AS msg_id,
             %s, %s, %s, %s, %s, %s, %s, %s, %s
      FROM messages
      WHERE (latitude IS NOT NULL AND longitude IS NOT NULL AND (latitude != 0 OR longitude != 0))
      ORDER BY timestamp
    """ % (
        sel("messages", mc, "key_remote_jid", "chat_jid"),
        sel("messages", mc, "remote_resource", "sender_jid"),
        sel("messages", mc, "key_from_me", "from_me"),
        sel("messages", mc, "key_id", "key_id"),
        sel("messages", mc, "timestamp"),
        sel("messages", mc, "latitude"), sel("messages", mc, "longitude"),
        sel("messages", mc, "media_wa_type", "message_type"),
        sel("messages", mc, "data", "place_name"),
    )
    rows = []
    for r in con.execute(q):
        d = dict(r)
        d["schema"] = "legacy"
        d["kind"] = "live" if d.get("message_type") in (16, "16") else "static"
        d.setdefault("place_address", None)
        d.setdefault("url", None)
        rows.append(d)
    return rows


def normalise(raw, contacts):
    out = []
    for d in raw:
        if not valid_coord(d.get("latitude"), d.get("longitude")):
            continue
        from_me = bool(d.get("from_me"))
        chat = d.get("chat_jid") or ""
        sender = d.get("sender_jid") or ""
        counterpart = chat if not sender or sender == chat else sender
        sender_label = "DEVICE OWNER" if from_me else (jid_to_number(sender) or jid_to_number(chat))
        lat, lon = float(d["latitude"]), float(d["longitude"])
        out.append({
            "msg_id": d.get("msg_id"),
            "key_id": d.get("key_id") or "",
            "timestamp_utc": ts_to_iso(d.get("timestamp")),
            "direction": "SENT" if from_me else "RECEIVED",
            "chat_jid": chat,
            "chat_number": jid_to_number(chat),
            "chat_is_group": chat.endswith("@g.us"),
            "sender": sender_label,
            "contact_name": contacts.get(counterpart) or contacts.get(chat) or "",
            "kind": d.get("kind", "static"),
            "latitude": round(lat, 7),
            "longitude": round(lon, 7),
            "place_name": (d.get("place_name") or "").strip() if isinstance(d.get("place_name"), str) else "",
            "place_address": (d.get("place_address") or "").strip() if isinstance(d.get("place_address"), str) else "",
            "share_duration_s": d.get("live_location_share_duration") or "",
            "live_sequence": d.get("live_location_sequence_number") or "",
            "final_latitude": d.get("live_location_final_latitude") or "",
            "final_longitude": d.get("live_location_final_longitude") or "",
            "map_link": "https://www.openstreetmap.org/?mlat=%s&mlon=%s#map=17/%s/%s" % (lat, lon, lat, lon),
            "schema": d.get("schema"),
        })
    return out


def analyse(db_path, wa_db=None):
    con = open_ro(db_path)
    t = tables(con)
    raw = []
    if "message_location" in t and "message" in t:
        raw += extract_new_schema(con)
    if "messages" in t and "latitude" in columns(con, "messages"):
        raw += extract_old_schema(con)
    con.close()
    if not raw and not ({"message_location", "messages"} & t):
        raise RuntimeError("No recognised WhatsApp message/location tables. Is this a decrypted msgstore.db?")
    return normalise(raw, load_contacts(wa_db))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def summarise(recs):
    per_chat = {}
    for r in recs:
        key = r["chat_number"] or "unknown"
        s = per_chat.setdefault(key, {"count": 0, "name": r["contact_name"], "group": r["chat_is_group"]})
        s["count"] += 1
    times = [r["timestamp_utc"] for r in recs if r["timestamp_utc"]]
    return {
        "total_locations": len(recs),
        "static": sum(1 for r in recs if r["kind"] == "static"),
        "live": sum(1 for r in recs if r["kind"] == "live"),
        "sent": sum(1 for r in recs if r["direction"] == "SENT"),
        "received": sum(1 for r in recs if r["direction"] == "RECEIVED"),
        "first_seen_utc": min(times) if times else "",
        "last_seen_utc": max(times) if times else "",
        "per_chat": dict(sorted(per_chat.items(), key=lambda kv: -kv[1]["count"])),
    }


FIELDS = ["msg_id", "timestamp_utc", "direction", "kind", "chat_number", "chat_is_group",
          "contact_name", "sender", "latitude", "longitude", "place_name", "place_address",
          "share_duration_s", "live_sequence", "final_latitude", "final_longitude",
          "key_id", "map_link"]


def write_csv(recs, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(recs)


def write_json(recs, meta, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "summary": summarise(recs), "locations": recs}, f, indent=2, ensure_ascii=False)


def write_kml(recs, path):
    esc = lambda s: html.escape(str(s), quote=True)
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
             "<name>%s</name>" % esc(TOOL)]
    for r in recs:
        title = r["place_name"] or "%s %s" % (r["kind"].title(), r["direction"])
        desc = "Time (UTC): %s\nChat: %s %s\nSender: %s\nMsg ID: %s" % (
            r["timestamp_utc"], r["chat_number"], r["contact_name"], r["sender"], r["msg_id"])
        parts.append("<Placemark><name>%s</name><description>%s</description>"
                     "<TimeStamp><when>%s</when></TimeStamp>"
                     "<Point><coordinates>%s,%s,0</coordinates></Point></Placemark>" % (
                         esc(title), esc(desc), esc(r["timestamp_utc"].replace(" ", "T") + "Z"),
                         r["longitude"], r["latitude"]))
    parts.append("</Document></kml>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


def write_html(recs, meta, path):
    e = html.escape
    s = summarise(recs)
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s, %s</td><td>%s</td>"
        "<td><a href='%s' target='_blank' rel='noopener'>map</a></td></tr>" % (
            e(str(r["msg_id"])), e(r["timestamp_utc"]), e(r["direction"]), e(r["kind"]),
            e((r["chat_number"] + " " + r["contact_name"]).strip()), r["latitude"], r["longitude"],
            e((r["place_name"] + " " + r["place_address"]).strip()), e(r["map_link"]))
        for r in recs)
    chats = "".join("<li>%s%s &mdash; %d</li>" % (
        e(k), e(" (%s)" % v["name"] if v["name"] else ""), v["count"]) for k, v in s["per_chat"].items())
    doc = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>%(tool)s - %(case)s</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;background:#0f1419;color:#e6edf3}
h1{color:#58a6ff}h2{border-bottom:1px solid #30363d;padding-bottom:4px}
table{border-collapse:collapse;width:100%%;font-size:13px}
th,td{border:1px solid #30363d;padding:6px 8px;text-align:left}th{background:#161b22}
a{color:#58a6ff}.box{background:#161b22;padding:12px;border-radius:6px;margin:10px 0}
.warn{color:#f0883e}code{color:#7ee787}
</style></head><body>
<h1>%(tool)s</h1>
<p>%(credit)s</p>
<div class="box warn">%(legal)s</div>
<h2>Case details</h2>
<div class="box">Case ID: <b>%(case)s</b><br>Examiner: <b>%(examiner)s</b><br>
Legal authority: <b>%(authority)s</b><br>Report generated: %(gen)s<br>
Evidence: <code>%(file)s</code><br>MD5: <code>%(md5)s</code><br>SHA-256: <code>%(sha)s</code><br>
Integrity after analysis: <b>%(integrity)s</b></div>
<h2>Summary</h2>
<div class="box">Locations: <b>%(total)d</b> (static %(st)d / live %(lv)d) &middot;
Sent %(sent)d / Received %(recv)d<br>Range (UTC): %(first)s &rarr; %(last)s</div>
<h2>Activity per chat</h2><ul>%(chats)s</ul>
<h2>Location artifacts</h2>
<table><tr><th>Msg ID</th><th>Time (UTC)</th><th>Direction</th><th>Type</th><th>Chat</th>
<th>Lat, Lon</th><th>Place</th><th>Map</th></tr>%(rows)s</table>
<p style="margin-top:24px;color:#8b949e">Timestamps are UTC. Coordinates are as stored by the app and
may be user-chosen (pin drop) rather than the device's true position. Corroborate with other evidence.</p>
</body></html>""" % {
        "tool": e(TOOL), "case": e(meta["case_id"]), "examiner": e(meta["examiner"]),
        "authority": e(meta["authority"]), "gen": e(meta["generated"]), "file": e(meta["evidence_file"]),
        "md5": meta["md5"], "sha": meta["sha256"], "integrity": e(meta["integrity"]),
        "credit": e(CREDIT), "legal": e(LEGAL_NOTICE).replace("\n", "<br>"),
        "total": s["total_locations"], "st": s["static"], "lv": s["live"],
        "sent": s["sent"], "recv": s["received"], "first": e(s["first_seen_utc"]),
        "last": e(s["last_seen_utc"]), "chats": chats, "rows": rows}
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def print_table(recs, limit=25):
    print("\n%-6s %-19s %-9s %-7s %-16s %-24s" % ("MSGID", "TIME (UTC)", "DIR", "TYPE", "CHAT", "LAT, LON"))
    print("-" * 88)
    for r in recs[:limit]:
        print("%-6s %-19s %-9s %-7s %-16s %-24s" % (
            str(r["msg_id"])[:6], r["timestamp_utc"], r["direction"], r["kind"],
            (r["chat_number"] or "?")[:16], "%s, %s" % (r["latitude"], r["longitude"])))
    if len(recs) > limit:
        print("... %d more (see exported reports)" % (len(recs) - limit))


# --------------------------------------------------------------------------- #
# Self test (synthetic data, no real person's data involved)
# --------------------------------------------------------------------------- #
def build_selftest_db(path):
    con = sqlite3.connect(path)
    c = con.cursor()
    c.executescript("""
      CREATE TABLE jid(_id INTEGER PRIMARY KEY, raw_string TEXT);
      CREATE TABLE chat(_id INTEGER PRIMARY KEY, jid_row_id INTEGER);
      CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER,
        key_id TEXT, sender_jid_row_id INTEGER, timestamp INTEGER, message_type INTEGER, text_data TEXT);
      CREATE TABLE message_location(message_row_id INTEGER, latitude REAL, longitude REAL,
        place_name TEXT, place_address TEXT, url TEXT, live_location_share_duration INTEGER,
        live_location_sequence_number INTEGER, live_location_final_latitude REAL,
        live_location_final_longitude REAL, live_location_final_timestamp INTEGER);
      INSERT INTO jid VALUES (1,'15550100001@s.whatsapp.net'),(2,'15550100002@s.whatsapp.net');
      INSERT INTO chat VALUES (1,1),(2,2);
      INSERT INTO message VALUES (1,1,0,'AAA',1,1760000000000,5,NULL),
                                 (2,1,1,'BBB',NULL,1760003600000,16,NULL),
                                 (3,2,0,'CCC',2,1760007200000,5,NULL);
      INSERT INTO message_location VALUES (1,33.9, 71.4,'Sample Cafe','Sample St',NULL,NULL,NULL,NULL,NULL,NULL),
                                          (2,34.0, 71.5,NULL,NULL,NULL,900,3,34.01,71.51,1760004500000),
                                          (3,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
    """)
    con.commit()
    con.close()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    print(BANNER)
    print("  %s  v%s" % (TOOL, VERSION))
    print("  %s\n" % CREDIT)
    print(LEGAL_NOTICE + "\n")

    ap = argparse.ArgumentParser(description=TOOL)
    ap.add_argument("--db", help="Path to decrypted WhatsApp msgstore.db (lawfully acquired)")
    ap.add_argument("--wa-db", help="Optional wa.db for contact names")
    ap.add_argument("--case-id", default="UNSPECIFIED")
    ap.add_argument("--examiner", default="Mr Sabaz Ali Khan")
    ap.add_argument("--authority", default="UNSPECIFIED", help="Warrant / order / consent reference")
    ap.add_argument("--out", default="wa_location_report", help="Output directory")
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="Confirm you have legal authority to examine this evidence")
    ap.add_argument("--selftest", action="store_true", help="Run against synthetic data")
    args = ap.parse_args()

    tmp = None
    if args.selftest:
        tmp = tempfile.mkdtemp(prefix="wa_selftest_")
        args.db = os.path.join(tmp, "msgstore.db")
        build_selftest_db(args.db)
        args.confirm_authorized = True
        args.case_id, args.authority = "SELFTEST", "Synthetic data"
        args.out = os.path.join(tmp, "report")
        print("[*] Self-test mode: synthetic database created.\n")

    if not args.db:
        ap.error("--db is required (or use --selftest)")
    if not os.path.isfile(args.db):
        sys.exit("[!] Evidence file not found: %s" % args.db)
    if args.db.lower().endswith((".crypt12", ".crypt14", ".crypt15")):
        sys.exit("[!] Encrypted backup detected. Provide a decrypted msgstore.db obtained lawfully.")
    if not args.confirm_authorized:
        sys.exit("[!] Refusing to run: add --confirm-authorized to attest you have legal authority.")

    os.makedirs(args.out, exist_ok=True)
    md5_before, sha_before = hash_file(args.db)
    print("[*] Evidence : %s" % args.db)
    print("[*] MD5      : %s" % md5_before)
    print("[*] SHA-256  : %s" % sha_before)

    try:
        recs = analyse(args.db, args.wa_db)
    except (sqlite3.Error, RuntimeError) as e:
        sys.exit("[!] Analysis failed: %s" % e)

    md5_after, sha_after = hash_file(args.db)
    integrity = "VERIFIED (unchanged)" if (md5_before, sha_before) == (md5_after, sha_after) else "MISMATCH - EVIDENCE CHANGED"
    print("[*] Integrity: %s" % integrity)

    meta = {"tool": TOOL, "version": VERSION, "credit": CREDIT, "case_id": args.case_id,
            "examiner": args.examiner, "authority": args.authority, "generated": now_utc(),
            "evidence_file": os.path.abspath(args.db), "md5": md5_before, "sha256": sha_before,
            "integrity": integrity}

    s = summarise(recs)
    print("\n[+] Location artifacts found: %d (static %d, live %d)" % (s["total_locations"], s["static"], s["live"]))
    if recs:
        print("[+] Time range (UTC): %s -> %s" % (s["first_seen_utc"], s["last_seen_utc"]))
        print_table(recs)

    base = os.path.join(args.out, args.case_id)
    write_csv(recs, base + "_locations.csv")
    write_json(recs, meta, base + "_locations.json")
    write_kml(recs, base + "_locations.kml")
    write_html(recs, meta, base + "_report.html")
    with open(base + "_chain_of_custody.txt", "w", encoding="utf-8") as f:
        f.write("%s\n%s\n\n" % (TOOL, CREDIT))
        for k in ("case_id", "examiner", "authority", "generated", "evidence_file", "md5", "sha256", "integrity"):
            f.write("%-14s: %s\n" % (k, meta[k]))
        f.write("\nOpened read-only/immutable. Artifacts: %d\n" % len(recs))

    print("\n[+] Reports written to: %s" % os.path.abspath(args.out))
    for ext in ("_locations.csv", "_locations.json", "_locations.kml", "_report.html", "_chain_of_custody.txt"):
        print("    - %s%s" % (os.path.basename(base), ext))
    print("\n  %s\n" % CREDIT)


if __name__ == "__main__":
    main()
