#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WHOIS & DNS Lookup Tool
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Pure standard library - no third-party packages required.
  * WHOIS : raw port-43 client with IANA discovery + registrar referral
  * DNS   : hand-built UDP/TCP resolver (A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, PTR)

Usage:
  python3 whois_dns_lookup.py example.com
  python3 whois_dns_lookup.py example.com --dns --types A MX TXT
  python3 whois_dns_lookup.py example.com --whois --raw
  python3 whois_dns_lookup.py 8.8.8.8
  python3 whois_dns_lookup.py example.com --json -o report.json
  python3 whois_dns_lookup.py example.com --resolver 1.1.1.1

Use only for lawful, authorized information gathering.
"""

import argparse
import ipaddress
import json
import os
import random
import re
import socket
import struct
import sys
from datetime import datetime, timezone

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡠⠖⠊⠉⠉⠉⠑⠒⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠠⡪⡻⣣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢢⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡽⠀⠹⣴⣄⡀⠀⣄⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠙⢝⢽⢻⣿⣟⡀⠀⠀⠀⡄⡸⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡜⣉⠀⠀⠈⡤⠅⠫⣿⠙⠀⠀⠀⣉⢳⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣳⢻⡚⠶⣤⡀⠸⡶⠟⢀⣠⠴⢛⡿⡜⠀⠀⠀⠀⠀⠀⠀⠀
⣄⠀⠀⠀⠀⠀⡜⢹⣌⢷⠤⠤⠽⡳⠷⢞⠯⠄⠤⡾⣁⠇⢀⠀⠀⠀⠀⠀⠀⢠
⢸⢦⡀⠀⠀⠸⡵⣹⠉⣳⠨⡀⠀⠀⠀⠀⠈⢈⠥⡾⠗⡉⢩⠛⠉⠀⠀⠀⡠⡏
⠀⢧⠙⢦⡀⠀⠙⢷⢞⣒⡇⠀⠀⠀⠀⠀⠀⠀⢰⠁⠦⢍⡩⠃⠀⢀⡠⠊⡰⠁
⠀⠀⠳⣐⢌⠲⢄⡈⠳⣀⣱⣄⠀⠀⠀⠀⠀⣀⠜⣉⣑⠭⢀⡠⠔⡉⢀⠔⠁⠀
⠀⠀⠀⠈⠓⢤⡂⢈⠓⠤⣉⡙⠳⠤⠀⠤⠞⠓⠉⣁⠤⠒⡉⢄⡨⠖⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠑⠪⢴⣠⠍⡓⠢⣄⡠⠔⢒⠉⣄⡢⠕⠊⠁⠀⠀⠀⠀⠀⠀
⡠⠤⠀⡀⡀⡀⠀⠠⠂⢱⠔⣛⠋⢭⣐⣦⡽⠒⣛⠣⡎⠁⡦⠀⡀⣀⢀⠀⠠⢤
⠧⠠⠄⠇⠧⠬⠼⠴⣇⣂⠖⠒⠉⠁⠀⠀⠈⠉⠒⠲⣡⣰⠥⠤⠦⠀⠄⢠⠀⠸
"""

CREDIT = "WHOIS & DNS Lookup Tool  |  coded by Mr Sabaz Ali Khan"

USE_COLOR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def show_banner():
    print(c(BANNER, "36"))
    print(c(f"  {CREDIT}", "1;32"))
    print(c("  " + "-" * 56, "90"))


# ----------------------------------------------------------------------------
# DNS (raw resolver)
# ----------------------------------------------------------------------------
QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257,
}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(Exception):
    pass


def system_resolvers():
    servers = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    servers = [s for s in servers if ":" not in s]  # IPv4 only for simplicity
    return servers + ["1.1.1.1", "8.8.8.8"]


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        try:
            raw = label.encode("idna")
        except UnicodeError:
            raw = label.encode("ascii", "ignore")
        if len(raw) > 63:
            raise DNSError("label too long")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, qtype):
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    return qid, header + question


def read_name(data, off):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(data) or hops > 50:
            raise DNSError("malformed name")
        length = data[off]
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            continue
        if length == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(data[off + 1:off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels) or ".", end


def parse_rdata(data, rtype, off, rdlen):
    end = off + rdlen
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(data[off:end])
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, data[off:end])
    if rtype in (2, 5, 12):
        return read_name(data, off)[0]
    if rtype == 15:
        pref = struct.unpack(">H", data[off:off + 2])[0]
        return f"{pref} {read_name(data, off + 2)[0]}"
    if rtype == 16:
        chunks, p = [], off
        while p < end:
            ln = data[p]
            chunks.append(data[p + 1:p + 1 + ln].decode("utf-8", "replace"))
            p += 1 + ln
        return "".join(chunks)
    if rtype == 6:
        mname, p = read_name(data, off)
        rname, p = read_name(data, p)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[p:p + 20])
        return (f"{mname} {rname} serial={serial} refresh={refresh} "
                f"retry={retry} expire={expire} min={minimum}")
    if rtype == 257:
        flags, taglen = data[off], data[off + 1]
        tag = data[off + 2:off + 2 + taglen].decode("ascii", "replace")
        val = data[off + 2 + taglen:end].decode("utf-8", "replace")
        return f'{flags} {tag} "{val}"'
    return data[off:end].hex()


def parse_response(data, qid):
    if len(data) < 12:
        raise DNSError("short response")
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        raise DNSError("transaction id mismatch")
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = read_name(data, off)
        rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        answers.append({
            "name": name,
            "type": QTYPE_NAMES.get(rtype, str(rtype)),
            "ttl": ttl,
            "data": parse_rdata(data, rtype, off, rdlen),
        })
        off += rdlen
    return {"rcode": flags & 0xF, "truncated": bool(flags & 0x200), "answers": answers}


def dns_query(name, qtype_name, resolver, timeout=4.0):
    qtype = QTYPES[qtype_name]
    qid, packet = build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (resolver, 53))
        data, _ = s.recvfrom(4096)
    result = parse_response(data, qid)
    if result["truncated"]:  # retry over TCP
        with socket.create_connection((resolver, 53), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            raw = b""
            while len(raw) < 2:
                raw += s.recv(2 - len(raw))
            need = struct.unpack(">H", raw[:2])[0]
            body = b""
            while len(body) < need:
                chunk = s.recv(need - len(body))
                if not chunk:
                    break
                body += chunk
        result = parse_response(body, qid)
    return result


def dns_lookup(domain, types, resolvers, timeout):
    results = {}
    for t in types:
        last_err = None
        for srv in resolvers:
            try:
                r = dns_query(domain, t, srv, timeout)
                results[t] = {
                    "resolver": srv,
                    "status": RCODES.get(r["rcode"], str(r["rcode"])),
                    "records": r["answers"],
                }
                break
            except (OSError, DNSError, struct.error) as exc:
                last_err = exc
        else:
            results[t] = {"resolver": None, "status": f"ERROR: {last_err}", "records": []}
    return results


def reverse_lookup(ip, resolvers, timeout):
    addr = ipaddress.ip_address(ip)
    ptr = addr.reverse_pointer
    return dns_lookup(ptr, ["PTR"], resolvers, timeout)["PTR"]


# ----------------------------------------------------------------------------
# WHOIS
# ----------------------------------------------------------------------------
def whois_query(server, query, timeout=8.0):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        q = query
        if server.endswith("denic.de"):
            q = f"-T dn,ace {query}"
        elif server == "whois.arin.net":
            q = f"n + {query}"
        s.sendall((q + "\r\n").encode())
        chunks = []
        while True:
            try:
                buf = s.recv(4096)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
    return b"".join(chunks).decode("utf-8", "replace")


def find_refer(text, keys=("refer", "whois", "registrar whois server", "referralserver")):
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() in keys and v.strip():
            val = v.strip()
            val = re.sub(r"^(r?whois://)", "", val, flags=re.I).strip("/ ")
            if val:
                return val.split(":")[0]
    return None


def whois_lookup(target, timeout=8.0):
    """Returns (list_of_(server, text) hops)."""
    hops = []
    iana = whois_query("whois.iana.org", target, timeout)
    hops.append(("whois.iana.org", iana))
    server = find_refer(iana, ("refer", "whois"))
    seen = {"whois.iana.org"}
    depth = 0
    while server and server not in seen and depth < 3:
        seen.add(server)
        text = whois_query(server, target, timeout)
        hops.append((server, text))
        depth += 1
        server = find_refer(text, ("registrar whois server", "referralserver"))
    return hops


FIELD_PATTERNS = {
    "registrar": r"^(?:registrar|sponsoring registrar)\s*:\s*(.+)$",
    "registrar_url": r"^registrar url\s*:\s*(.+)$",
    "created": r"^(?:creation date|created|created on|registered on|registration time)\s*:\s*(.+)$",
    "updated": r"^(?:updated date|last updated|last-modified|changed|last update)\s*:\s*(.+)$",
    "expires": r"^(?:registry expiry date|registrar registration expiration date|expiry date|"
               r"expiration date|expires|paid-till)\s*:\s*(.+)$",
    "status": r"^(?:domain status|status)\s*:\s*(.+)$",
    "name_servers": r"^(?:name server|nserver|nameserver)\s*:\s*(.+)$",
    "dnssec": r"^dnssec\s*:\s*(.+)$",
    "registrant_org": r"^(?:registrant organization|registrant organisation|org-name|orgname|organization)\s*:\s*(.+)$",
    "registrant_country": r"^(?:registrant country|country)\s*:\s*(.+)$",
    "abuse_email": r"^(?:registrar abuse contact email|abuse-mailbox|orgabuseemail)\s*:\s*(.+)$",
    "netname": r"^(?:netname|net-name)\s*:\s*(.+)$",
    "cidr": r"^(?:cidr|inetnum|netrange)\s*:\s*(.+)$",
    "asn": r"^(?:origin|originas)\s*:\s*(.+)$",
}
MULTI = {"status", "name_servers"}


def parse_whois(text):
    out = {}
    for key, pat in FIELD_PATTERNS.items():
        rx = re.compile(pat, re.I | re.M)
        vals = []
        for m in rx.finditer(text):
            v = m.group(1).strip()
            if v and v.lower() not in ("redacted for privacy", "not disclosed") and v not in vals:
                vals.append(v)
        if vals:
            out[key] = [v.lower() if key == "name_servers" else v for v in vals] if key in MULTI else vals[0]
    return out


DATE_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d")


def parse_date(s):
    s = s.strip().split(" (")[0]
    s2 = re.sub(r"\.\d+", "", s)
    for fmt in DATE_FORMATS:
        for cand in (s, s2):
            try:
                d = datetime.strptime(cand, fmt)
                return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def date_insights(info):
    now = datetime.now(timezone.utc)
    notes = {}
    if "created" in info and (d := parse_date(info["created"])):
        notes["age_days"] = (now - d).days
    if "expires" in info and (d := parse_date(info["expires"])):
        notes["days_until_expiry"] = (d - now).days
    return notes


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
def print_whois(info, notes):
    print(c("\n[ WHOIS ]", "1;33"))
    if not info:
        print("  No structured fields parsed (try --raw).")
        return
    labels = {
        "registrar": "Registrar", "registrar_url": "Registrar URL", "registrant_org": "Organization",
        "registrant_country": "Country", "created": "Created", "updated": "Updated",
        "expires": "Expires", "dnssec": "DNSSEC", "netname": "Net Name", "cidr": "Range",
        "asn": "Origin AS", "abuse_email": "Abuse Contact",
    }
    for k, label in labels.items():
        if k in info:
            print(f"  {c(label.ljust(15), '36')} {info[k]}")
    for k, label in (("status", "Status"), ("name_servers", "Name Servers")):
        for i, v in enumerate(info.get(k, [])):
            print(f"  {c((label if i == 0 else '').ljust(15), '36')} {v}")
    if "age_days" in notes:
        print(f"  {c('Domain Age'.ljust(15), '36')} {notes['age_days']} days (~{notes['age_days'] / 365:.1f} yrs)")
    if "days_until_expiry" in notes:
        d = notes["days_until_expiry"]
        col = "1;31" if d < 30 else "32"
        print(f"  {c('Expires In'.ljust(15), '36')} {c(str(d) + ' days', col)}"
              + (c("  <-- expiring soon / expired", "31") if d < 30 else ""))


def print_dns(results):
    print(c("\n[ DNS RECORDS ]", "1;33"))
    for t, res in results.items():
        recs = res["records"]
        head = f"  {c(t.ljust(6), '1;35')} "
        if not recs:
            print(head + c(f"- ({res['status']})", "90"))
            continue
        for i, r in enumerate(recs):
            prefix = head if i == 0 else "         "
            print(f"{prefix}{r['data']}  {c('TTL ' + str(r['ttl']), '90')}")
    print(c(f"\n  Resolver used: {next((r['resolver'] for r in results.values() if r['resolver']), 'n/a')}", "90"))


def main():
    p = argparse.ArgumentParser(
        description="WHOIS & DNS Lookup Tool - coded by Mr Sabaz Ali Khan",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", help="domain name or IP address")
    p.add_argument("--whois", action="store_true", help="WHOIS lookup only")
    p.add_argument("--dns", action="store_true", help="DNS lookup only")
    p.add_argument("--types", nargs="+", default=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"],
                   help="DNS record types (default: A AAAA MX NS TXT SOA CNAME CAA)")
    p.add_argument("--resolver", help="DNS resolver IPv4 (default: system, then 1.1.1.1/8.8.8.8)")
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--raw", action="store_true", help="print raw WHOIS responses")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("-o", "--output", help="save JSON report to file")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    if not args.json and not args.no_banner:
        show_banner()

    target = args.target.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    is_ip = True
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False

    do_whois = args.whois or not args.dns
    do_dns = args.dns or not args.whois
    resolvers = [args.resolver] if args.resolver else system_resolvers()
    types = [t.upper() for t in args.types]
    bad = [t for t in types if t not in QTYPES]
    if bad:
        p.error(f"unsupported record type(s): {', '.join(bad)} (supported: {', '.join(QTYPES)})")

    report = {
        "tool": "WHOIS & DNS Lookup Tool",
        "author": "Mr Sabaz Ali Khan",
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if do_whois:
        try:
            hops = whois_lookup(target, args.timeout)
            merged = {}
            for _srv, txt in reversed(hops):  # authoritative (last) wins
                merged.update(parse_whois(txt))
            notes = date_insights(merged)
            report["whois"] = {"servers": [h[0] for h in hops], "parsed": merged, "insights": notes}
            if args.raw:
                report["whois"]["raw"] = {srv: txt for srv, txt in hops}
            if not args.json:
                print_whois(merged, notes)
                if args.raw:
                    for srv, txt in hops:
                        print(c(f"\n--- RAW: {srv} ---", "90"))
                        print(txt)
        except OSError as exc:
            report["whois"] = {"error": str(exc)}
            if not args.json:
                print(c(f"\n[!] WHOIS failed: {exc}", "31"))

    if do_dns:
        if is_ip:
            res = {"PTR": reverse_lookup(target, resolvers, args.timeout)}
        else:
            res = dns_lookup(target, types, resolvers, args.timeout)
        report["dns"] = res
        if not args.json:
            print_dns(res)

    if args.json:
        print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        if not args.json:
            print(c(f"\n[+] Report saved to {args.output}", "32"))
    if not args.json:
        print(c(f"\n  {CREDIT}\n", "90"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
