#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoT Discovery - Shodan / Censys API Wrapper
Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Unified, stdlib-only wrapper around the official Shodan and Censys Search APIs
for IoT / exposed-device discovery. Results from both engines are normalised
into a single Device record so they can be displayed, merged and exported
(table / JSON / CSV) the same way.

AUTHORIZED USE ONLY: use it for asset inventory of your own infrastructure,
authorised assessments, or research that complies with the providers' terms
and applicable law. This tool only queries the providers' indexes; it never
connects to the discovered devices.

Credentials (environment variables or CLI flags):
    SHODAN_API_KEY
    CENSYS_API_ID, CENSYS_API_SECRET

Examples:
    python iot_discovery.py presets
    python iot_discovery.py search --engine shodan --preset webcam --country PK --limit 50
    python iot_discovery.py search --engine censys --query 'services.port=1883' --limit 25
    python iot_discovery.py search --engine both --preset mqtt --format csv --out mqtt.csv
    python iot_discovery.py host 8.8.8.8 --engine shodan
    python iot_discovery.py count --engine shodan --query 'port:502'
    python iot_discovery.py account
"""

import argparse
import base64
import csv
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterator, List, Optional

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣷⣶⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀
⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀
⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷
⣿⣿⣿⣿⡟⠿⣿⣿⣛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⢛⣿⣿⡿⢿⣿⣿⣿⣿
⢸⣿⣿⣿⡇⠀⠀⠉⠛⢻⣶⣤⡄⠀⠀⠀⠀⠀⣤⣶⣿⠛⠉⠁⠀⢸⣿⣿⣿⣿
⠸⣿⣿⣿⣿⡀⠀⠀⢰⣿⣿⣿⡇⠀⠀⠀⠀⠸⣿⣿⣿⡇⠀⠀⢀⣿⣿⣿⣿⡇
⠀⢹⣿⣿⣿⣷⣄⠀⠈⠻⠿⠟⠁⠀⠀⠀⠀⠀⠛⠿⠟⠃⠀⢠⣾⣿⣿⣿⡟⠀
⠀⠀⠹⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⡟⠀⠀
⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣶⣤⣀⣀⣀⣀⣀⣀⣤⣴⣾⣿⣿⣿⣿⡿⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⠿⣿⣿⣿⣿⣿⣿⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀
"""

CREDIT = "IoT Discovery | Shodan / Censys API Wrapper  -  coded by Mr Sabaz Ali Khan"

# --------------------------------------------------------------------------- #
# IoT query presets (engine specific syntax)
# --------------------------------------------------------------------------- #
PRESETS: Dict[str, Dict[str, str]] = {
    "webcam": {
        "desc": "Exposed IP cameras / web cams",
        "shodan": 'product:"webcam" OR "Server: webcamXP" OR "Server: IP Webcam Server"',
        "censys": 'services.http.response.html_title: "webcam" or services.http.response.html_title: "IP Camera"',
    },
    "mqtt": {
        "desc": "MQTT brokers (IoT messaging)",
        "shodan": "port:1883 product:mosquitto",
        "censys": "services.port=1883",
    },
    "modbus": {
        "desc": "Modbus/TCP (ICS / SCADA)",
        "shodan": "port:502",
        "censys": "services.service_name=MODBUS",
    },
    "router": {
        "desc": "Home / SOHO routers with web admin",
        "shodan": 'http.title:"router" OR http.title:"RouterOS"',
        "censys": 'services.http.response.html_title: "router"',
    },
    "printer": {
        "desc": "Network printers",
        "shodan": "port:9100 OR port:631 printer",
        "censys": "services.port=9100",
    },
    "smarthome": {
        "desc": "Smart-home hubs (Home Assistant, Hue etc.)",
        "shodan": 'http.title:"Home Assistant" OR http.title:"Hue"',
        "censys": 'services.http.response.html_title: "Home Assistant"',
    },
    "rtsp": {
        "desc": "RTSP video streams",
        "shodan": "port:554 has_screenshot:true",
        "censys": "services.service_name=RTSP",
    },
    "telnet-iot": {
        "desc": "Telnet-exposed embedded devices",
        "shodan": "port:23 embedded",
        "censys": "services.service_name=TELNET",
    },
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Device:
    source: str
    ip: str
    ports: List[int] = field(default_factory=list)
    org: str = ""
    country: str = ""
    city: str = ""
    hostnames: List[str] = field(default_factory=list)
    product: str = ""
    os: str = ""
    services: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    last_seen: str = ""

    def merge(self, other: "Device") -> None:
        """Merge another record for the same IP (used for --engine both)."""
        self.source = "+".join(sorted(set(self.source.split("+") + other.source.split("+"))))
        self.ports = sorted(set(self.ports) | set(other.ports))
        self.hostnames = sorted(set(self.hostnames) | set(other.hostnames))
        self.services = sorted(set(self.services) | set(other.services))
        self.vulns = sorted(set(self.vulns) | set(other.vulns))
        for attr in ("org", "country", "city", "product", "os", "last_seen"):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))


class APIError(Exception):
    pass


# --------------------------------------------------------------------------- #
# HTTP layer with retry / backoff / rate limiting
# --------------------------------------------------------------------------- #
class HTTPClient:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None,
                 timeout: int = 30, retries: int = 3, min_interval: float = 1.0):
        self.base_url = base_url.rstrip("/")
        self.headers = {"User-Agent": "iot-discovery/1.0 (Mr Sabaz Ali Khan)",
                        "Accept": "application/json"}
        self.headers.update(headers or {})
        self.timeout = timeout
        self.retries = retries
        self.min_interval = min_interval  # Shodan free tier allows ~1 req/sec
        self._last = 0.0

    def get(self, path: str, params: Optional[Dict[str, object]] = None) -> dict:
        url = self.base_url + path
        if params:
            clean = {k: v for k, v in params.items() if v not in (None, "")}
            url += "?" + urllib.parse.urlencode(clean)
        last_err: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
            req = urllib.request.Request(url, headers=self.headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")[:300]
                if e.code in (429, 500, 502, 503, 504):
                    last_err = APIError(f"HTTP {e.code}: {body}")
                    time.sleep(2 ** attempt)
                    continue
                if e.code in (401, 403):
                    raise APIError(f"Authentication/permission error (HTTP {e.code}): {body}")
                raise APIError(f"HTTP {e.code}: {body}")
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = APIError(f"Network error: {e}")
                time.sleep(2 ** attempt)
        raise last_err or APIError("Request failed")


# --------------------------------------------------------------------------- #
# Shodan
# --------------------------------------------------------------------------- #
class ShodanClient:
    name = "shodan"

    def __init__(self, api_key: str):
        if not api_key:
            raise APIError("Missing Shodan key (set SHODAN_API_KEY or use --shodan-key)")
        self.key = api_key
        self.http = HTTPClient("https://api.shodan.io", min_interval=1.1)

    def account(self) -> dict:
        return self.http.get("/api-info", {"key": self.key})

    def count(self, query: str) -> dict:
        return self.http.get("/shodan/host/count", {"key": self.key, "query": query})

    def search(self, query: str, limit: int = 100) -> Iterator[Device]:
        page, yielded = 1, 0
        while yielded < limit:
            data = self.http.get("/shodan/host/search",
                                 {"key": self.key, "query": query, "page": page})
            matches = data.get("matches", [])
            if not matches:
                return
            for m in matches:
                yield self._to_device(m)
                yielded += 1
                if yielded >= limit:
                    return
            page += 1

    def host(self, ip: str) -> Device:
        data = self.http.get(f"/shodan/host/{urllib.parse.quote(ip)}", {"key": self.key})
        d = Device(
            source="shodan", ip=data.get("ip_str", ip),
            ports=sorted(data.get("ports", [])),
            org=data.get("org") or data.get("isp") or "",
            country=data.get("country_name") or "", city=data.get("city") or "",
            hostnames=data.get("hostnames", []), os=data.get("os") or "",
            vulns=sorted(data.get("vulns", [])),
            last_seen=data.get("last_update", ""),
        )
        d.services = sorted({
            (s.get("_shodan", {}).get("module") or s.get("product") or "") for s in data.get("data", [])
        } - {""})
        return d

    @staticmethod
    def _to_device(m: dict) -> Device:
        loc = m.get("location", {}) or {}
        vulns = m.get("vulns")
        return Device(
            source="shodan", ip=m.get("ip_str", ""),
            ports=[m["port"]] if "port" in m else [],
            org=m.get("org") or m.get("isp") or "",
            country=loc.get("country_name") or "", city=loc.get("city") or "",
            hostnames=m.get("hostnames", []), product=m.get("product") or "",
            os=m.get("os") or "",
            services=[(m.get("_shodan", {}) or {}).get("module", "")] if m.get("_shodan") else [],
            vulns=sorted(vulns.keys() if isinstance(vulns, dict) else (vulns or [])),
            last_seen=m.get("timestamp", ""),
        )


# --------------------------------------------------------------------------- #
# Censys (Search API v2)
# --------------------------------------------------------------------------- #
class CensysClient:
    name = "censys"

    def __init__(self, api_id: str, api_secret: str,
                 base_url: str = "https://search.censys.io"):
        if not (api_id and api_secret):
            raise APIError("Missing Censys credentials (CENSYS_API_ID / CENSYS_API_SECRET)")
        token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        self.http = HTTPClient(base_url, headers={"Authorization": f"Basic {token}"},
                               min_interval=0.6)

    def account(self) -> dict:
        return self.http.get("/api/v1/account")

    def count(self, query: str) -> dict:
        data = self.http.get("/api/v2/hosts/search", {"q": query, "per_page": 1})
        return {"total": data.get("result", {}).get("total", 0)}

    def search(self, query: str, limit: int = 100) -> Iterator[Device]:
        cursor, yielded = None, 0
        while yielded < limit:
            data = self.http.get("/api/v2/hosts/search", {
                "q": query, "per_page": min(100, limit - yielded), "cursor": cursor})
            result = data.get("result", {})
            for hit in result.get("hits", []):
                yield self._to_device(hit)
                yielded += 1
                if yielded >= limit:
                    return
            cursor = (result.get("links") or {}).get("next")
            if not cursor:
                return

    def host(self, ip: str) -> Device:
        data = self.http.get(f"/api/v2/hosts/{urllib.parse.quote(ip)}")
        return self._to_device(data.get("result", {}))

    @staticmethod
    def _to_device(h: dict) -> Device:
        services = h.get("services", []) or []
        loc = h.get("location", {}) or {}
        asys = h.get("autonomous_system", {}) or {}
        names = []
        for key in ("dns",):
            names += (h.get(key, {}) or {}).get("reverse_dns", {}).get("names", []) or []
        return Device(
            source="censys", ip=h.get("ip", ""),
            ports=sorted({s["port"] for s in services if "port" in s}),
            org=asys.get("name", ""), country=loc.get("country", ""),
            city=loc.get("city", ""), hostnames=names,
            os=(h.get("operating_system", {}) or {}).get("product", ""),
            services=sorted({s.get("service_name", "") for s in services} - {""}),
            last_seen=h.get("last_updated_at", ""),
        )


# --------------------------------------------------------------------------- #
# Query building / output
# --------------------------------------------------------------------------- #
def build_query(engine: str, args) -> str:
    if args.query:
        q = args.query
    elif args.preset:
        q = PRESETS[args.preset][engine]
    else:
        raise APIError("Provide --query or --preset")
    if getattr(args, "country", None):
        cc = args.country.upper()
        q += f" country:{cc}" if engine == "shodan" else f' and location.country_code="{cc}"'
    return q


def render_table(devices: List[Device]) -> str:
    cols = [("IP", lambda d: d.ip), ("SRC", lambda d: d.source),
            ("PORTS", lambda d: ",".join(map(str, d.ports[:6]))),
            ("COUNTRY", lambda d: d.country), ("ORG", lambda d: d.org),
            ("PRODUCT/SVC", lambda d: d.product or ",".join(d.services[:3])),
            ("VULNS", lambda d: str(len(d.vulns)))]
    rows = [[fn(d)[:34] for _, fn in cols] for d in devices]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, (h, _) in enumerate(cols)]
    line = "  ".join(h.ljust(widths[i]) for i, (h, _) in enumerate(cols))
    out = [line, "-" * len(line)]
    out += ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows]
    return "\n".join(out)


def render(devices: List[Device], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([asdict(d) for d in devices], indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["source", "ip", "ports", "org", "country", "city", "hostnames",
                    "product", "os", "services", "vulns", "last_seen"])
        for d in devices:
            w.writerow([d.source, d.ip, ";".join(map(str, d.ports)), d.org, d.country,
                        d.city, ";".join(d.hostnames), d.product, d.os,
                        ";".join(d.services), ";".join(d.vulns), d.last_seen])
        return buf.getvalue()
    return render_table(devices)


def dedupe(devices: List[Device]) -> List[Device]:
    merged: Dict[str, Device] = {}
    for d in devices:
        if d.ip in merged:
            merged[d.ip].merge(d)
        else:
            merged[d.ip] = d
    return list(merged.values())


def get_clients(args) -> list:
    wanted = ["shodan", "censys"] if args.engine == "both" else [args.engine]
    clients = []
    for name in wanted:
        if name == "shodan":
            clients.append(ShodanClient(args.shodan_key or os.getenv("SHODAN_API_KEY", "")))
        else:
            clients.append(CensysClient(args.censys_id or os.getenv("CENSYS_API_ID", ""),
                                        args.censys_secret or os.getenv("CENSYS_API_SECRET", "")))
    return clients


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_presets(_args) -> None:
    print(f"{'PRESET':<12} DESCRIPTION")
    for name, p in PRESETS.items():
        print(f"{name:<12} {p['desc']}")


def cmd_account(args) -> None:
    for c in get_clients(args):
        print(f"[{c.name}] {json.dumps(c.account(), indent=2)}")


def cmd_count(args) -> None:
    for c in get_clients(args):
        q = build_query(c.name, args)
        print(f"[{c.name}] query: {q}\n[{c.name}] total: {c.count(q).get('total', 'n/a')}")


def cmd_search(args) -> None:
    devices: List[Device] = []
    for c in get_clients(args):
        q = build_query(c.name, args)
        print(f"[*] {c.name}: {q}", file=sys.stderr)
        try:
            devices += list(c.search(q, args.limit))
        except APIError as e:
            print(f"[!] {c.name}: {e}", file=sys.stderr)
    devices = dedupe(devices)
    text = render(devices, args.format)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"[+] {len(devices)} devices written to {args.out}", file=sys.stderr)
    else:
        print(text)
        print(f"\n[+] {len(devices)} unique devices", file=sys.stderr)


def cmd_host(args) -> None:
    devices = []
    for c in get_clients(args):
        try:
            devices.append(c.host(args.ip))
        except APIError as e:
            print(f"[!] {c.name}: {e}", file=sys.stderr)
    for d in dedupe(devices):
        print(json.dumps(asdict(d), indent=2))


def main() -> None:
    print(BANNER)
    print(CREDIT + "\n")
    p = argparse.ArgumentParser(description="Shodan/Censys IoT device discovery wrapper")
    p.add_argument("--shodan-key")
    p.add_argument("--censys-id")
    p.add_argument("--censys-secret")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, query=True):
        sp.add_argument("--engine", choices=["shodan", "censys", "both"], default="shodan")
        if query:
            sp.add_argument("--query", "-q", help="Native query for the chosen engine")
            sp.add_argument("--preset", choices=PRESETS.keys(), help="IoT preset query")
            sp.add_argument("--country", help="2-letter country code filter (e.g. PK)")

    sub.add_parser("presets", help="List IoT presets").set_defaults(fn=cmd_presets)
    sp = sub.add_parser("account", help="Show API plan / credits"); common(sp, False)
    sp.set_defaults(fn=cmd_account)
    sp = sub.add_parser("count", help="Count matches"); common(sp)
    sp.set_defaults(fn=cmd_count)
    sp = sub.add_parser("search", help="Search for devices"); common(sp)
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--format", choices=["table", "json", "csv"], default="table")
    sp.add_argument("--out", help="Write output to file")
    sp.set_defaults(fn=cmd_search)
    sp = sub.add_parser("host", help="Lookup a single IP"); common(sp, False)
    sp.add_argument("ip")
    sp.set_defaults(fn=cmd_host)

    args = p.parse_args()
    try:
        args.fn(args)
    except APIError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
