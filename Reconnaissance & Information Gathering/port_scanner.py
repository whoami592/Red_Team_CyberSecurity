#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanner - Custom TCP/UDP scanner built on raw socket programming.

Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)

Features
  * TCP connect scan (full three-way handshake)
  * UDP scan with protocol-specific probes (DNS, NTP, SNMP, NetBIOS, SSDP, ...)
  * Banner grabbing for open TCP ports (with HTTP probe fallback)
  * Multi-threaded, configurable timeout and thread count
  * Port ranges / lists / "top" ports, service-name lookup
  * JSON and text report output

LEGAL: Scan only systems you own or have explicit written permission to test.
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

BANNER = r"""
⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⢠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣤⣄⡀⠀⠀⠀⠙⣿⡯⠛⠛⠛⠲⠤⢿⣆⣙⠻⡶⢤⣀⣠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢿⣯⠙⠛⠳⠦⠤⠼⣿⠛⠓⠲⠴⣶⠾⣿⠽⣧⣿⣤⡈⠻⣿⠦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⣯⢣⡀⠈⠓⢦⣄⡈⠃⠀⠀⠀⠙⢧⡈⠻⣶⣭⣄⠙⢶⣌⠑⣾⣝⡳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⣷⣝⠦⣀⠀⠀⠉⢙⣲⡶⠴⠶⠶⠿⠷⣤⡈⠛⠿⡶⢍⣠⡿⣿⠗⠿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣟⠷⣌⡓⠦⠀⢯⡉⠉⠉⠉⠙⠒⠶⢴⣿⡟⠶⠦⠀⠘⠿⢿⣄⢀⣻⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠹⣟⢦⣀⣹⡧⠤⠍⠻⢦⣀⠀⠀⠀⠀⠸⣇⠙⣆⠀⡗⠓⣦⣄⣀⣿⡌⣧⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠘⠳⢿⣟⡒⠤⠤⠤⢄⠉⠳⣦⣤⠄⠀⣉⡤⠼⠞⠛⠋⠉⠉⠉⠙⠛⣿⡎⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⠏⠙⠛⣲⣶⠶⢶⡏⠁⢀⡴⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣿⣷⠀⢳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠛⠛⢻⣿⡁⠀⠀⠸⠶⠞⠉⠀⠀⠀⠀⢀⣀⣠⣴⡶⠚⠋⢹⣿⢹⣿⡇⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⣿⣇⠀⠀⢀⣀⣀⣠⡤⠶⠖⢛⣯⣵⠾⠿⠛⠓⠀⠀⢻⢘⣿⡇⠀⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠉⣉⣉⣀⣀⣄⡀⠀⠛⠋⢀⣴⣾⣿⠆⠀⠀⠈⢯⣿⠃⠀⠈⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣼⡌⠉⢩⣽⣽⠽⢹⠀⠀⠀⠈⠈⠛⠁⠀⠀⠀⣠⡾⠃⠀⠀⠀⠀⠈⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣯⣧⠀⠁⠈⠉⠀⣼⣤⡤⠶⣶⠒⠒⠒⢚⣉⣭⠟⠁⠀⠀⠀⣀⣤⣤⠀⠹⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣧⣀⡤⠖⣫⣽⠶⣷⠚⠉⠉⢿⠉⢉⡾⠁⠀⢀⡴⠞⠉⣁⣀⣤⠤⠤⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠤⠖⠛⢹⠀⠀⢻⡀⠀⠀⢸⡶⠋⢀⡠⢞⣣⠴⠚⠋⠁⠀⠀⠀⠀⠈⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣧⠀⠀⠈⣧⠀⠀⢧⣀⡴⠋⠀⠀⢉⡴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣇⠀⠀⠈⠂⢀⡼⠋⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡿⣆⠀⠀⣰⠟⠁⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣶⠶⠖⠚⠉⠉⠙⠓⠶⣤⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡟⠀⠙⣦⡾⠁⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⢀⡤⠶⠋⠉⣠⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢶⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⠟⠀⠀⣰⠟⠀⣠⡶⠋⠀⠀⠀⠀⠀⠀⢀⣤⠞⠉⠀⠀⠀⡼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣆⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡿⠃⠀⢀⡴⠃⢀⡀⠁⠀⠀⠀⠀⠀⢀⡤⠒⢿⡀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣇
⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⡁⠀⠀⣾⡁⣠⠞⠁⠀⠀⠀⠀⣀⡴⠋⠁⠀⠀⠻⠀⠀⢠⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣇⠀⢰⡏⠉⠁⠀⠀⠀⣀⡴⠚⠁⠀⢀⣴⠀⠀⠀⠀⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸
⠀⠀⠀⠀⠀⠀⠀⢀⣤⠾⣿⠀⠀⠁⠀⠀⢀⣤⢾⡅⠀⠀⣠⡴⠋⠁⠀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸
⠀⠀⠀⠀⠀⠀⣠⠟⠁⠀⢸⡧⠤⠶⣺⣿⡉⠀⢸⣅⣴⠟⠁⠀⠀⠀⠀⠀⠀⣸⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸
⠀⠀⠀⠀⠀⢠⡟⠀⢀⣴⠛⡇⢸⡼⣿⣿⣿⣤⠾⡏⠁⠀⠀⠀⠀⠀⠀⠀⡼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸
⠀⠀⠀⠀⠀⢸⠀⣠⠞⢁⣴⡇⠘⣧⣽⡇⡟⠀⠀⠈⠃⠀⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿
⠀⠀⠀⠀⠀⠸⠾⠃⠀⠾⠀⠻⠋⠉⠘⠿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠐⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃
"""

CREDIT = "Port Scanner  |  coded by Mr Sabaz Ali Khan"

# ----------------------------------------------------------------------------
# Colours
# ----------------------------------------------------------------------------
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    X = "\033[0m"


def show_banner():
    print(C.CY + BANNER + C.X)
    print(C.BOLD + C.G + f"  {CREDIT}" + C.X)
    print(C.DIM + "  Custom TCP/UDP scanner - socket programming" + C.X)
    print(C.Y + "  Use only on systems you own or are authorised to test.\n" + C.X)


# ----------------------------------------------------------------------------
# Port helpers
# ----------------------------------------------------------------------------
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 500, 514, 515, 587, 631, 993, 995, 1080,
    1194, 1433, 1521, 1701, 1723, 1900, 2049, 2082, 2083, 2181, 3000, 3306,
    3389, 4500, 5000, 5060, 5432, 5601, 5672, 5900, 5985, 6379, 6667, 8000,
    8008, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017,
]


def parse_ports(spec):
    """Accepts: '80', '1-1024', '22,80,443', '1-100,443', 'top', 'all'."""
    spec = spec.strip().lower()
    if spec == "top":
        return sorted(set(TOP_PORTS))
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Port(s) out of range 1-65535: {bad[:5]}")
    return sorted(ports)


def service_name(port, proto):
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


# ----------------------------------------------------------------------------
# UDP probes: many UDP services only answer a well-formed request
# ----------------------------------------------------------------------------
UDP_PROBES = {
    # DNS: standard query for version.bind / example.com A record
    53: bytes.fromhex(
        "6a6b01000001000000000000076578616d706c6503636f6d0000010001"
    ),
    # NTP client request (mode 3)
    123: b"\x1b" + 47 * b"\x00",
    # SNMP v1 GetRequest sysDescr, community "public"
    161: bytes.fromhex(
        "302602010004067075626c6963a019020400000001020100020100"
        "300b300906052b060102010500"
    ),
    # NetBIOS name query
    137: bytes.fromhex(
        "a2480000000100000000000020434b4141414141414141414141414141414141"
        "41414141414141414141410000210001"
    ),
    # SSDP M-SEARCH
    1900: (
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    ),
    # IKE / ISAKMP (minimal header)
    500: bytes.fromhex("0000000000000000000000000000000001100200000000000000001c"),
    # TFTP read request
    69: b"\x00\x01test.txt\x00octet\x00",
    # mDNS
    5353: bytes.fromhex("000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001"),
    # SIP OPTIONS
    5060: (
        b"OPTIONS sip:100@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\n"
        b"From: <sip:scan@127.0.0.1>\r\nTo: <sip:100@127.0.0.1>\r\n"
        b"Call-ID: scan@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"
    ),
}
GENERIC_UDP_PROBE = b"\x00" * 8


# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------
class PortScanner:
    def __init__(self, target, timeout=1.0, threads=200, grab_banner=True,
                 retries=1, verbose=False):
        self.target_name = target
        self.target_ip = self.resolve(target)
        self.timeout = timeout
        self.threads = threads
        self.grab_banner = grab_banner
        self.retries = retries
        self.verbose = verbose
        self.results = []

    # --- name resolution -----------------------------------------------------
    @staticmethod
    def resolve(host):
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as exc:
            raise SystemExit(f"{C.R}[!] Cannot resolve '{host}': {exc}{C.X}")

    # --- TCP -----------------------------------------------------------------
    def scan_tcp(self, port):
        """TCP connect scan. connect_ex returns 0 when the handshake succeeds."""
        state, banner = "closed", ""
        for _ in range(self.retries + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                code = s.connect_ex((self.target_ip, port))
                if code == 0:
                    state = "open"
                    if self.grab_banner:
                        banner = self.get_banner(s, port)
                    break
                # ECONNREFUSED -> closed; anything else (timeout etc.) -> filtered
                if code in (111, 10061, 61):
                    state = "closed"
                    break
                state = "filtered"
            except socket.timeout:
                state = "filtered"
            except OSError:
                state = "filtered"
            finally:
                s.close()
        return {"port": port, "proto": "tcp", "state": state,
                "service": service_name(port, "tcp"), "banner": banner}

    def get_banner(self, sock, port):
        """Read a passive banner; if silent, send a protocol-appropriate probe."""
        try:
            sock.settimeout(min(self.timeout, 2.0))
            try:
                data = sock.recv(1024)
                if data:
                    return self.clean(data)
            except socket.timeout:
                pass
            if port in (80, 8000, 8008, 8080, 8888, 9000, 9090, 3000, 5000):
                probe = (f"HEAD / HTTP/1.0\r\nHost: {self.target_name}\r\n"
                         "User-Agent: PortScanner\r\n\r\n").encode()
            else:
                probe = b"\r\n"
            sock.sendall(probe)
            data = sock.recv(1024)
            return self.clean(data)
        except OSError:
            return ""

    @staticmethod
    def clean(data):
        text = data.decode("utf-8", errors="replace")
        text = " ".join(text.split())
        return text[:120]

    # --- UDP -----------------------------------------------------------------
    def scan_udp(self, port):
        """
        UDP scan logic:
          * reply received          -> open
          * ICMP port unreachable   -> closed (surfaces as ConnectionRefused/Reset)
          * silence                 -> open|filtered (cannot tell the difference)
        """
        probe = UDP_PROBES.get(port, GENERIC_UDP_PROBE)
        state, banner = "open|filtered", ""
        for _ in range(self.retries + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            try:
                s.connect((self.target_ip, port))
                s.send(probe)
                data = s.recv(1024)
                state = "open"
                if self.grab_banner and data:
                    banner = self.clean(data) or data[:24].hex()
                break
            except socket.timeout:
                state = "open|filtered"
            except (ConnectionRefusedError, ConnectionResetError):
                state = "closed"
                break
            except OSError:
                state = "filtered"
            finally:
                s.close()
        return {"port": port, "proto": "udp", "state": state,
                "service": service_name(port, "udp"), "banner": banner}

    # --- driver --------------------------------------------------------------
    def run(self, ports, do_tcp=True, do_udp=False, show_closed=False):
        jobs = []
        if do_tcp:
            jobs += [("tcp", p) for p in ports]
        if do_udp:
            jobs += [("udp", p) for p in ports]

        print(f"{C.B}[*] Target   : {self.target_name} ({self.target_ip}){C.X}")
        print(f"{C.B}[*] Ports    : {len(ports)}   Protocols: "
              f"{'TCP ' if do_tcp else ''}{'UDP' if do_udp else ''}{C.X}")
        print(f"{C.B}[*] Threads  : {self.threads}   Timeout: {self.timeout}s   "
              f"Retries: {self.retries}{C.X}")
        print(f"{C.B}[*] Started  : {datetime.now():%Y-%m-%d %H:%M:%S}{C.X}\n")
        print(f"{C.BOLD}{'PORT':<10}{'STATE':<16}{'SERVICE':<16}BANNER{C.X}")
        print("-" * 78)

        start = time.time()
        done = 0
        total = len(jobs)
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = []
                for proto, port in jobs:
                    fn = self.scan_tcp if proto == "tcp" else self.scan_udp
                    futures.append(pool.submit(fn, port))
                for fut in as_completed(futures):
                    r = fut.result()
                    done += 1
                    self.results.append(r)
                    self.print_result(r, show_closed)
                    if not self.verbose and done % 500 == 0:
                        print(f"{C.DIM}    ... {done}/{total} probes done{C.X}")
        except KeyboardInterrupt:
            print(f"\n{C.R}[!] Interrupted by user - showing partial results{C.X}")

        self.elapsed = time.time() - start
        self.summary()

    def print_result(self, r, show_closed):
        st = r["state"]
        if st == "open":
            colour = C.G
        elif st == "open|filtered":
            colour = C.Y
        elif st == "filtered":
            colour = C.M
        else:
            colour = C.R
            if not show_closed:
                return
        if st == "filtered" and not show_closed and not self.verbose:
            return
        label = f"{r['port']}/{r['proto']}"
        print(f"{colour}{label:<10}{st:<16}{r['service']:<16}{C.X}"
              f"{C.DIM}{r['banner']}{C.X}")

    def summary(self):
        self.results.sort(key=lambda r: (r["proto"], r["port"]))
        count = lambda s: sum(1 for r in self.results if r["state"] == s)
        print("-" * 78)
        print(f"{C.G}[+] Open           : {count('open')}{C.X}")
        print(f"{C.Y}[+] Open|Filtered  : {count('open|filtered')}{C.X}")
        print(f"{C.M}[+] Filtered       : {count('filtered')}{C.X}")
        print(f"{C.R}[+] Closed         : {count('closed')}{C.X}")
        print(f"{C.B}[*] Completed in {self.elapsed:.2f}s{C.X}")
        print(f"\n{C.BOLD}{C.G}{CREDIT}{C.X}\n")

    # --- reports -------------------------------------------------------------
    def save(self, path):
        interesting = [r for r in self.results
                       if r["state"] in ("open", "open|filtered")]
        if path.lower().endswith(".json"):
            payload = {
                "tool": "Port Scanner",
                "author": "Mr Sabaz Ali Khan",
                "target": self.target_name,
                "ip": self.target_ip,
                "scanned_at": datetime.now().isoformat(timespec="seconds"),
                "duration_seconds": round(self.elapsed, 2),
                "results": interesting,
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(BANNER + "\n" + CREDIT + "\n\n")
                fh.write(f"Target: {self.target_name} ({self.target_ip})\n")
                fh.write(f"Date  : {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
                fh.write(f"{'PORT':<10}{'STATE':<16}{'SERVICE':<16}BANNER\n")
                for r in interesting:
                    fh.write(f"{r['port']}/{r['proto']:<6}{r['state']:<16}"
                             f"{r['service']:<16}{r['banner']}\n")
        print(f"{C.G}[+] Report saved to {path}{C.X}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Custom TCP/UDP port scanner - coded by Mr Sabaz Ali Khan",
        epilog="Examples:\n"
               "  python3 port_scanner.py 192.168.1.10 -p 1-1024\n"
               "  python3 port_scanner.py scanme.nmap.org -p top --udp\n"
               "  python3 port_scanner.py 10.0.0.5 -p 22,80,443 -t -o report.json\n"
               "  python3 port_scanner.py 10.0.0.5 -p 53,123,161 -u\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="Hostname or IPv4 address to scan")
    p.add_argument("-p", "--ports", default="top",
                   help="Ports: 80 | 1-1024 | 22,80,443 | top | all  (default: top)")
    p.add_argument("-t", "--tcp", action="store_true", help="TCP connect scan")
    p.add_argument("-u", "--udp", action="store_true", help="UDP scan")
    p.add_argument("-T", "--timeout", type=float, default=1.0,
                   help="Socket timeout in seconds (default 1.0)")
    p.add_argument("-w", "--threads", type=int, default=200,
                   help="Worker threads (default 200)")
    p.add_argument("-r", "--retries", type=int, default=1,
                   help="Retries per port on timeout (default 1)")
    p.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    p.add_argument("--show-closed", action="store_true",
                   help="Also print closed/filtered ports")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("-o", "--output", help="Save report (.json or .txt)")
    p.add_argument("--no-banner-art", action="store_true",
                   help="Hide the ASCII banner")
    return p


def main():
    args = build_parser().parse_args()
    if not args.no_banner_art:
        show_banner()
    else:
        print(C.BOLD + C.G + CREDIT + C.X + "\n")

    # Default: TCP if nothing selected
    do_tcp = args.tcp or not args.udp
    do_udp = args.udp

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        sys.exit(f"{C.R}[!] Invalid port specification: {exc}{C.X}")

    scanner = PortScanner(
        args.target,
        timeout=args.timeout,
        threads=max(1, args.threads),
        grab_banner=not args.no_banner,
        retries=max(0, args.retries),
        verbose=args.verbose,
    )
    scanner.run(ports, do_tcp=do_tcp, do_udp=do_udp, show_closed=args.show_closed)

    if args.output:
        scanner.save(args.output)


if __name__ == "__main__":
    main()
