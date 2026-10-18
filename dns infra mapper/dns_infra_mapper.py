#!/usr/bin/env python3
"""
DNS & Network Infrastructure Mapper
coded by Mr Sabaz Ali Khan

Maps a target domain's DNS and network infrastructure:
  - Core records: A, AAAA, MX, NS, TXT, SOA, CNAME
  - Mail infrastructure: MX hosts -> resolved IPs -> reverse DNS (PTR)
  - ASN / organization / hosting provider lookup per resolved IP (RDAP)
  - Sibling / related domains sharing the same nameservers, MX hosts,
    or SPF "include:" entries
  - Subdomain discovery via certificate transparency (crt.sh)
  - Lightweight CDN / hosting-provider fingerprinting from CNAME + ASN org
  - JSON / CSV export + a plain-text infrastructure summary report

Dependencies: dnspython, requests
    pip install dnspython requests --break-system-packages

Usage:
    python3 dns_infra_mapper.py example.com
    python3 dns_infra_mapper.py example.com --json out.json --csv out.csv
    python3 dns_infra_mapper.py example.com --no-ct      (skip crt.sh lookup)
    python3 dns_infra_mapper.py example.com --timeout 5
"""

import argparse
import concurrent.futures
import csv
import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    print("[!] Missing dependency: dnspython. Install with:")
    print("    pip install dnspython --break-system-packages")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests. Install with:")
    print("    pip install requests --break-system-packages")
    sys.exit(1)

BANNER = r"""
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠘⢿⣿⣿⣿⡿⠉⣿⣿⡿⣻⠃⠀⠘⣿⣿⣿⣿⠋⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠙⢿⡿⠃⢀⣿⠿⠁⠁⠀⠀⢀⣿⣿⠟⠁⠀⢻⣿⣿⠟⠋⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠈⢿⣿⠛⠿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠘⠋⠀⠀⠀⠀⠀⢰⣟⡵⠀⠀⢀⣾⠏⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠈⢿⡆⠀⠀⠙⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣟⡿⠁⠀⡾⠉⠇⠀⠀⠛⢛⡛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢹⣿⡇⠀⠀⠀⠻⠀⠀⢸⠀⠀⢱⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠉⠉⠀⢀⡼⠁⠀⠀⠀⠀⠀⠀⢀⣤⡿⠟⠋⢨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⣿⣿⠀⠀⠀⠀⡀⠀⠸⣆⠀⠀⠂⠁⠀⠀⠀⠀⢹⠀⠀⠀⠀⠀⢰⠏⠀⠀⢀⡀⠀⠀⠀⠐⠉⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⡇⠹⣿⠷⠀⠀⠀⢸⡄⠀⠀⠀⢠⡄⠀⠀⠀⠀⠀⣾⠀⠀⠀⠀⠀⠀⣀⣴⠞⠉⠠⠖⠀⠠⠀⠀⠀⠀⠀⠾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠙⢷⠀⠈⠀⠀⠐⢦⣀⢳⡄⠀⠀⠈⢳⡀⠀⠀⠀⢀⣿⢀⣴⢆⣠⣴⣾⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⢉⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠄⠀⠀⠀⠀⠀⠀⠈⠁⠀⠁⢤⣀⣈⣳⣄⣀⣠⣾⠿⢋⡿⠿⠿⣿⣃⣉⣀⣠⣤⣴⡶⠿⠋⣀⣀⠀⠀⠀⠀⠀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣦⠈⠉⠉⠉⠁⠀⠀⠀⠀⠠⣤⣀⡀⠀⣀⣰⣴⠖⠛⠛⠋⣭⠁⢨⣇⠀⢠⡄⠀⠀⠀⠀⠀⠀⠀⠈⢻⢷⡼⠟⠉⠀⠀⠀⠀⠀⠫⠵⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣧⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠷⣾⠟⠀⠀⠀⠀⠀⢠⡏⢀⣸⣿⠀⣦⢹⣆⠀⠀⠀⠀⠀⠀⠀⠈⠙⠷⣄⠀⠀⠀⠀⠀⠀⢦⣀⣀⣉⣻⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡻⢯⠅⠀⠐⠦⢤⣤⣥⠤⠴⠒⣴⠏⠀⠀⠀⠀⠀⠀⣸⣧⣸⡿⠛⢰⣿⠾⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⣿⡇⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⠶⠀⠀⠀⠀⠀⣠⡾⠁⠀⠀⠀⠀⠀⠀⠀⣽⡟⠉⣿⠀⢸⡏⠀⠀⠙⠂⣀⣀⣤⣤⠶⠆⠀⠀⠀⢹⣧⡀⢤⣀⠀⠀⢀⣈⣻⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⢿⠿⠿⠿⠛⠋⠁⠀⠀⠀⠀⢀⣴⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠀⠀⡇⠀⢀⣴⠿⠋⣄⣤⠤⠤⠀⠀⠀⠀⠀⢻⣿⣷⣮⣷⣦⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣷⡀⠀⠀⠀⠀⣠⠀⠀⠀⢠⣶⣻⣿⠇⠀⠀⠀⠐⠚⠉⠉⠉⠛⠻⡶⣤⡀⠀⠀⠀⠀⣿⢉⣴⠟⣉⣥⣤⠶⠶⠶⢶⡀⠀⢹⣿⣿⣷⣦⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣄⣀⣀⣴⠋⠀⣀⣴⢿⡿⢫⡿⠀⠀⠀⠀⠀⢠⣶⣾⣛⣛⣛⣿⣿⣻⣆⠀⠀⠀⠻⠿⠱⡿⠋⣸⣷⣤⡀⠀⣠⣇⠀⠘⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡋⢁⣤⣾⣿⠗⢈⣴⣿⣷⠀⠀⢀⡶⠚⠉⠉⢀⣤⣄⠙⢯⡈⠛⢙⣦⣀⡀⠀⠀⠀⢧⣤⣹⣿⣟⣀⣴⣯⡏⣶⡶⠀⣿⡿⠋⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣆⣸⣿⣿⣿⡀⠀⢈⡻⣄⠀⠀⠻⣾⢿⣀⡬⠁⣰⣿⣿⠿⠿⣷⣦⣄⣀⣀⡀⠀⠀⠀⣩⣷⣾⣿⡧⠀⣿⢠⡟⣳⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣴⢦⡙⣿⣷⣦⠾⠚⠋⠁⣀⣼⡿⠋⠉⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠰⠻⡿⢿⣷⢴⢡⣟⢳⡍⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢀⠈⠻⣇⣸⣷⡿⣟⠶⠆⠀⠀⠀⠈⠉⠉⠀⠀⡀⠀⠀⢠⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢰⢈⣿⣿⠁⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠿⠛⣦⡈⣻⣿⡟⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣷⡠⠾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⢸⣼⡿⠃⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠸⣿⣇⠉⠻⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⣀⣀⣀⣀⣰⣦⡀⠀⠀⣾⣧⡾⠋⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠹⢿⣧⣄⠙⣿⡄⠀⠀⠀⠀⠀⠀⠀⣀⣤⠴⠖⠚⠛⠋⣉⣀⣀⣀⣤⣤⡟⠁⠀⢰⣿⢿⣧⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠉⠉⢷⣼⣿⡆⠀⠀⢠⣶⠖⢫⣉⣀⣤⣶⣶⣿⣯⣿⡿⠟⣩⠼⠋⠀⠀⠀⣾⣿⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣴⣿⡸⣿⣄⠀⠈⠙⠳⠶⠤⠍⠍⠉⠁⠀⠤⠤⣖⡏⠀⠀⠀⠀⢠⣾⡿⣳⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢷⡹⣿⣷⣄⠀⠀⠀⠀⠀⠀⠒⠒⠒⠛⠛⠉⠀⢀⣀⣀⣴⣿⢋⣾⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡈⠻⢦⡙⢿⣷⣄⣀⠀⣠⣶⣤⣄⡀⠀⠀⣴⢿⣿⠿⠿⠟⣵⠟⣱⠏⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠙⠳⣭⣛⠿⠿⠛⠛⣷⣽⡆⠀⢀⣯⡼⠃⠀⣠⡾⠃⣴⠃⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠉⠛⠦⣤⣀⠈⠻⠛⠀⠀⠀⠀⣠⡾⠋⣀⣴⡇⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣀⣄⠀⠀⠀⠀⠀⠉⠛⠓⠒⠒⠒⠒⠛⠁⣠⡞⢹⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢀⡞⢻⣹⠀⠀⠀⠀⠀⠰⡄⠀⠀⠀⠀⠀⢠⡾⠉⠀⢸⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠘⡿⣧⠀⠀⠀⠀⠀⢻⡄⠀⠀⠀⣴⠏⠀⠀⠀⣸⡏⠀⠀⢸⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢻⡇⠀⠀⢹⣽⡀⠀⠀⠀⠀⠈⢳⣦⣀⡾⠃⠀⠀⠀⠀⣿⠃⠀⠀⢸⠀⠈⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣁⣀⣸⡇⠀⠀⠈⢿⣇⠀⠀⠀⠀⠀⠀⠸⢿⠁⠀⠀⠀⠀⠀⣿⠀⠀⠀⢸⡇⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠉⠉⠻⣿⠀⠀⠀⠘⣿⡆⢸⡛⠳⣤⡀⠀⠸⡇⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⡄⠀⠀⠀⢻⣇⢸⡇⠀⠀⠙⠻⠾⠃⠀⠀⠀⠀⢰⡇⠀⠀⠀⢧⠀⠀⠀⠀⠀⠀⠘⢿⠿⠿⠿⠿⠇⠈⠛⠿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⢡⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⢀⡇⠀⠀⠀⠀⢻⡦⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠁⠀⠀⠀⢸⣆⠀⠀⠀⠀⠀⠀⠘⣤⣤⣤⣤⣤⣄⠀⠀⠀
⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠾⠟⠛⠉⠉⠀⠀⠀⠀⠀⠀⢠⣿⠀⠀⠀⠀⠀⠀⢹⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀⠀⠀⠀⢸⣿⣦⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⡀⠀⠀
⠿⠛⠋⠀⠀⠀⣀⣤⠀⠀⣠⣤⣤⣶⣶⣿⠇⠀⠀⠀⠀⣰⣿⣿⠀⠀⠀⠀⠀⠀⠀⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⣾⠁⠀⠀⠀⠀⢸⢿⠘⠷⣄⣀⣀⣀⣀⣨⣿⡿⠿⠟⠛⣛⣀⠀
⠀⠀⠀⠀⠀⠾⣯⣄⡀⢠⣿⣿⣿⣿⣿⡟⠀⠀⠀⣠⡾⣿⠏⣿⠀⠀⠀⠀⠀⠀⠀⠀⢿⣷⡀⠀⠀⠀⠀⠀⢠⠇⠀⣀⣀⣤⣤⠾⠞⠓⠊⠉⠉⠉⠉⠀⠀⠀⢷⣶⣿⣿⣿⣿⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠉⢉⣙⣛⠻⠿⠿⠧⠤⠴⢿⣯⣿⠃⠀⣿⣀⣀⣀⣀⠀⠀⠀⠀⠀⢻⣷⣦⣀⠀⢀⣴⣿⡔⠋⠁⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿
              DNS & NETWORK INFRASTRUCTURE MAPPER
                 coded by Mr Sabaz Ali Khan
"""

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
CDN_FINGERPRINTS = {
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai"],
    "fastly": ["fastly"],
    "amazon cloudfront": ["cloudfront"],
    "google": ["googleusercontent", "google llc", "google cloud"],
    "microsoft azure": ["microsoft corporation", "azure"],
    "digitalocean": ["digitalocean"],
    "ovh": ["ovh"],
    "incapsula / imperva": ["incapsula", "imperva"],
    "sucuri": ["sucuri"],
}


@dataclass
class HostInfo:
    ip: str
    ptr: str | None = None
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    cdn_guess: str | None = None


@dataclass
class MapResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    mail_hosts: dict[str, list[HostInfo]] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    a_hosts: list[HostInfo] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    sibling_domains: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def resolve_records(domain: str, timeout: float) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    out: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                out[rtype] = sorted(
                    f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers
                )
            elif rtype == "SOA":
                out[rtype] = [str(a).rstrip(".") for a in answers]
            else:
                out[rtype] = sorted(str(a).rstrip('"').rstrip(".") if rtype != "TXT"
                                     else str(a).strip('"') for a in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            out[rtype] = []
        except Exception as e:
            out[rtype] = []
    return out


def reverse_dns(ip: str, timeout: float) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        rev = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev, "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


def resolve_ip(hostname: str, timeout: float) -> list[str]:
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def rdap_lookup(ip: str, timeout: float) -> dict[str, Any]:
    """Query RDAP (rdap.org bootstrap) for ASN/org/country info on an IP."""
    result = {"asn": None, "org": None, "country": None}
    try:
        resp = requests.get(f"https://rdap.org/ip/{ip}", timeout=timeout,
                             headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            return result
        data = resp.json()
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field_ in vcard[1]:
                    if field_[0] == "fn":
                        result["org"] = field_[3]
                        break
            if result["org"]:
                break
        if not result["org"]:
            result["org"] = data.get("name")
        result["country"] = data.get("country")
        for rem in data.get("remarks", []):
            pass
        cidr0 = data.get("cidr0_cidrs")
        result["asn"] = data.get("handle")
    except Exception:
        pass
    return result


def guess_cdn(org: str | None, cname_chain: list[str]) -> str | None:
    haystack = " ".join(filter(None, [org or "", *cname_chain])).lower()
    for cdn_name, needles in CDN_FINGERPRINTS.items():
        if any(n in haystack for n in needles):
            return cdn_name
    return None


def build_host_info(ip: str, timeout: float, cname_chain: list[str]) -> HostInfo:
    ptr = reverse_dns(ip, timeout)
    rdap = rdap_lookup(ip, timeout)
    cdn = guess_cdn(rdap.get("org"), cname_chain)
    return HostInfo(ip=ip, ptr=ptr, asn=rdap.get("asn"), org=rdap.get("org"),
                     country=rdap.get("country"), cdn_guess=cdn)


def extract_spf_includes(txt_records: list[str]) -> list[str]:
    includes = []
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            for token in txt.split():
                if token.lower().startswith("include:"):
                    includes.append(token.split(":", 1)[1])
    return includes


def crtsh_subdomains(domain: str, timeout: float) -> list[str]:
    """Pull subdomains from certificate transparency logs via crt.sh."""
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                             timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
        names = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and "*" not in name and name.endswith(domain):
                    names.add(name)
        return sorted(names)
    except Exception:
        return []


def find_sibling_domains(domain: str, nameservers: list[str],
                          mx_hosts: list[str], timeout: float) -> dict[str, list[str]]:
    """
    Best-effort: reverse-check a small set of common TLD variants / known
    registrar patterns is out of scope without a paid reverse-WHOIS API,
    so this function instead reports the infrastructure fingerprints
    (shared NS / MX) that a user can pivot on with a reverse-DNS/WHOIS
    service of their choice.
    """
    return {
        "shared_nameservers": nameservers,
        "shared_mail_hosts": mx_hosts,
        "note": ["Use a reverse-WHOIS/reverse-NS service with these "
                 "values to enumerate domains sharing this infrastructure."],
    }


def map_domain(domain: str, timeout: float, do_ct: bool) -> MapResult:
    result = MapResult(domain=domain)
    print(f"[*] Resolving core DNS records for {domain} ...")
    records = resolve_records(domain, timeout)
    result.records = records
    result.nameservers = records.get("NS", [])

    a_ips = records.get("A", []) + records.get("AAAA", [])
    cname_chain = records.get("CNAME", [])

    print(f"[*] Looking up ASN/org info for {len(a_ips)} resolved IP(s) ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(build_host_info, ip, timeout, cname_chain): ip
                   for ip in a_ips}
        for fut in concurrent.futures.as_completed(futures):
            try:
                result.a_hosts.append(fut.result())
            except Exception as e:
                result.errors.append(f"host info failed for {futures[fut]}: {e}")

    mx_records = records.get("MX", [])
    mx_hostnames = []
    for mx in mx_records:
        parts = mx.split(" ", 1)
        if len(parts) == 2:
            mx_hostnames.append(parts[1])

    print(f"[*] Mapping {len(mx_hostnames)} mail host(s) ...")
    for mx_host in mx_hostnames:
        ips = resolve_ip(mx_host, timeout)
        host_infos = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(build_host_info, ip, timeout, []) for ip in ips]
            for f in concurrent.futures.as_completed(futs):
                try:
                    host_infos.append(f.result())
                except Exception:
                    pass
        result.mail_hosts[mx_host] = host_infos

    result.spf_includes = extract_spf_includes(records.get("TXT", []))

    if do_ct:
        print(f"[*] Querying certificate transparency logs (crt.sh) ...")
        result.subdomains = crtsh_subdomains(domain, timeout)
        print(f"    -> found {len(result.subdomains)} subdomain(s)")

    result.sibling_domains = find_sibling_domains(
        domain, result.nameservers, mx_hostnames, timeout)

    return result


def print_report(result: MapResult) -> None:
    print("\n" + "=" * 70)
    print(f" INFRASTRUCTURE MAP: {result.domain}")
    print("=" * 70)

    print("\n-- Core DNS Records --")
    for rtype in RECORD_TYPES:
        vals = result.records.get(rtype, [])
        if vals:
            print(f"  {rtype}:")
            for v in vals:
                print(f"    - {v}")

    print("\n-- Resolved A/AAAA Hosts --")
    for h in result.a_hosts:
        print(f"  {h.ip}")
        if h.ptr:
            print(f"    PTR: {h.ptr}")
        if h.org:
            print(f"    Org/ASN: {h.org} ({h.asn})")
        if h.country:
            print(f"    Country: {h.country}")
        if h.cdn_guess:
            print(f"    Likely CDN/host: {h.cdn_guess}")

    print("\n-- Mail Infrastructure --")
    for mx_host, hosts in result.mail_hosts.items():
        print(f"  {mx_host}")
        for h in hosts:
            print(f"    -> {h.ip}  org={h.org}  ptr={h.ptr}")

    if result.spf_includes:
        print("\n-- SPF include: targets (possible related infra) --")
        for inc in result.spf_includes:
            print(f"  - {inc}")

    if result.subdomains:
        print(f"\n-- Subdomains discovered via crt.sh ({len(result.subdomains)}) --")
        for sub in result.subdomains[:50]:
            print(f"  - {sub}")
        if len(result.subdomains) > 50:
            print(f"  ... and {len(result.subdomains) - 50} more (see export file)")

    print("\n-- Pivot points for sibling/related domain discovery --")
    for k, v in result.sibling_domains.items():
        if k == "note":
            continue
        print(f"  {k}: {v}")
    print(f"  note: {result.sibling_domains.get('note', [''])[0]}")

    if result.errors:
        print("\n-- Errors / Warnings --")
        for e in result.errors:
            print(f"  ! {e}")

    print("\n" + "=" * 70)


def export_json(result: MapResult, path: str) -> None:
    def default(o):
        if isinstance(o, HostInfo):
            return asdict(o)
        return str(o)
    with open(path, "w") as f:
        json.dump(asdict(result), f, indent=2, default=default)
    print(f"[+] JSON report written to {path}")


def export_csv(result: MapResult, path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "key", "value1", "value2", "value3", "value4"])
        for rtype, vals in result.records.items():
            for v in vals:
                writer.writerow(["dns_record", rtype, v, "", "", ""])
        for h in result.a_hosts:
            writer.writerow(["a_host", h.ip, h.ptr or "", h.org or "",
                              h.asn or "", h.cdn_guess or ""])
        for mx_host, hosts in result.mail_hosts.items():
            for h in hosts:
                writer.writerow(["mail_host", mx_host, h.ip, h.org or "",
                                  h.ptr or "", ""])
        for sub in result.subdomains:
            writer.writerow(["subdomain", sub, "", "", "", ""])
        for inc in result.spf_includes:
            writer.writerow(["spf_include", inc, "", "", "", ""])
    print(f"[+] CSV report written to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="DNS & Network Infrastructure Mapper - coded by Mr Sabaz Ali Khan")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--timeout", type=float, default=6.0,
                         help="Per-query timeout in seconds (default: 6)")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV file")
    parser.add_argument("--no-ct", action="store_true",
                         help="Skip certificate-transparency subdomain lookup")
    parser.add_argument("--no-banner", action="store_true",
                         help="Suppress the ASCII banner on startup")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    start = time.time()
    result = map_domain(args.domain, args.timeout, do_ct=not args.no_ct)
    print_report(result)
    print(f"\n[*] Completed in {time.time() - start:.2f}s")

    if args.json:
        export_json(result, args.json)
    if args.csv:
        export_csv(result, args.csv)


if __name__ == "__main__":
    main()
