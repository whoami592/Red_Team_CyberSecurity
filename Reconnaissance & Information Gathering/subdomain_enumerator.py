#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Enumerator - DNS Brute Force + Certificate Transparency
Coded by Cyber Security Engineer Mr Sabaz Ali Khan

Use ONLY against domains you own or have explicit written permission to test.

Features:
  * Certificate Transparency discovery (crt.sh)
  * Multi-threaded DNS brute force (built-in or custom wordlist)
  * Wildcard DNS detection and filtering
  * Optional custom resolvers (requires dnspython; falls back to system resolver)
  * Output to TXT / JSON / CSV

Usage:
  python3 subdomain_enumerator.py -d example.com
  python3 subdomain_enumerator.py -d example.com -w words.txt -t 100 -o out.json
  python3 subdomain_enumerator.py -d example.com --no-brute          # CT only
  python3 subdomain_enumerator.py -d example.com --no-ct             # brute only
  python3 subdomain_enumerator.py -d example.com -r 1.1.1.1,8.8.8.8  # needs dnspython
"""

import argparse
import csv
import json
import random
import re
import socket
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver  # type: ignore
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

BANNER = r"""
⢀⣀⠀⠀⠀⠰⣶⡖⠲⠦⠤⣿⣝⠲⣤⣄⡀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠸⣿⡉⠛⣒⠲⠾⡟⠓⠒⠲⡾⢿⣿⢿⡦⣍⠻⣷⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠹⣟⢄⡈⠙⠢⠤⣀⣀⣀⣙⣦⣙⠻⢦⣌⡳⠄⣿⣮⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⡷⣝⡢⠄⢰⡚⠛⠓⠒⠤⠬⣿⡶⠬⡅⠘⢿⣷⠀⣻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠹⣗⣤⣽⡦⠄⠙⢦⣀⠀⠀⠀⢻⠘⣆⢰⣒⣦⣤⣼⣍⡿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⠙⣿⢯⣔⣒⣀⣈⠿⠒⣀⡤⠒⠋⠉⠁⠀⠀⠀⠉⣿⡘⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠿⠷⢶⡞⠋⠉⢩⠤⠞⠁⠀⠀⠀⢀⣀⣤⠤⠲⣞⣿⣷⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣀⣀⣀⣠⠤⠤⠖⢒⣿⠿⠟⠛⠂⠀⢹⣿⣿⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣻⡠⠤⣤⣴⣦⡀⠉⠁⠴⣿⠟⠀⠀⠀⣿⠏⠀⠀⠑⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢻⣿⣇⠀⠛⠛⠁⣇⣀⣤⡤⠤⠤⠤⢰⡾⠃⠀⠀⢀⣀⡈⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣤⡤⠖⣫⠵⢷⠚⠛⢻⠉⣹⠋⠀⣠⠔⢊⣁⡤⠤⠌⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣷⠚⠉⢱⠀⠸⡄⠀⣠⠟⠁⠴⣫⠔⠊⠁⠀⠀⠀⠀⠈⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣇⠀⠀⠇⠀⣱⠞⠁⠀⡠⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⡿⣆⠀⢠⠞⠁⠀⡠⠊⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⠤⠔⠒⠚⠓⠒⠤⣄⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⡿⠁⠈⡶⠃⢀⡴⠊⠀⠀⠀⠀⠀⣠⠴⠚⠉⣠⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢆⠀⠀
⠀⠀⠀⠀⠀⠀⢰⣿⣿⠟⠀⢀⠞⠁⠐⠋⠀⠀⠀⠀⣠⢴⡎⠁⠀⠀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⠀
⠀⠀⠀⠀⠀⠀⠈⢿⡇⠀⢠⣏⣠⠞⠀⠀⠀⢀⡴⠊⠁⠀⠳⠀⢀⡜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡇
⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠸⠈⠀⠀⢀⡤⠖⠉⠀⣠⠆⠀⠀⢀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⢀⡴⠋⢹⣆⣀⣠⣤⠒⠙⡇⣠⠔⠋⠀⠀⠀⠀⣸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⡞⠀⢀⠼⡇⢰⣾⣿⣷⡴⣟⠁⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⣇⡴⢁⡴⣇⣨⣼⣿⠋⠀⠈⠀⠀⠀⠀⢀⡼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠃
⠀⠀⠀⠀⠀⠉⠀⠈⠀⠈⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

TITLE = "SUBDOMAIN ENUMERATOR  |  DNS Brute Force + Certificate Transparency"
CREDIT = "Coded by Cyber Security Engineer Mr Sabaz Ali Khan"

DEFAULT_WORDLIST = """
www mail remote blog webmail server ns1 ns2 ns3 ns4 smtp secure vpn m shop ftp
mail2 test portal ns dev admin api staging stage beta demo app apps cdn static
assets img images media video docs doc help support status monitor grafana
kibana jenkins gitlab git github bitbucket svn ci cd build repo registry docker
k8s kube kubernetes rancher vault consul nomad prometheus alertmanager zabbix
nagios sentry elk elastic logs log syslog splunk db database mysql postgres
postgresql mongo mongodb redis memcached rabbitmq kafka mq queue cache sql mssql
oracle backup backups bak old new legacy internal intranet extranet corp
corporate office hr crm erp sap sharepoint wiki confluence jira redmine
helpdesk ticket tickets servicedesk owa exchange autodiscover lyncdiscover sip
webex meet chat im slack teams zoom conference cloud aws azure gcp s3 storage
files file upload uploads download downloads share sync drive owncloud nextcloud
auth sso login signin signup register accounts account id idp oauth ldap ad
adfs radius mfa 2fa pay payment payments billing invoice checkout store shop
cart orders order partner partners client clients customer customers vendor
vendors supplier affiliate affiliates reseller careers jobs news press media
events event forum forums community social mobile android ios ws wss socket
websocket gateway gw proxy lb loadbalancer edge origin node web web1 web2 web3
app1 app2 host host1 host2 mx mx1 mx2 pop pop3 imap relay mailer newsletter
email smtp1 smtp2 dns dns1 dns2 time ntp router fw firewall waf ids ips
dmz uat qa prod production pre preprod sandbox lab labs research analytics
stats metrics tracking track ads ad adserver search solr elasticsearch graphql
rest v1 v2 v3 api1 api2 api-dev api-test dev1 dev2 test1 test2 stg stage1
beta1 alpha demo1 preview canary status2 health ping panel cpanel whm plesk
webdisk webmin directadmin phpmyadmin pma adminer dashboard console manage
manager management control controlpanel secure2 ssl tls cert certs pki ca
vpn1 vpn2 sslvpn ra rdp ssh bastion jump jumpbox terminal tools tool utils
service services svc microservice ms lambda functions function serverless
printer print scan camera cam cctv nas san iscsi vmware vcenter esxi proxmox
hyperv xen openstack ceph
""".split()

_print_lock = threading.Lock()


def log(msg, quiet=False):
    if not quiet:
        with _print_lock:
            print(msg, flush=True)


# --------------------------------------------------------------------------- #
# DNS resolution
# --------------------------------------------------------------------------- #
class Resolver:
    def __init__(self, nameservers=None, timeout=3.0):
        self.timeout = timeout
        self.use_dnspython = bool(nameservers) and HAVE_DNSPYTHON
        if nameservers and not HAVE_DNSPYTHON:
            print("[!] Custom resolvers need dnspython (pip install dnspython). "
                  "Falling back to the system resolver.")
        if self.use_dnspython:
            self._res = dns.resolver.Resolver(configure=False)
            self._res.nameservers = nameservers
            self._res.timeout = timeout
            self._res.lifetime = timeout
        else:
            socket.setdefaulttimeout(timeout)

    def resolve(self, host):
        """Return sorted list of IPs (A/AAAA) for host, or [] if not found."""
        ips = set()
        if self.use_dnspython:
            for rtype in ("A", "AAAA"):
                try:
                    for rdata in self._res.resolve(host, rtype):
                        ips.add(rdata.to_text())
                except Exception:
                    pass
        else:
            try:
                for info in socket.getaddrinfo(host, None):
                    ips.add(info[4][0])
            except (socket.gaierror, socket.timeout, OSError):
                pass
        return sorted(ips)


def detect_wildcard(resolver, domain, tries=3):
    """Resolve random labels; any answer means wildcard DNS is in play."""
    wild_ips = set()
    for _ in range(tries):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        wild_ips.update(resolver.resolve(f"{label}.{domain}"))
    return wild_ips


# --------------------------------------------------------------------------- #
# Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------- #
def query_crtsh(domain, timeout=30, retries=3, quiet=False):
    url = "https://crt.sh/?q=" + urllib.parse.quote(f"%.{domain}") + "&output=json"
    headers = {"User-Agent": "SubdomainEnumerator/1.0 (security research)"}
    found = set()

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and (name == domain or name.endswith("." + domain)):
                        if re.fullmatch(r"[a-z0-9._-]+", name):
                            found.add(name)
            return found
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout,
                json.JSONDecodeError, ConnectionError, OSError) as exc:
            log(f"[!] crt.sh attempt {attempt}/{retries} failed: {exc}", quiet)
            time.sleep(2 * attempt)
    return found


# --------------------------------------------------------------------------- #
# Brute force
# --------------------------------------------------------------------------- #
def load_wordlist(path):
    if not path:
        return list(dict.fromkeys(DEFAULT_WORDLIST))
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().lower()
            if w and not w.startswith("#"):
                words.append(w)
    return list(dict.fromkeys(words))


def brute_force(resolver, domain, words, threads, wild_ips, quiet=False):
    results = {}
    total = len(words)
    done = 0
    lock = threading.Lock()

    def worker(word):
        host = f"{word}.{domain}"
        ips = resolver.resolve(host)
        return host, ips

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, w) for w in words]
        for fut in as_completed(futures):
            try:
                host, ips = fut.result()
            except Exception:
                continue
            with lock:
                done += 1
                if not quiet and done % 100 == 0:
                    print(f"\r[*] Brute force progress: {done}/{total}", end="", flush=True)
            if not ips:
                continue
            # Drop results that only match the wildcard answer
            if wild_ips and set(ips).issubset(wild_ips):
                continue
            results[host] = ips
            log(f"\r[+] {host:<45} {', '.join(ips)}", quiet)
    if not quiet:
        print(f"\r[*] Brute force progress: {total}/{total}          ")
    return results


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def save_results(path, domain, records):
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else "txt"
    if ext == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "tool": "Subdomain Enumerator",
                "author": "Mr Sabaz Ali Khan",
                "domain": domain,
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "count": len(records),
                "results": records,
            }, fh, indent=2)
    elif ext == "csv":
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["subdomain", "ips", "source"])
            for r in records:
                w.writerow([r["subdomain"], ";".join(r["ips"]), ",".join(r["sources"])])
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# {CREDIT}\n# Domain: {domain}\n")
            for r in records:
                fh.write(f"{r['subdomain']}\t{','.join(r['ips'])}\t{'/'.join(r['sources'])}\n")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        description="Subdomain Enumerator - DNS brute force + Certificate Transparency "
                    "(coded by Mr Sabaz Ali Khan)")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist", help="Custom wordlist file (one label per line)")
    p.add_argument("-t", "--threads", type=int, default=50, help="Brute-force threads (default 50)")
    p.add_argument("-r", "--resolvers", help="Comma-separated DNS servers (requires dnspython)")
    p.add_argument("--timeout", type=float, default=3.0, help="DNS timeout seconds (default 3)")
    p.add_argument("--no-brute", action="store_true", help="Skip DNS brute force")
    p.add_argument("--no-ct", action="store_true", help="Skip certificate transparency")
    p.add_argument("--no-resolve-ct", action="store_true",
                   help="Do not DNS-verify CT results (keep all names)")
    p.add_argument("-o", "--output", help="Save results (.txt, .json or .csv)")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print final subdomains")
    p.add_argument("--no-banner", action="store_true", help="Hide the banner")
    return p.parse_args()


def main():
    args = parse_args()
    domain = args.domain.strip().lower().strip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", domain):
        sys.exit("[-] Invalid domain.")
    if args.no_brute and args.no_ct:
        sys.exit("[-] Nothing to do: both --no-brute and --no-ct were set.")

    if not args.no_banner:
        print(BANNER)
        print(f"  {TITLE}")
        print(f"  {CREDIT}")
        print("  For authorized security testing only.\n")

    nameservers = [s.strip() for s in args.resolvers.split(",")] if args.resolvers else None
    resolver = Resolver(nameservers, args.timeout)
    start = time.time()
    records = {}  # host -> {"ips": set, "sources": set}

    def add(host, ips, source):
        rec = records.setdefault(host, {"ips": set(), "sources": set()})
        rec["ips"].update(ips)
        rec["sources"].add(source)

    # Wildcard detection
    wild_ips = detect_wildcard(resolver, domain)
    if wild_ips:
        log(f"[!] Wildcard DNS detected ({', '.join(sorted(wild_ips))}) - "
            f"filtering matching results", args.quiet)

    # Certificate transparency
    if not args.no_ct:
        log(f"[*] Querying certificate transparency logs (crt.sh) for {domain} ...", args.quiet)
        ct_names = query_crtsh(domain, quiet=args.quiet)
        log(f"[*] crt.sh returned {len(ct_names)} unique names", args.quiet)
        if args.no_resolve_ct:
            for n in ct_names:
                add(n, [], "ct")
        else:
            log("[*] Resolving CT names ...", args.quiet)
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futs = {pool.submit(resolver.resolve, n): n for n in ct_names}
                for fut in as_completed(futs):
                    n = futs[fut]
                    try:
                        ips = fut.result()
                    except Exception:
                        ips = []
                    if ips and not (wild_ips and set(ips).issubset(wild_ips)
                                    and n.count(".") > domain.count(".") + 1):
                        add(n, ips, "ct")
                        log(f"[+] {n:<45} {', '.join(ips)}  (CT)", args.quiet)

    # DNS brute force
    if not args.no_brute:
        try:
            words = load_wordlist(args.wordlist)
        except OSError as exc:
            sys.exit(f"[-] Cannot read wordlist: {exc}")
        log(f"[*] Brute forcing {len(words)} labels with {args.threads} threads ...", args.quiet)
        try:
            found = brute_force(resolver, domain, words, args.threads, wild_ips, args.quiet)
        except KeyboardInterrupt:
            print("\n[!] Interrupted - showing partial results.")
            found = {}
        for host, ips in found.items():
            add(host, ips, "brute")

    # Final report
    final = [
        {"subdomain": h, "ips": sorted(r["ips"]), "sources": sorted(r["sources"])}
        for h, r in sorted(records.items())
    ]

    if args.quiet:
        for r in final:
            print(r["subdomain"])
    else:
        print("\n" + "=" * 78)
        print(f"  RESULTS for {domain}")
        print("=" * 78)
        print(f"  {'SUBDOMAIN':<42}{'IP(S)':<24}SOURCE")
        print("  " + "-" * 74)
        for r in final:
            print(f"  {r['subdomain']:<42}{', '.join(r['ips'])[:22]:<24}{'/'.join(r['sources'])}")
        print("=" * 78)
        print(f"  Total: {len(final)} subdomains | Time: {time.time() - start:.1f}s")
        print(f"  {CREDIT}")

    if args.output:
        save_results(args.output, domain, final)
        log(f"[+] Saved to {args.output}", args.quiet)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(130)
