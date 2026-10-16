#!/usr/bin/env python3
"""
Google Dorking Automation
--------------------------
Automates reconnaissance using Google Dork queries against a target
domain/organization. Runs a curated (and extensible) set of dork
templates, scrapes the resulting search result URLs, de-duplicates
them, and saves a categorized report (JSON + TXT).

Coded by: Mr Sabaz Ali Khan (Cyber Security Engineer)

Legal/Ethical notice:
    Use this tool ONLY against targets you own or are explicitly
    authorized to test. Unauthorized reconnaissance against third
    party assets may be illegal in your jurisdiction. The author
    assumes no liability for misuse.
"""

import argparse
import json
import re
import sys
import time
import random
import urllib.parse
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] Missing dependency 'requests'. Install with: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependency 'beautifulsoup4'. Install with: pip install beautifulsoup4")
    sys.exit(1)


BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⡴⠶⠚⠛⠛⠛⠛⠛⠛⠶⢦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⢤⣤⣶⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⢦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡤⢴⣿⣿⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠛⡿⠈⣻⣥⡻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣷⡟⠁⠈⡿⢮⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠀⠀⠀⢻⣦⡸⣿⣄⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⢹⣽⡶⣿⡛⢷⣄⣠⣀⣹⣿⣷⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠀⠀⡄⠀⠀⠉⢧⡀⢻⡈⠸⢻⣿⢛⣿⣯⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⢀⡄⠀⣸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡀⣀⡽⠀⠀⠀⠀⠹⣆⠙⣾⡀⠻⣿⣿⣿⣯⣤⣤⡄⠀⠀⠀⠀⠀⠀⢾⡀⠀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠟⠋⠁⠀⠀⠀⠀⠀⠹⡆⠀⠉⠓⢮⣿⢻⣯⡍⠛⠷⠀⠀⠀⠀⠀⠀⠈⠙⠻⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡇⢰⣤⣀⠀⠀⠀⠀⠀⠀⢳⡞⠙⡆⠀⠉⠻⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡆⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⢸⢿⣮⣝⡦⣄⡀⠀⠀⠀⠁⠀⣷⣄⣤⣴⣾⣧⠀⠀⠀⠀⢀⣠⢴⣮⣷⡿⡇⣰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                    GOOGLE DORKING AUTOMATION
                 Coded by Mr Sabaz Ali Khan
                   Cyber Security Engineer
"""

DEFAULT_DORKS = {
    "Exposed Files": [
        'site:{target} filetype:pdf',
        'site:{target} filetype:xls OR filetype:xlsx',
        'site:{target} filetype:doc OR filetype:docx',
        'site:{target} filetype:sql',
        'site:{target} filetype:log',
        'site:{target} filetype:env',
        'site:{target} filetype:bak',
        'site:{target} filetype:config OR filetype:conf',
        'site:{target} filetype:xml',
        'site:{target} filetype:json',
    ],
    "Login / Admin Panels": [
        'site:{target} inurl:login',
        'site:{target} inurl:admin',
        'site:{target} intitle:"login" intitle:"admin"',
        'site:{target} inurl:wp-admin',
        'site:{target} inurl:signin',
        'site:{target} inurl:portal',
    ],
    "Exposed Directories": [
        'site:{target} intitle:"index of /"',
        'site:{target} intitle:"index of" "parent directory"',
        'site:{target} inurl:backup',
        'site:{target} inurl:uploads',
    ],
    "Sensitive Parameters / Errors": [
        'site:{target} inurl:"id=" intext:"sql syntax near"',
        'site:{target} intext:"warning" intext:"mysql_fetch"',
        'site:{target} intext:"error" intext:"stack trace"',
        'site:{target} inurl:"debug=true"',
    ],
    "API / Config Exposure": [
        'site:{target} inurl:api intext:"key"',
        'site:{target} intext:"api_key" OR intext:"apikey"',
        'site:{target} filetype:json intext:"password"',
        'site:{target} intext:"aws_access_key_id"',
    ],
    "Credential / Secret Leaks": [
        'site:{target} intext:"password" filetype:txt',
        'site:{target} intext:"BEGIN RSA PRIVATE KEY"',
        'site:{target} intext:"DB_PASSWORD"',
    ],
    "Subdomains / Related Hosts": [
        'site:*.{target} -site:www.{target}',
    ],
    "Cloud Storage": [
        'site:s3.amazonaws.com "{target}"',
        'site:blob.core.windows.net "{target}"',
        'site:storage.googleapis.com "{target}"',
    ],
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

GOOGLE_SEARCH_URL = "https://www.google.com/search"


class GoogleDorkAutomation:
    def __init__(self, target, delay=4.0, results_per_query=10, timeout=10, verbose=True):
        self.target = target
        self.delay = delay
        self.results_per_query = results_per_query
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.findings = {}  # category -> list of {dork, urls}
        self.all_urls = set()

    def log(self, msg):
        if self.verbose:
            print(msg)

    def _headers(self):
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _search(self, query):
        """Run one Google search and return a list of result URLs."""
        params = {"q": query, "num": self.results_per_query}
        try:
            resp = self.session.get(
                GOOGLE_SEARCH_URL,
                params=params,
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            self.log(f"    [!] Request failed: {exc}")
            return []

        if resp.status_code == 429:
            self.log("    [!] Rate-limited by Google (HTTP 429). "
                      "Increase --delay and retry later.")
            return []
        if resp.status_code != 200:
            self.log(f"    [!] Unexpected status code: {resp.status_code}")
            return []

        return self._parse_results(resp.text)

    @staticmethod
    def _parse_results(html):
        soup = BeautifulSoup(html, "html.parser")
        urls = []
        for a in soup.select('a[href]'):
            href = a['href']
            match = re.search(r'/url\?q=(https?://[^&]+)&', href)
            if match:
                url = urllib.parse.unquote(match.group(1))
                urls.append(url)
            elif href.startswith("http") and "google.com" not in href:
                urls.append(href)
        # De-dupe while preserving order
        seen = set()
        deduped = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

    def run(self, dorks=None, categories=None):
        dork_set = dorks or DEFAULT_DORKS
        if categories:
            dork_set = {k: v for k, v in dork_set.items() if k in categories}

        self.log(f"[*] Target: {self.target}")
        self.log(f"[*] Categories: {', '.join(dork_set.keys())}")
        self.log(f"[*] Delay between queries: {self.delay}s\n")

        for category, templates in dork_set.items():
            self.log(f"[+] Category: {category}")
            self.findings[category] = []
            for template in templates:
                query = template.format(target=self.target)
                self.log(f"  -> Query: {query}")
                urls = self._search(query)
                if urls:
                    self.log(f"     Found {len(urls)} result(s)")
                    for u in urls:
                        self.all_urls.add(u)
                else:
                    self.log("     No results / blocked")
                self.findings[category].append({"dork": query, "results": urls})
                time.sleep(self.delay + random.uniform(0, 1.5))
            self.log("")

        return self.findings

    def save_report(self, out_dir="."):
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', self.target)

        json_file = out_path / f"dork_report_{safe_target}_{timestamp}.json"
        txt_file = out_path / f"dork_report_{safe_target}_{timestamp}.txt"

        report = {
            "target": self.target,
            "generated_at": datetime.now().isoformat(),
            "tool": "Google Dorking Automation",
            "author": "Mr Sabaz Ali Khan (Cyber Security Engineer)",
            "total_unique_urls": len(self.all_urls),
            "categories": self.findings,
        }

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(f"Google Dorking Report - {self.target}\n")
            f.write(f"Generated: {report['generated_at']}\n")
            f.write("Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)\n")
            f.write("=" * 60 + "\n\n")
            for category, items in self.findings.items():
                f.write(f"## {category}\n")
                for item in items:
                    f.write(f"  Dork: {item['dork']}\n")
                    if item["results"]:
                        for u in item["results"]:
                            f.write(f"    - {u}\n")
                    else:
                        f.write("    (no results)\n")
                f.write("\n")
            f.write(f"\nTotal unique URLs found: {len(self.all_urls)}\n")

        return json_file, txt_file


def main():
    parser = argparse.ArgumentParser(
        description="Google Dorking Automation - coded by Mr Sabaz Ali Khan (Cyber Security Engineer)"
    )
    parser.add_argument("target", help="Target domain, e.g. example.com")
    parser.add_argument("-d", "--delay", type=float, default=4.0,
                         help="Delay in seconds between queries (default: 4.0)")
    parser.add_argument("-n", "--num-results", type=int, default=10,
                         help="Results requested per query (default: 10)")
    parser.add_argument("-c", "--categories", nargs="*",
                         help="Only run specific categories (space separated, quoted)")
    parser.add_argument("-o", "--output-dir", default="dork_reports",
                         help="Directory to save reports (default: dork_reports)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner/verbose logs")
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    engine = GoogleDorkAutomation(
        target=args.target,
        delay=args.delay,
        results_per_query=args.num_results,
        verbose=not args.quiet,
    )
    engine.run(categories=args.categories)
    json_file, txt_file = engine.save_report(args.output_dir)

    print(f"\n[+] Scan complete. {len(engine.all_urls)} unique URLs discovered.")
    print(f"[+] JSON report: {json_file}")
    print(f"[+] TXT report:  {txt_file}")
    print("\nCoded by Mr Sabaz Ali Khan | Cyber Security Engineer")


if __name__ == "__main__":
    main()
