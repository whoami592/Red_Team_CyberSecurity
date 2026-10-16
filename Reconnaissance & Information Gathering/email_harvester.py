#!/usr/bin/env python3
"""
Email Harvester - OSINT Email Reconnaissance Tool
coded by Mr Sabaz Ali Khan

Legitimate use only: authorized penetration testing, security research,
and reconnaissance of your own domains/assets. Do not use against targets
you do not have explicit permission to assess.
"""

import re
import sys
import argparse
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣠⣀⠀⠀
⢠⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢍⣹⡀
⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣯⢩⠃
⠸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣔⣿⣿⣆⠀⠀⢀⢼⣿⡟⠀
⠀⢹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⢷⢛⣿⣴⠒⢫⣿⠟⠀⠀
⠀⠀⢻⣆⠀⠀⠀⠀⠀⠀⠀⣀⣠⣶⢿⣋⡸⠃⠀⣿⠏⠀⠀⠀
⠀⠀⠀⢻⣆⠀⠀⣀⢤⣶⣝⣡⣶⣿⣍⣉⣀⡀⣰⡇⠀⠀⠀⠀
⠀⠀⠀⠐⢿⣧⡸⠷⠾⠋⠉⠀⠀⠀⢻⣯⣁⢀⣾⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠛⠂⠀⠀⠀⠀⢀⣀⣤⣾⣿⣿⣿⣿⣶⠋⢁⡆⠀
⠀⠀⠀⠀⠀⣀⣀⣠⣤⣔⣊⣁⣠⣞⣿⣿⣿⣿⢿⣿⡿⢹⠇⠀
⠀⣠⣤⣊⣉⣀⣀⣽⡿⠿⠿⠿⡛⡼⠇⠀⠈⠀⣾⠟⢁⡎⠀⠀
⡔⣋⠿⠛⠿⠛⠉⠁⠀⠀⠀⠀⠈⠁⠀⠀⠀⢘⠿⠞⢟⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠉⠀⠀

        EMAIL HARVESTER - OSINT Recon Tool
        coded by Mr Sabaz Ali Khan
"""

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


class LinkParser(HTMLParser):
    """Collects same-domain <a href> links for shallow crawling."""

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                full = urljoin(self.base_url, value)
                if urlparse(full).netloc == urlparse(self.base_url).netloc:
                    self.links.add(full.split("#")[0])


def fetch(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "text" not in content_type:
                return None
            raw = resp.read(2_000_000)  # cap read size
            return raw.decode(errors="ignore")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None


def extract_emails(html_text):
    return set(EMAIL_REGEX.findall(html_text))


def harvest(start_url, depth=1, max_pages=25, verbose=True):
    """Shallow same-domain crawl collecting emails from each page."""
    visited = set()
    to_visit = [(start_url, 0)]
    found = set()

    while to_visit and len(visited) < max_pages:
        url, level = to_visit.pop(0)
        if url in visited or level > depth:
            continue
        visited.add(url)

        if verbose:
            print(f"[*] Crawling: {url}")

        html_text = fetch(url)
        if not html_text:
            continue

        new_emails = extract_emails(html_text)
        if new_emails - found and verbose:
            for e in sorted(new_emails - found):
                print(f"    [+] Found: {e}")
        found |= new_emails

        if level < depth:
            parser = LinkParser(url)
            try:
                parser.feed(html_text)
            except Exception:
                continue
            for link in parser.links:
                if link not in visited:
                    to_visit.append((link, level + 1))

    return found, visited


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Email Harvester - OSINT reconnaissance tool. "
        "Use only on domains/assets you are authorized to assess."
    )
    parser.add_argument("url", help="Target URL to start harvesting from (e.g. https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("-m", "--max-pages", type=int, default=25, help="Max pages to crawl (default: 25)")
    parser.add_argument("-o", "--output", help="Save results to a text file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress per-page progress output")

    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    print(f"[*] Target: {args.url}")
    print(f"[*] Depth: {args.depth} | Max pages: {args.max_pages}\n")

    emails, visited = harvest(
        args.url, depth=args.depth, max_pages=args.max_pages, verbose=not args.quiet
    )

    print(f"\n[*] Pages crawled: {len(visited)}")
    print(f"[*] Unique emails found: {len(emails)}\n")

    for email in sorted(emails):
        print(email)

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Email Harvester results for {args.url}\n")
            f.write("coded by Mr Sabaz Ali Khan\n\n")
            for email in sorted(emails):
                f.write(email + "\n")
        print(f"\n[*] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
