import os
import requests
import urllib.parse
import ipaddress
import time
import traceback
import csv
from io import StringIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ABUSECH_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
GEO_API = "http://ip-api.com/json/"
LOOT_DIR = "loot"
HEADERS = {"User-Agent": "Mozilla/5.0"}
MAX_WORKERS = 10

def log(msg):
    print(f"[LOG] {msg}")

def error(msg):
    print(f"[ERROR] {msg}")

def is_opendir(response_text, server_header):
    if "Index of /" in response_text:
        return True
    if "Directory listing for" in response_text:
        return True
    if "To Parent Directory" in response_text:
        return True
    if "nginx" in server_header.lower() and "<title>Index of" in response_text:
        return True
    return False

def strip_file_from_url(url):
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    if "." in os.path.basename(path):
        path = os.path.dirname(path)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path + "/", '', '', ''))

def download_files(base_url, loot_subdir):
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=10, verify=False)
        r.raise_for_status()
    except Exception as e:
        error(f"Fetch failed: {base_url} ({e.__class__.__name__})")
        return

    links = []
    for line in r.text.splitlines():
        if "<a href=" in line:
            parts = line.split('<a href="')[1:]
            for part in parts:
                href = part.split('"')[0]
                if href not in ("../", "./") and not href.startswith("?"):
                    links.append(href)

    for href in links:
        file_url = urllib.parse.urljoin(base_url, href)
        try:
            file_response = requests.get(file_url, headers=HEADERS, timeout=10, verify=False, stream=True)
            file_response.raise_for_status()
            filename = os.path.basename(urllib.parse.urlparse(file_url).path)
            if not filename:
                continue
            os.makedirs(loot_subdir, exist_ok=True)
            filepath = os.path.join(loot_subdir, filename)
            with open(filepath, "wb") as f:
                for chunk in file_response.iter_content(chunk_size=8192):
                    f.write(chunk)
        except Exception as e:
            error(f"Download failed: {file_url} ({e.__class__.__name__})")
            continue

def get_geolocation(ip):
    try:
        r = requests.get(GEO_API + ip, headers=HEADERS, timeout=5)
        data = r.json()
        if data.get("status") == "success":
            return f"{data['country']} ({data['query']})"
    except Exception as e:
        error(f"Geo lookup error: {ip} ({e.__class__.__name__})")
    return "Unknown"

def extract_hostname(url):
    return urllib.parse.urlparse(url).netloc.split(":")[0]

def is_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def get_c2_urls():
    urls = set()
    try:
        log("Fetching C2 URL list from abuse.ch")
        r = requests.get(ABUSECH_URL, headers=HEADERS, timeout=10)
        r.raise_for_status()
        content = r.text

        csv_reader = csv.reader(StringIO(content))
        for row in csv_reader:
            if len(row) < 3 or row[0].startswith("#"):
                continue
            url = row[2].strip()
            if url.startswith("http"):
                stripped = strip_file_from_url(url)
                urls.add(stripped)
    except Exception as e:
        error(f"Failed to fetch abuse.ch feed ({e.__class__.__name__})")
    log(f"Total unique C2 base URLs: {len(urls)}")
    return list(urls)

def probe_url(url):
    hostname = extract_hostname(url)

    if is_ip(hostname):
        ip_addr = hostname
    else:
        try:
            ip = requests.get(f"https://dns.google/resolve?name={hostname}", timeout=5).json()
            ip_addr = ip.get("Answer", [{}])[0].get("data", "")
            if not ip_addr:
                error(f"DNS resolution failed: {hostname}")
                return
        except Exception as e:
            error(f"DNS resolution error: {hostname} ({e.__class__.__name__})")
            return

    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        server_header = r.headers.get("Server", "")
        if is_opendir(r.text, server_header):
            geo = get_geolocation(ip_addr)
            print(f"[OpenDir] {url} - {geo} - Server: {server_header}")
            loot_path = os.path.join(LOOT_DIR, ip_addr)
            download_files(url, loot_path)
    except Exception as e:
        error(f"Probe failed: {url} ({e.__class__.__name__})")

def main():
    c2_urls = get_c2_urls()
    visited = set()
    targets = []

    for url in c2_urls:
        hostname = extract_hostname(url)
        if hostname in visited:
            continue
        visited.add(hostname)
        targets.append(url)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(probe_url, url) for url in targets]
        for _ in as_completed(futures):
            pass

if __name__ == "__main__":
    main()

