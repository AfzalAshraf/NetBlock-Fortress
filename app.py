#!/usr/bin/env python3
"""
NetBlock Fortress v19.0
Network-wide DNS filtering & threat intelligence dashboard.

DNS filtering is domain-level: this service intentionally does not claim to
remove URL-path, cosmetic, or same-host video ads that DNS cannot distinguish.
"""

import hashlib
import hmac
import ipaddress
import json
import math
import os
import queue
import secrets
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSQuestion, DNSRecord
from flask import Flask, jsonify, redirect, render_template_string, request, session

from adblock_rules import (
    find_matching_rule,
    normalize_domain,
    normalize_query_name,
    parse_blocklist_text,
)

# ──────────────────────────────────────────────
#  Paths
# ──────────────────────────────────────────────
BASE_DIR = Path(os.environ.get("NETBLOCK_HOME", "/opt/netblock"))
DATA_DIR = BASE_DIR / "data"
LIST_DIR = DATA_DIR / "lists"
CONFIG_FILE = DATA_DIR / "config.json"
STATUS_FILE = DATA_DIR / "list_status.json"
QUERY_LOG_FILE = DATA_DIR / "queries.jsonl"
CUSTOM_BLOCK = DATA_DIR / "custom_blocked.txt"
CUSTOM_WHITE = DATA_DIR / "custom_whitelist.txt"

os.umask(0o077)
for d in [DATA_DIR, LIST_DIR]:
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass

# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    "admin_username": "admin",
    "password_hash": hashlib.sha256(b"admin123").hexdigest(),
    "flask_secret_key": "",
    "config_version": 2,
    "block_mode": "aggressive_ads",
    "dns_upstream": "1.1.1.1",
    "dns_port": 53,
    "web_port": 8080,
    "auto_refresh": True,
    "refresh_hours": 24,
    "cname_uncloaking": True,
    "rebinding_protection": True,
    "dga_protection": True,
    "rate_limiting": True,
    "rate_limit_rps": 100,
    "amplification_protection": True,
    "query_logging": True,
    "enabled_lists": [
        "stevenblack", "adguard", "oisd", "hagezi_pro_plus", "easylist", "peterlowe",
        "adaway", "1hosts", "firebog_ticked",
        "easypriv", "prigent_ads", "winspy", "smarttv", "ubpriv", "adguard_track", "notrack",
        "urlhaus", "rpi_mal", "phisharmy", "prigent_mal", "dshield",
        "sb_phish", "hagezi_threat", "phishdb", "rpi_phish",
        "nocoin", "coinblocker", "hagezi_dyndns", "hagezi_hoster", "hagezi_spam_tlds"
    ]
}

CFG = dict(DEFAULT_CONFIG)
CONFIG_LOCK = threading.RLock()
CONFIG_WAS_PRESENT = CONFIG_FILE.exists()

def load_config():
    global CFG
    if CONFIG_FILE.exists():
        try:
            saved = json.loads(CONFIG_FILE.read_text())
            CFG.update(saved)
        except Exception:
            pass

def save_config():
    try:
        with CONFIG_LOCK:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            tmp = CONFIG_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(CFG, indent=2))
            os.replace(str(tmp), str(CONFIG_FILE))
    except OSError as exc:
        print(f"[!] Config save error: {exc}")

load_config()
if not CFG.get("flask_secret_key"):
    CFG["flask_secret_key"] = secrets.token_hex(32)
    save_config()

# CLI: change credentials from terminal
if len(sys.argv) >= 4 and sys.argv[1] == "--set-auth":
    CFG["admin_username"] = sys.argv[2].strip()
    CFG["password_hash"] = hashlib.sha256(sys.argv[3].encode()).hexdigest()
    save_config()
    print(f"[+] Credentials updated. User='{sys.argv[2]}'")
    sys.exit(0)

# ──────────────────────────────────────────────
#  Blocklist Registry (domain-capable feeds only)
# ──────────────────────────────────────────────
ALL_LISTS = {
    # ── Advertisements ──
    "stevenblack":     {"name": "StevenBlack Unified",    "cat": "ads",      "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
    "adguard":         {"name": "AdGuard DNS Filter",     "cat": "ads",      "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
    "oisd":            {"name": "OISD Big",               "cat": "ads",      "url": "https://big.oisd.nl/domainswild"},
    "hagezi_pro":      {"name": "HaGeZi Multi Pro",       "cat": "ads",      "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"},
    "hagezi_pro_plus": {"name": "HaGeZi Multi Pro++",     "cat": "ads",      "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt"},
    "hagezi_ulti":     {"name": "HaGeZi Multi Ultimate",  "cat": "ads",      "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt"},
    "easylist":        {"name": "EasyList DNS Mirror",    "cat": "ads",      "url": "https://v.firebog.net/hosts/Easylist.txt"},
    "peterlowe":       {"name": "Peter Lowe Ad Server",   "cat": "ads",      "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
    "adaway":          {"name": "AdAway Mobile Ads",      "cat": "ads",      "url": "https://adaway.org/hosts.txt"},
    "1hosts":          {"name": "1Hosts Lite",            "cat": "ads",      "url": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt"},
    "firebog_ticked":  {"name": "Firebog Ticked Ads",     "cat": "ads",      "url": "https://v.firebog.net/hosts/AdguardDNS.txt"},

    # ── Trackers ──
    "easypriv":        {"name": "EasyPrivacy",            "cat": "trackers", "url": "https://v.firebog.net/hosts/Easyprivacy.txt"},
    "prigent_ads":     {"name": "Prigent Ads & Trackers", "cat": "trackers", "url": "https://v.firebog.net/hosts/Prigent-Ads.txt"},
    "winspy":          {"name": "Windows Spy Blocker",    "cat": "trackers", "url": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"},
    "smarttv":         {"name": "SmartTV Tracking",       "cat": "trackers", "url": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt"},
    "ubpriv":          {"name": "uBlock Privacy Filters", "cat": "trackers", "url": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt"},
    "adguard_track":   {"name": "AdGuard Tracking Prot.", "cat": "trackers", "url": "https://v.firebog.net/hosts/AdguardDNS.txt"},
    "notrack":         {"name": "NoTrack Tracker List",   "cat": "trackers", "url": "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-blocklist.txt"},

    # ── Malware ──
    "urlhaus":         {"name": "URLhaus Malware Feed",   "cat": "malware",  "url": "https://urlhaus.abuse.ch/downloads/hostfile/"},
    "rpi_mal":         {"name": "RPiList Malware",        "cat": "malware",  "url": "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware"},
    "phisharmy":       {"name": "Phishing Army Ext.",     "cat": "malware",  "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt"},
    "prigent_mal":     {"name": "Prigent Malware",        "cat": "malware",  "url": "https://v.firebog.net/hosts/Prigent-Malware.txt"},
    "dshield":         {"name": "DShield Suspicious Domains", "cat": "malware", "url": "https://www.dshield.org/feeds/suspiciousdomains_High.txt"},

    # ── Phishing ──
    "sb_phish":        {"name": "StevenBlack Fake/Phish", "cat": "phishing", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts"},
    "hagezi_threat":   {"name": "HaGeZi Threat Intelligence", "cat": "phishing", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt"},
    "phishdb":         {"name": "Phishing Database Active","cat": "phishing", "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"},
    "rpi_phish":       {"name": "RPiList Phishing",       "cat": "phishing", "url": "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe"},

    # ── Spam ──
    "hagezi_spam_tlds": {"name": "HaGeZi Spam TLD Domains", "cat": "spam", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds-adblock.txt"},

    # ── Social ──
    "fb_track":        {"name": "Facebook Tracking Pixels","cat": "social",   "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts"},

    # ── Adult ──
    "sb_porn":         {"name": "StevenBlack Adult",      "cat": "adult",    "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts"},
    "sin_porn":        {"name": "Sinfonietta Adult NSFW", "cat": "adult",    "url": "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts"},
    "oisd_nsfw":       {"name": "OISD NSFW Filter",       "cat": "adult",    "url": "https://nsfw.oisd.nl/domainswild"},

    # ── Gambling ──
    "sb_gamble":       {"name": "StevenBlack Gambling",   "cat": "gambling", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts"},
    "sin_gamble":      {"name": "Sinfonietta Gambling",   "cat": "gambling", "url": "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts"},

    # ── Crypto ──
    "nocoin":          {"name": "NoCoin Cryptomining",    "cat": "crypto",   "url": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"},
    "coinblocker":     {"name": "CoinBlocker Crypto List","cat": "crypto",   "url": "https://zerodot1.gitlab.io/CoinBlockerLists/hosts"},

    # ── Security ──
    "hagezi_dyndns":   {"name": "HaGeZi DynDNS Abuse",   "cat": "security", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/dyndns.txt"},
    "hagezi_hoster":   {"name": "HaGeZi Free Host Abuse", "cat": "security", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt"}
}

ADVERTISING_FEEDS = [
    "stevenblack", "adguard", "oisd", "hagezi_pro_plus", "easylist",
    "peterlowe", "adaway", "1hosts", "firebog_ticked",
]
TRACKER_FEEDS = ["easypriv", "prigent_ads", "winspy", "smarttv", "ubpriv", "adguard_track", "notrack"]
THREAT_FEEDS = [
    "urlhaus", "rpi_mal", "phisharmy", "prigent_mal", "dshield",
    "sb_phish", "hagezi_threat", "phishdb", "rpi_phish",
]
SECURITY_FEEDS = ["hagezi_dyndns", "hagezi_hoster", "hagezi_spam_tlds", "nocoin", "coinblocker"]
PROFILE_LISTS = {
    "balanced": ["stevenblack", "adguard", "hagezi_pro", "peterlowe", "urlhaus", "phisharmy", "sb_phish"],
    "strict": [
        "stevenblack", "adguard", "oisd", "hagezi_pro", "easylist", "peterlowe", "adaway", "1hosts",
        "firebog_ticked", *TRACKER_FEEDS, *THREAT_FEEDS, *SECURITY_FEEDS,
    ],
    "aggressive_ads": [
        *ADVERTISING_FEEDS, *TRACKER_FEEDS, *THREAT_FEEDS, *SECURITY_FEEDS,
    ],
    "family": [
        "stevenblack", "adguard", "oisd", "hagezi_pro", "easylist", "peterlowe", "adaway",
        "1hosts", "firebog_ticked", *TRACKER_FEEDS, *THREAT_FEEDS, *SECURITY_FEEDS,
        "sb_porn", "sin_porn", "oisd_nsfw", "sb_gamble", "sin_gamble",
    ],
}

# Keep saved configurations compatible as feeds are added or retired.
if not CONFIG_WAS_PRESENT:
    CFG["enabled_lists"] = list(PROFILE_LISTS["aggressive_ads"])
CFG["enabled_lists"] = [lid for lid in CFG.get("enabled_lists", []) if lid in ALL_LISTS]
if not CFG["enabled_lists"]:
    CFG["enabled_lists"] = list(PROFILE_LISTS.get(CFG.get("block_mode"), PROFILE_LISTS["aggressive_ads"]))
if CFG.get("block_mode") not in PROFILE_LISTS:
    CFG["block_mode"] = "aggressive_ads"
CFG["enabled_lists"] = list(dict.fromkeys(CFG["enabled_lists"]))
save_config()

CAT = {
    "ads":      {"name": "Advertisements",   "color": "#fb542b", "icon": "fa-bullhorn"},
    "trackers": {"name": "Trackers & Spy",   "color": "#8b5cf6", "icon": "fa-user-secret"},
    "malware":  {"name": "Malware & C2",     "color": "#ef4444", "icon": "fa-skull-crossbones"},
    "phishing": {"name": "Phishing & Fraud", "color": "#f59e0b", "icon": "fa-fish"},
    "spam":     {"name": "Spam & Botnets",   "color": "#ec4899", "icon": "fa-envelope-open-text"},
    "social":   {"name": "Social Trackers",  "color": "#06b6d4", "icon": "fa-share-nodes"},
    "adult":    {"name": "Adult & NSFW",     "color": "#f43f5e", "icon": "fa-ban"},
    "gambling": {"name": "Gambling & Casino","color": "#14b8a6", "icon": "fa-dice"},
    "crypto":   {"name": "Cryptojacking",    "color": "#eab308", "icon": "fa-coins"},
    "security": {"name": "Threat Feeds",     "color": "#3b82f6", "icon": "fa-shield-halved"}
}

# ──────────────────────────────────────────────
#  Runtime State
# ──────────────────────────────────────────────
BLOCKED_DOMAINS = set()
CUSTOM_BLOCKED = set()
CUSTOM_WHITELIST = set()
DOMAIN_CATEGORIES = {}
DOMAIN_SOURCES = {}

# Small hard-coded safety net for frequently abused ad endpoints. Googlevideo
# is intentionally absent: its hosts serve both ads and the actual video stream.
STATIC_AD_RULES = {
    "ad.doubleclick.net", "securepubads.g.doubleclick.net",
    "pubads.g.doubleclick.net", "pagead2.googlesyndication.com",
    "googleadservices.com", "adservice.google.com",
}
PROTECTED_MEDIA_DOMAINS = {"googlevideo.com"}

TOTAL_QUERIES = 0
BLOCKED_QUERIES = 0
STATS_LOCK = threading.Lock()
START_TIME = time.time()
QUERY_LOGS = deque(maxlen=300)
QUERY_LOG_LOCK = threading.RLock()
QUERY_LOG_MAX_BYTES = 5 * 1024 * 1024
QUERY_LOG_BACKUPS = 3
MAX_TRACKED_CLIENTS = 4096
CLIENT_ACTIVITY = OrderedDict()
CLIENT_ACTIVITY_LOCK = threading.RLock()
CLIENT_RATES = OrderedDict()
RATE_LIMIT_LOCK = threading.Lock()
SECURITY_EVENTS = deque(maxlen=200)
SECURITY_EVENTS_LOCK = threading.RLock()


def update_stats(total=0, blocked=0):
    global TOTAL_QUERIES, BLOCKED_QUERIES
    with STATS_LOCK:
        TOTAL_QUERIES += total
        BLOCKED_QUERIES += blocked


def update_client_activity(client_ip, total=0, blocked=0, threats=0, last_seen=None):
    with CLIENT_ACTIVITY_LOCK:
        activity = CLIENT_ACTIVITY.get(client_ip)
        if activity is None:
            if len(CLIENT_ACTIVITY) >= MAX_TRACKED_CLIENTS:
                CLIENT_ACTIVITY.popitem(last=False)
            activity = {"total": 0, "blocked": 0, "last_seen": 0, "threats": 0}
            CLIENT_ACTIVITY[client_ip] = activity
        else:
            CLIENT_ACTIVITY.move_to_end(client_ip)
        activity["total"] += total
        activity["blocked"] += blocked
        activity["threats"] += threats
        if last_seen is not None:
            activity["last_seen"] = last_seen


def client_activity_snapshot():
    with CLIENT_ACTIVITY_LOCK:
        return {ip: dict(activity) for ip, activity in CLIENT_ACTIVITY.items()}


def _load_query_logs():
    paths = [Path(str(QUERY_LOG_FILE) + f".{index}") for index in range(QUERY_LOG_BACKUPS, 0, -1)]
    paths.append(QUERY_LOG_FILE)
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        entry = json.loads(line)
                        if isinstance(entry, dict) and "domain" in entry:
                            QUERY_LOGS.appendleft(entry)
                    except (ValueError, TypeError):
                        continue
        except OSError:
            continue


def record_query(entry):
    entry = dict(entry)
    entry.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
    with QUERY_LOG_LOCK:
        QUERY_LOGS.appendleft(entry)
        if not CFG.get("query_logging", True):
            return
        try:
            if QUERY_LOG_FILE.exists() and QUERY_LOG_FILE.stat().st_size >= QUERY_LOG_MAX_BYTES:
                for index in range(QUERY_LOG_BACKUPS, 0, -1):
                    source = QUERY_LOG_FILE if index == 1 else Path(str(QUERY_LOG_FILE) + f".{index - 1}")
                    target = Path(str(QUERY_LOG_FILE) + f".{index}")
                    if target.exists():
                        target.unlink()
                    if source.exists():
                        os.replace(str(source), str(target))
            with QUERY_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
        except OSError as exc:
            print(f"[!] Query log write error: {exc}")


def query_log_snapshot(limit=300):
    with QUERY_LOG_LOCK:
        entries = list(QUERY_LOGS)
    return entries[:limit] if limit is not None else entries


def clear_query_logs():
    with QUERY_LOG_LOCK:
        QUERY_LOGS.clear()
        for path in [QUERY_LOG_FILE] + [Path(str(QUERY_LOG_FILE) + f".{i}") for i in range(1, QUERY_LOG_BACKUPS + 1)]:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                print(f"[!] Query log clear error: {exc}")


def record_security_event(event_type, client_ip, detail):
    event = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": event_type,
        "client": client_ip,
        "detail": str(detail)[:240],
    }
    with SECURITY_EVENTS_LOCK:
        SECURITY_EVENTS.appendleft(event)


_load_query_logs()

# ──────────────────────────────────────────────
#  List Status Persistence
# ──────────────────────────────────────────────
LIST_STATUS = {}
for lid, info in ALL_LISTS.items():
    LIST_STATUS[lid] = {
        "name": info["name"],
        "cat": info["cat"],
        "enabled": lid in CFG["enabled_lists"],
        "state": "idle",
        "count": 0,
        "last_updated": "Never",
        "error": None
    }

def save_list_status():
    try:
        with LIST_STATUS_LOCK:
            payload = json.dumps(LIST_STATUS, indent=2)
            tmp_path = STATUS_FILE.with_suffix(".tmp")
            tmp_path.write_text(payload)
            os.replace(str(tmp_path), str(STATUS_FILE))
    except OSError as exc:
        print(f"[!] List status save error: {exc}")

def list_status_snapshot():
    with LIST_STATUS_LOCK:
        return {lid: dict(status) for lid, status in LIST_STATUS.items()}


def load_list_status():
    global LIST_STATUS
    if STATUS_FILE.exists():
        try:
            saved = json.loads(STATUS_FILE.read_text())
            for k, v in saved.items():
                if k in LIST_STATUS:
                    LIST_STATUS[k].update(v)
        except Exception:
            pass

load_list_status()
for _lid in ALL_LISTS:
    LIST_STATUS[_lid]["enabled"] = _lid in CFG.get("enabled_lists", [])

# ──────────────────────────────────────────────
#  Detection Helpers
# ──────────────────────────────────────────────
def is_dga(domain):
    try:
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        sld = parts[-2]
        if len(sld) < 12:
            return False
        counts = {}
        for c in sld:
            counts[c] = counts.get(c, 0) + 1
        entropy = -sum(
            (cnt / len(sld)) * math.log2(cnt / len(sld))
            for cnt in counts.values()
        )
        return entropy > 3.8
    except Exception:
        return False

def is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except Exception:
        return False

# ──────────────────────────────────────────────
#  Blocklist Parsing & Safe Feed Updates
# ──────────────────────────────────────────────
MAX_LIST_BYTES = 32 * 1024 * 1024
MAX_LIST_RULES = 2_000_000
LIST_STATUS_LOCK = threading.RLock()
LIST_DOWNLOAD_LOCKS = {lid: threading.Lock() for lid in ALL_LISTS}

def parse_blocklist_file(file_path):
    try:
        return parse_blocklist_text(Path(file_path).read_bytes())
    except (OSError, ValueError):
        return set()

def _set_list_status(lid, **updates):
    with LIST_STATUS_LOCK:
        LIST_STATUS[lid].update(updates)
    save_list_status()

def download_and_parse_list(lid):
    """Fetch a feed, validate it, then atomically replace its last-known-good copy."""
    if lid not in ALL_LISTS:
        return 0
    with LIST_DOWNLOAD_LOCKS[lid]:
        info = ALL_LISTS[lid]
        out_path = LIST_DIR / f"{lid}.txt"
        _set_list_status(lid, state="downloading", error=None)
        try:
            import requests
            headers = {"User-Agent": "NetBlock-Fortress/19.0 (+DNS blocklist updater)"}
            chunks = []
            total_bytes = 0
            with requests.get(info["url"], headers=headers, timeout=(8, 30), stream=True) as res:
                res.raise_for_status()
                content_length = res.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_LIST_BYTES:
                    raise ValueError("Feed exceeds 32 MiB safety limit")
                for chunk in res.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_LIST_BYTES:
                        raise ValueError("Feed exceeds 32 MiB safety limit")
                    chunks.append(chunk)
            body = b"".join(chunks)
            domains = parse_blocklist_text(body)
            if not domains:
                raise ValueError("No supported DNS domain rules found; cached feed kept")
            if len(domains) > MAX_LIST_RULES:
                raise ValueError("Feed exceeds 2 million domain rules")

            tmp_path = out_path.with_suffix(".tmp")
            tmp_path.write_bytes(body)
            os.replace(str(tmp_path), str(out_path))
            _set_list_status(
                lid,
                state="active",
                count=len(domains),
                last_updated=datetime.now().strftime("%Y-%m-%d %H:%M"),
                error=None,
            )
            return len(domains)
        except Exception as exc:
            cached_count = len(parse_blocklist_file(out_path)) if out_path.exists() else 0
            message = str(exc).replace("\\n", " ")[:100] or exc.__class__.__name__
            _set_list_status(
                lid,
                state="stale" if cached_count else "error",
                count=cached_count,
                error=message,
            )
            return 0

def download_list_and_rebuild(lid):
    download_and_parse_list(lid)
    rebuild_master_blocklist()

def rebuild_master_blocklist():
    global BLOCKED_DOMAINS, DOMAIN_CATEGORIES, DOMAIN_SOURCES
    new_set = set()
    new_cats = {}
    new_sources = {}

    for lid, info in ALL_LISTS.items():
        if lid not in CFG.get("enabled_lists", []):
            continue
        fpath = LIST_DIR / f"{lid}.txt"
        if not fpath.exists():
            continue
        for domain in parse_blocklist_file(fpath):
            new_set.add(domain)
            if domain not in new_cats:
                new_cats[domain] = info["cat"]
                new_sources[domain] = lid

    # Narrow, known ad endpoints are a fallback if list downloads are offline.
    for domain in STATIC_AD_RULES:
        new_set.add(domain)
        new_cats.setdefault(domain, "ads")
        new_sources.setdefault(domain, "built-in")

    load_custom_lists()
    for domain in CUSTOM_BLOCKED:
        new_set.add(domain)
        new_cats[domain] = "custom"
        new_sources[domain] = "custom"

    BLOCKED_DOMAINS = new_set
    DOMAIN_CATEGORIES = new_cats
    DOMAIN_SOURCES = new_sources

def _read_domain_rules(path):
    if not path.exists():
        return set()
    rules = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rule = normalize_domain(line, allow_local=True)
            if rule:
                rules.add(rule)
    except OSError:
        pass
    return rules

def load_custom_lists():
    global CUSTOM_BLOCKED, CUSTOM_WHITELIST
    CUSTOM_BLOCKED = _read_domain_rules(CUSTOM_BLOCK)
    CUSTOM_WHITELIST = _read_domain_rules(CUSTOM_WHITE)

load_custom_lists()
rebuild_master_blocklist()

# ──────────────────────────────────────────────
#  Threat Auditing
# ──────────────────────────────────────────────
def audit_threat(domain):
    """Return verdict, category, color, matched rule, and its source."""
    query = normalize_query_name(domain)
    if not query:
        return "allowed", "clean", "#10b981", "", ""

    whitelist_rule = find_matching_rule(query, CUSTOM_WHITELIST)
    if whitelist_rule:
        return "whitelisted", "custom", "#10b981", whitelist_rule, "custom whitelist"

    custom_rule = find_matching_rule(query, CUSTOM_BLOCKED)
    if custom_rule:
        return "blocked", "custom", "#fb542b", custom_rule, "custom rule"

    protected_rule = find_matching_rule(query, PROTECTED_MEDIA_DOMAINS)
    if protected_rule:
        return "allowed", "clean", "#10b981", protected_rule, "protected media guard"

    matched_rule = find_matching_rule(query, DOMAIN_CATEGORIES)
    if matched_rule:
        category = DOMAIN_CATEGORIES[matched_rule]
        source_id = DOMAIN_SOURCES.get(matched_rule, "blocklist")
        source = ALL_LISTS.get(source_id, {}).get("name", source_id)
        return "blocked", category, CAT.get(category, {}).get("color", "#fb542b"), matched_rule, source

    return "allowed", "clean", "#10b981", "", ""

# ──────────────────────────────────────────────
#  DNS Server
# ──────────────────────────────────────────────
DNS_UDP_WORKERS = 32
DNS_UDP_QUEUE_SIZE = 128
DNS_TCP_WORKERS = 16
DNS_TCP_QUEUE_SIZE = 64


def _recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _upstream_sockaddr(upstream, port):
    address = ipaddress.ip_address(upstream)
    if address.version == 6:
        return socket.AF_INET6, (str(address), port, 0, 0)
    return socket.AF_INET, (str(address), port)


def _resolve_upstream_tcp(family, sockaddr, request_data, timeout=3.0):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as upstream_sock:
            upstream_sock.settimeout(timeout)
            upstream_sock.connect(sockaddr)
            upstream_sock.sendall(struct.pack("!H", len(request_data)) + request_data)
            length_bytes = _recv_exact(upstream_sock, 2)
            if not length_bytes:
                return None
            response_length = struct.unpack("!H", length_bytes)[0]
            response_data = _recv_exact(upstream_sock, response_length)
            return DNSRecord.parse(response_data) if response_data else None
    except Exception:
        return None


def resolve_upstream(qname, qtype=QTYPE.A, qclass=1):
    try:
        upstream = CFG.get("dns_upstream", "1.1.1.1")
        port = int(CFG.get("dns_upstream_port", 53))
        family, sockaddr = _upstream_sockaddr(upstream, port)
        req = DNSRecord(q=DNSQuestion(qname, qtype, qclass))
        request_data = req.pack()
        with socket.socket(family, socket.SOCK_DGRAM) as upstream_sock:
            upstream_sock.settimeout(2.5)
            upstream_sock.connect(sockaddr)
            upstream_sock.send(request_data)
            data = upstream_sock.recv(4096)
        response = DNSRecord.parse(data)
        if response.header.id != req.header.id:
            return None
        if response.header.tc:
            response = _resolve_upstream_tcp(family, sockaddr, request_data)
            if not response or response.header.id != req.header.id:
                return None
        return response
    except Exception:
        return None


def rate_limit_check(client_ip):
    if not CFG.get("rate_limiting", True):
        return True
    now = time.monotonic()
    max_rps = max(1, int(CFG.get("rate_limit_rps", 100)))
    with RATE_LIMIT_LOCK:
        bucket = CLIENT_RATES.get(client_ip)
        if bucket is None:
            if len(CLIENT_RATES) >= MAX_TRACKED_CLIENTS:
                CLIENT_RATES.popitem(last=False)
            bucket = deque()
            CLIENT_RATES[client_ip] = bucket
        else:
            CLIENT_RATES.move_to_end(client_ip)
        while bucket and now - bucket[0] >= 1.0:
            bucket.popleft()
        if len(bucket) >= max_rps:
            return False
        bucket.append(now)
        return True


def _send_dns_reply(reply, sock, addr, tcp=False):
    packet = reply.pack()
    if tcp:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
    else:
        sock.sendto(packet, addr)


def handle_dns_request(data, addr, sock, tcp=False):
    client_ip = addr[0]
    try:
        request_record = DNSRecord.parse(data)
    except Exception:
        return
    if not request_record.questions:
        return

    q = request_record.questions[0]
    qname = normalize_query_name(str(q.qname))
    qtype = q.qtype
    qtype_str = QTYPE.get(qtype, f"TYPE{qtype}")
    if not qname:
        reply = request_record.reply()
        reply.header.rcode = RCODE.FORMERR
        try:
            _send_dns_reply(reply, sock, addr, tcp)
        except OSError:
            pass
        return

    update_stats(total=1)
    update_client_activity(client_ip, total=1, last_seen=time.time())

    def log_query(status, reason, category="clean", matched_rule="", source=""):
        record_query({
            "time": datetime.now().strftime("%H:%M:%S"),
            "client": client_ip,
            "domain": qname,
            "type": qtype_str,
            "status": status,
            "reason": reason,
            "cat": category,
            "color": CAT.get(category, {}).get("color", "#fb542b" if status == "Blocked" else "#10b981"),
            "matched_rule": matched_rule,
            "source": source,
        })

    if not rate_limit_check(client_ip):
        record_security_event("Rate Limit Exceeded", client_ip,
                              f"Exceeded {CFG.get('rate_limit_rps', 100)} req/sec")
        reply = request_record.reply()
        reply.header.rcode = RCODE.REFUSED
        try:
            _send_dns_reply(reply, sock, addr, tcp)
        except OSError:
            pass
        log_query("Blocked", "Rate limit exceeded", "security", qname, "rate limiter")
        return

    if CFG.get("amplification_protection", True) and qtype_str == "ANY":
        reply = request_record.reply()
        reply.header.rcode = RCODE.REFUSED
        try:
            _send_dns_reply(reply, sock, addr, tcp)
        except OSError:
            pass
        record_security_event("DNS Amplification Blocked", client_ip, f"ANY query for {qname}")
        log_query("Blocked", "ANY query refused", "security", qname, "amplification defense")
        return

    action, block_cat, _, matched_rule, source = audit_threat(qname)
    is_blocked = action == "blocked"
    block_reason = f"Blocklist ({block_cat.title()})" if is_blocked else ""

    # Explicit allow rules take priority over heuristic DGA detection.
    if action != "whitelisted" and source != "protected media guard" and not is_blocked and CFG.get("dga_protection", True) and is_dga(qname):
        is_blocked = True
        block_cat = "malware"
        block_reason = "DGA heuristic"
        matched_rule = qname
        source = "DGA detector"
        record_security_event("DGA Domain Blocked", client_ip, f"High entropy: {qname}")

    def blocked_reply():
        reply = request_record.reply()
        reply.header.rcode = RCODE.NOERROR
        if q.qclass == 1 and qtype == QTYPE.A:
            reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A("0.0.0.0")))
        elif q.qclass == 1 and qtype == QTYPE.AAAA:
            reply.add_answer(RR(rname=q.qname, rtype=QTYPE.AAAA, rclass=1, ttl=60, rdata=AAAA("::")))
        return reply

    if is_blocked:
        update_stats(blocked=1)
        update_client_activity(
            client_ip,
            blocked=1,
            threats=int(block_cat in ("malware", "phishing", "spam", "security")),
        )
        try:
            _send_dns_reply(blocked_reply(), sock, addr, tcp)
        except OSError:
            pass
        log_query("Blocked", block_reason, block_cat, matched_rule, source)
        return

    # Resolve once, inspect the actual answer chain for CNAME cloaking, and
    # reuse that response. The old implementation performed an extra upstream
    # lookup for every clean hostname and often missed the final CNAME chain.
    resolved = resolve_upstream(qname, qtype, q.qclass)
    if not resolved:
        reply = request_record.reply()
        reply.header.rcode = RCODE.SERVFAIL
        try:
            _send_dns_reply(reply, sock, addr, tcp)
        except OSError:
            pass
        log_query("Error", "Upstream DNS lookup failed", "clean", "", CFG.get("dns_upstream", "1.1.1.1"))
        return

    # The upstream request uses its own transaction ID; restore the client's ID
    # and original question before returning the packet.
    resolved.header.id = request_record.header.id
    resolved.questions = request_record.questions

    if CFG.get("cname_uncloaking", True):
        for rr in resolved.rr:
            if rr.rtype != QTYPE.CNAME:
                continue
            cname_target = normalize_query_name(str(rr.rdata))
            if not cname_target:
                continue
            cname_action, cname_cat, _, cname_rule, cname_source = audit_threat(cname_target)
            if cname_action == "blocked":
                is_blocked = True
                block_cat = cname_cat
                matched_rule = cname_rule
                source = cname_source
                block_reason = f"CNAME target blocked ({cname_target})"
                break

    if is_blocked:
        update_stats(blocked=1)
        update_client_activity(
            client_ip,
            blocked=1,
            threats=int(block_cat in ("malware", "phishing", "spam", "security")),
        )
        try:
            _send_dns_reply(blocked_reply(), sock, addr, tcp)
        except OSError:
            pass
        log_query("Blocked", block_reason, block_cat, matched_rule, source)
        return

    # Rebinding checks cover A and AAAA records and all answers in the chain.
    local_suffixes = (".local", ".internal", ".home", ".home.arpa", ".lan")
    if CFG.get("rebinding_protection", True) and not qname.endswith(local_suffixes):
        for rr in resolved.rr:
            if rr.rtype not in (QTYPE.A, QTYPE.AAAA):
                continue
            ip_value = str(rr.rdata)
            if is_private_ip(ip_value):
                record_security_event("DNS Rebinding Blocked", client_ip, f"{qname} -> {ip_value}")
                update_stats(blocked=1)
                update_client_activity(client_ip, blocked=1)
                reply = request_record.reply()
                reply.header.rcode = RCODE.NXDOMAIN
                try:
                    _send_dns_reply(reply, sock, addr, tcp)
                except OSError:
                    pass
                log_query("Blocked", f"DNS rebinding: {ip_value}", "security", qname, "rebinding protection")
                return

    try:
        _send_dns_reply(resolved, sock, addr, tcp)
    except OSError:
        return
    if resolved.header.rcode == RCODE.NXDOMAIN:
        reason = "Upstream NXDOMAIN"
    elif source == "protected media guard":
        reason = "Protected media domain"
    elif action == "whitelisted":
        reason = "Custom whitelist"
    else:
        reason = "Clean"
    log_query("Allowed", reason, "clean", matched_rule, source)


def _udp_dns_worker(work_queue, sock):
    while True:
        data, addr = work_queue.get()
        try:
            handle_dns_request(data, addr, sock)
        except Exception as exc:
            print(f"[!] DNS UDP request error: {exc}")
        finally:
            work_queue.task_done()


def dns_server_worker():
    port = int(CFG.get("dns_port", 53))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
        print(f"[*] DNS UDP server on 0.0.0.0:{port}")
    except OSError as exc:
        print(f"[!] Cannot bind DNS UDP port {port}: {exc}")
        sock.close()
        return

    work_queue = queue.Queue(maxsize=DNS_UDP_QUEUE_SIZE)
    for index in range(DNS_UDP_WORKERS):
        threading.Thread(
            target=_udp_dns_worker,
            args=(work_queue, sock),
            name=f"dns-udp-{index + 1}",
            daemon=True,
        ).start()

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            try:
                work_queue.put_nowait((data, addr))
            except queue.Full:
                # Drop excess traffic instead of allocating unbounded threads or memory.
                continue
        except OSError:
            break
        except Exception:
            continue


def handle_dns_tcp_connection(conn, addr):
    try:
        conn.settimeout(10)
        request_count = 0
        deadline = time.monotonic() + 300
        while request_count < 256 and time.monotonic() < deadline:
            length_bytes = _recv_exact(conn, 2)
            if not length_bytes:
                return
            message_length = struct.unpack("!H", length_bytes)[0]
            if message_length == 0:
                return
            data = _recv_exact(conn, message_length)
            if not data:
                return
            handle_dns_request(data, addr, conn, tcp=True)
            request_count += 1
    except (OSError, socket.timeout):
        return


def _tcp_dns_worker(connection_queue):
    while True:
        conn, addr = connection_queue.get()
        try:
            handle_dns_tcp_connection(conn, addr)
        except Exception as exc:
            print(f"[!] DNS TCP connection error: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            connection_queue.task_done()


def dns_tcp_server_worker():
    port = int(CFG.get("dns_port", 53))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(DNS_TCP_QUEUE_SIZE)
        print(f"[*] DNS TCP server on 0.0.0.0:{port}")
    except OSError as exc:
        print(f"[!] Cannot bind DNS TCP port {port}: {exc}")
        server.close()
        return

    connection_queue = queue.Queue(maxsize=DNS_TCP_QUEUE_SIZE)
    for index in range(DNS_TCP_WORKERS):
        threading.Thread(
            target=_tcp_dns_worker,
            args=(connection_queue,),
            name=f"dns-tcp-{index + 1}",
            daemon=True,
        ).start()

    while True:
        try:
            conn, addr = server.accept()
            try:
                connection_queue.put_nowait((conn, addr))
            except queue.Full:
                conn.close()
        except OSError:
            break
        except Exception:
            continue


def update_enabled_lists(list_ids):
    ids = [lid for lid in list_ids if lid in ALL_LISTS]
    if not ids:
        rebuild_master_blocklist()
        return
    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(download_and_parse_list, ids))
    rebuild_master_blocklist()


def auto_refresh_worker():
    time.sleep(2)
    try:
        # Refresh enabled feeds once at startup so upgraded source URLs and
        # cached rules are reconciled without delaying DNS service startup.
        update_enabled_lists(CFG.get("enabled_lists", []))
    except Exception as exc:
        print(f"[!] Initial blocklist refresh error: {exc}")

    while True:
        try:
            interval = max(300, int(CFG.get("refresh_hours", 24)) * 3600)
            time.sleep(interval)
            if CFG.get("auto_refresh", True):
                update_enabled_lists(CFG.get("enabled_lists", []))
        except Exception as exc:
            print(f"[!] Automatic list refresh error: {exc}")
            time.sleep(60)


if os.environ.get("NETBLOCK_DISABLE_SERVERS") != "1":
    threading.Thread(target=dns_server_worker, daemon=True).start()
    threading.Thread(target=dns_tcp_server_worker, daemon=True).start()
    threading.Thread(target=auto_refresh_worker, daemon=True).start()

# ──────────────────────────────────────────────
#  Flask App
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = CFG["flask_secret_key"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

def is_logged_in():
    return session.get("logged_in") is True

def login_req(f):
    def wrap(*args, **kwargs):
        if not is_logged_in():
            return redirect("/login")
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# ──────────────────────────────────────────────
#  Templates
# ──────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login - NetBlock Fortress</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
body{background:#0a0e17;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-card{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:36px;width:100%;max-width:380px;box-shadow:0 20px 40px rgba(0,0,0,.6)}
.logo{text-align:center;margin-bottom:24px}
.logo-icon{font-size:42px;color:#fb542b;margin-bottom:10px}
.logo h1{font-size:22px;font-weight:700;color:#fff}
.logo p{font-size:12px;color:#8892b0;margin-top:4px}
.inp-grp{margin-bottom:16px}
.lbl{display:block;font-size:11px;text-transform:uppercase;color:#8892b0;letter-spacing:.8px;margin-bottom:6px;font-weight:600}
.inp{width:100%;background:#0a0e17;border:1px solid #374151;border-radius:8px;padding:12px;color:#fff;font-size:14px;outline:none}
.inp:focus{border-color:#fb542b}
.btn{width:100%;background:#fb542b;border:none;border-radius:8px;padding:12px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px}
.err{background:rgba(239,68,68,.12);border:1px solid #ef4444;color:#ef4444;padding:10px;border-radius:6px;font-size:12px;margin-bottom:16px;text-align:center}
</style></head><body>
<div class="login-card">
<div class="logo">
<div class="logo-icon"><i class="fa-solid fa-shield-halved"></i></div>
<h1>NetBlock Fortress</h1>
<p>Network-Wide Protection Shield</p>
</div>
{% if err %}<div class="err"><i class="fa-solid fa-circle-exclamation"></i> {{ err }}</div>{% endif %}
<form method="POST" action="/login">
<div class="inp-grp"><label class="lbl">Username</label>
<input class="inp" type="text" name="username" required autofocus placeholder="Username"></div>
<div class="inp-grp"><label class="lbl">Password</label>
<input class="inp" type="password" name="password" required placeholder="Password"></div>
<button class="btn" type="submit"><i class="fa-solid fa-lock"></i> Sign In</button>
</form></div></body></html>"""

BASE_TPL = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} - NetBlock Fortress</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
:root{--pri:#fb542b;--sec:#8b5cf6;--bg:#0a0e17;--card:#111827;--cb:#1f2937;--txt:#e2e8f0;--mut:#8892b0;--grn:#10b981;--red:#ef4444;--yel:#f59e0b}
*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
body{background:var(--bg);color:var(--txt);min-height:100vh;display:flex}
.sidebar{width:240px;background:var(--card);border-right:1px solid var(--cb);display:flex;flex-direction:column;flex-shrink:0;min-height:100vh}
.brand{padding:22px 20px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--cb)}
.brand i{font-size:24px;color:var(--pri)}
.bn{font-size:16px;font-weight:700;color:#fff}
.bs{font-size:10px;color:var(--mut);text-transform:uppercase;letter-spacing:1px}
.nav{flex:1;padding:16px 10px;display:flex;flex-direction:column;gap:4px}
.ni{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:8px;color:var(--mut);text-decoration:none;font-size:13px;font-weight:500}
.ni:hover{background:rgba(255,255,255,.04);color:#fff}
.ni.active{background:rgba(251,84,43,.12);color:var(--pri);font-weight:600}
.sf{padding:14px;border-top:1px solid var(--cb);display:flex;align-items:center;justify-content:space-between}
.lo{color:var(--mut);text-decoration:none;font-size:12px;display:flex;align-items:center;gap:6px}
.lo:hover{color:var(--red)}
.main{flex:1;display:flex;flex-direction:column;overflow-x:hidden}
.tb{height:60px;background:var(--card);border-bottom:1px solid var(--cb);display:flex;align-items:center;justify-content:space-between;padding:0 28px}
.tt{font-size:16px;font-weight:700;color:#fff}
.ts{display:flex;align-items:center;gap:16px;font-size:12px}
.sp{display:flex;align-items:center;gap:6px;padding:4px 10px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:20px;color:var(--grn);font-weight:600}
.content{padding:28px;flex:1}
.card{background:var(--card);border:1px solid var(--cb);border-radius:12px;padding:20px;margin-bottom:20px}
.ch{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.ct{font-size:14px;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.sc{background:var(--card);border:1px solid var(--cb);border-radius:12px;padding:18px;position:relative;overflow:hidden}
.sv{font-size:26px;font-weight:800;color:#fff;margin:6px 0 2px;letter-spacing:-.5px}
.sl{font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:600;letter-spacing:.5px}
.bg{position:absolute;right:14px;bottom:14px;font-size:42px;opacity:.06;color:#fff}
.ss{font-size:11px;color:var(--mut);margin-top:4px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:none;text-decoration:none}
.bp{background:var(--pri);color:#fff}.bp:hover{opacity:.9}
.b2{background:#1f2937;color:#fff;border:1px solid #374151}
.bs2{padding:5px 10px;font-size:11px}
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{text-align:left;padding:10px 14px;background:#0d131f;color:var(--mut);font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:.6px}
.tbl td{padding:10px 14px;border-top:1px solid #1f2937}
.tbl tr:hover td{background:rgba(255,255,255,.02)}
.bdg{display:inline-block;padding:3px 8px;border-radius:6px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}
.inp{background:#0a0e17;border:1px solid #374151;border-radius:6px;padding:8px 12px;color:#fff;font-size:12px;outline:none}
.inp:focus{border-color:var(--pri)}
.lbl{display:block;font-size:11px;text-transform:uppercase;color:var(--mut);margin-bottom:5px;font-weight:600}
.fg{margin-bottom:16px}
.sw{position:relative;display:inline-block;width:38px;height:20px}
.sw input{opacity:0;width:0;height:0}
.sl2{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#374151;transition:.2s;border-radius:20px}
.sl2:before{position:absolute;content:"";height:14px;width:14px;left:3px;bottom:3px;background:white;transition:.2s;border-radius:50%}
input:checked+.sl2{background:var(--pri)}
input:checked+.sl2:before{transform:translateX(18px)}
.al{padding:12px 16px;border-radius:8px;font-size:12px;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.alok{background:rgba(16,185,129,.12);border:1px solid var(--grn);color:var(--grn)}
.alerr{background:rgba(239,68,68,.12);border:1px solid var(--red);color:var(--red)}
</style></head><body>
<div class="sidebar">
<div class="brand"><i class="fa-solid fa-shield-halved"></i>
<div><div class="bn">NetBlock</div><div class="bs">Fortress v19.0</div></div></div>
<div class="nav">
<a class="ni {% if a=='dash' %}active{% endif %}" href="/"><i class="fa-solid fa-gauge"></i> Dashboard</a>
<a class="ni {% if a=='sec' %}active{% endif %}" href="/security"><i class="fa-solid fa-lock"></i> Security Center</a>
<a class="ni {% if a=='bl' %}active{% endif %}" href="/blocklists"><i class="fa-solid fa-list-check"></i> Blocklists ({{ list_count }})</a>
<a class="ni {% if a=='modes' %}active{% endif %}" href="/modes"><i class="fa-solid fa-sliders"></i> Protection Modes</a>
<a class="ni {% if a=='logs' %}active{% endif %}" href="/logs"><i class="fa-solid fa-clock-rotate-left"></i> Live Query Logs</a>
<a class="ni {% if a=='cust' %}active{% endif %}" href="/custom"><i class="fa-solid fa-pen-to-square"></i> Custom Rules</a>
<a class="ni {% if a=='sett' %}active{% endif %}" href="/settings"><i class="fa-solid fa-gear"></i> Settings</a>
</div>
<div class="sf">
<div style="font-size:11px;color:var(--mut)"><i class="fa-solid fa-circle" style="color:var(--grn);font-size:8px"></i> DNS Active (:{ dns_port })</div>
<a class="lo" href="/logout"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
</div></div>
<div class="main">
<div class="tb"><div class="tt">{{ page_title }}</div>
<div class="ts"><div class="sp"><i class="fa-solid fa-shield"></i> {{ "{:,}".format(blocked_count) }} Blocked</div></div></div>
<div class="content">
{% if msg %}
<div class="al {% if msg_type=='err' %}alerr{% else %}alok{% endif %}">
<i class="fa-solid {% if msg_type=='err' %}fa-circle-exclamation{% else %}fa-circle-check{% endif %}"></i> {{ msg }}
</div>
{% endif %}{% block content %}{% endblock %}</div></div></body></html>"""

def render_page(tpl, nav, page_title="Dashboard", msg="", msg_type="ok", **kw):
    full = BASE_TPL.replace("{% block content %}{% endblock %}", tpl)
    return render_template_string(full, a=nav, page_title=page_title,
        title=page_title, msg=msg, msg_type=msg_type,
        blocked_count=len(BLOCKED_DOMAINS),
        dns_port=CFG.get("dns_port", 53), list_count=len(ALL_LISTS), **kw)

# ── Dashboard Page ──
PAGE_DASH = """
<div class="sg">
<div class="sc"><i class="fa-solid fa-shield-halved bg"></i>
<div class="sl">Total Queries</div><div class="sv">{{ "{:,}".format(total_queries) }}</div>
<div class="ss">Across {{ client_count }} clients</div></div>
<div class="sc"><i class="fa-solid fa-ban bg" style="color:var(--pri)"></i>
<div class="sl">Threats & Ads Blocked</div><div class="sv" style="color:var(--pri)">{{ "{:,}".format(blocked_queries) }}</div>
<div class="ss">{{ block_rate }}% block rate</div></div>
<div class="sc"><i class="fa-solid fa-download bg" style="color:var(--grn)"></i>
<div class="sl">Estimated Bandwidth Saved</div><div class="sv" style="color:var(--grn)">{{ bandwidth_saved }}</div>
<div class="ss">~125 KB assumed per blocked request</div></div>
<div class="sc"><i class="fa-solid fa-hourglass-half bg" style="color:var(--sec)"></i>
<div class="sl">Estimated Time Saved</div><div class="sv" style="color:var(--sec)">{{ time_saved }}</div>
<div class="ss">~1.5s assumed per blocked request</div></div>
</div>
<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-bottom:20px">
<div class="card" style="margin-bottom:0"><div class="ch">
<div class="ct"><i class="fa-solid fa-shield-virus" style="color:var(--pri)"></i> Threat Category Distribution</div></div>
<div style="display:flex;flex-direction:column;gap:12px">
{% for cid, inf in cat_summary.items() %}<div>
<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
<span><i class="fa-solid {{ inf.icon }}" style="color:{{ inf.color }};width:16px"></i> {{ inf.name }}</span>
<span style="font-weight:700">{{ "{:,}".format(inf.count) }} rules</span></div>
<div style="background:#1f2937;height:6px;border-radius:3px;overflow:hidden">
<div style="background:{{ inf.color }};height:100%;width:{{ inf.pct }}%"></div></div>
</div>{% endfor %}</div></div>
<div class="card" style="margin-bottom:0"><div class="ch">
<div class="ct"><i class="fa-solid fa-server"></i> Fortress Status</div></div>
<div style="display:flex;flex-direction:column;gap:14px;font-size:12px">
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">Active Block Rules</span>
<span style="font-weight:700;color:var(--grn)">{{ "{:,}".format(rule_count) }}</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">DNS Rebinding</span><span style="font-weight:700;color:{% if rebinding_enabled %}var(--grn){% else %}var(--mut){% endif %}">{% if rebinding_enabled %}ON{% else %}OFF{% endif %}</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">DGA Detection</span><span style="font-weight:700;color:{% if dga_enabled %}var(--grn){% else %}var(--mut){% endif %}">{% if dga_enabled %}ON{% else %}OFF{% endif %}</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">CNAME Uncloaking</span><span style="font-weight:700;color:{% if cname_enabled %}var(--grn){% else %}var(--mut){% endif %}">{% if cname_enabled %}ON{% else %}OFF{% endif %}</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">YouTube video handling</span><span style="font-weight:700;color:var(--grn)">Playback-safe</span></div>
<div style="display:flex;justify-content:space-between">
<span style="color:var(--mut)">Uptime</span><span style="font-weight:700">{{ uptime_str }}</span></div>
</div></div></div>
<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-clock-rotate-left"></i> Recent Threat Audits</div>
<a href="/logs" class="btn b2 bs2">View All</a></div>
<table class="tbl"><thead><tr>
<th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Verdict</th><th>Category</th></tr></thead><tbody>
{% for l in recent_logs %}<tr>
<td style="color:var(--mut)">{{ l.time }}</td><td><code>{{ l.client }}</code></td>
<td style="font-weight:600">{{ l.domain }}</td><td style="color:var(--mut)">{{ l.type }}</td>
<td>{% if l.status=='Blocked' %}<span class="bdg" style="background:rgba(239,68,68,.15);color:var(--red)">BLOCKED</span>
{% else %}<span class="bdg" style="background:rgba(16,185,129,.15);color:var(--grn)">CLEAN</span>{% endif %}</td>
<td><span class="bdg" style="background:rgba(255,255,255,.05);color:{{ l.color }}">{{ l.reason }}</span></td></tr>
{% else %}<tr><td colspan="6" style="text-align:center;color:var(--mut);padding:20px">No queries yet. Point DNS to this server.</td></tr>{% endfor %}
</tbody></table></div>
"""

# ── Security Page ──
PAGE_SEC = """
<div class="sg">
<div class="sc"><i class="fa-solid fa-shield-virus bg" style="color:var(--red)"></i>
<div class="sl">Security Blocks</div><div class="sv" style="color:var(--red)">{{ events|length }}</div>
<div class="ss">Rebinding, DGA, Amplification</div></div>
<div class="sc"><i class="fa-solid fa-users bg"></i>
<div class="sl">Active Clients</div><div class="sv">{{ clients|length }}</div>
<div class="ss">Network endpoints</div></div>
<div class="sc"><i class="fa-solid fa-user-shield bg" style="color:var(--yel)"></i>
<div class="sl">Suspicious Endpoints</div><div class="sv" style="color:var(--yel)">{{ suspicious }}</div>
<div class="ss">High threat traffic</div></div>
</div>
<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-triangle-exclamation" style="color:var(--red)"></i> Security Events</div></div>
<table class="tbl"><thead><tr>
<th>Time</th><th>Type</th><th>Client</th><th>Details</th><th>Action</th></tr></thead><tbody>
{% for ev in events %}<tr>
<td style="color:var(--mut)">{{ ev.time }}</td>
<td><span class="bdg" style="background:rgba(239,68,68,.15);color:var(--red)">{{ ev.type }}</span></td>
<td><code>{{ ev.client }}</code></td><td style="font-weight:600">{{ ev.detail }}</td>
<td><span class="bdg" style="background:rgba(16,185,129,.15);color:var(--grn)">BLOCKED</span></td></tr>
{% else %}<tr><td colspan="5" style="text-align:center;color:var(--mut);padding:24px">No attacks detected.</td></tr>{% endfor %}
</tbody></table></div>
<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-network-wired"></i> Client Inspection</div></div>
<table class="tbl"><thead><tr>
<th>IP</th><th>Total</th><th>Threats</th><th>Block Ratio</th><th>Last Seen</th></tr></thead><tbody>
{% for ip, d in clients.items() %}<tr>
<td><code>{{ ip }}</code></td><td>{{ "{:,}".format(d.total) }}</td>
<td>{% if d.threats > 0 %}<span class="bdg" style="background:rgba(239,68,68,.2);color:var(--red)">{{ d.threats }}</span>
{% else %}<span style="color:var(--mut)">0</span>{% endif %}</td>
<td>{% if d.total > 0 %}{{ "%.1f"|format(d.blocked / d.total * 100) }}%{% else %}0%{% endif %}</td>
<td style="color:var(--mut)">{{ d.last_seen_str }}</td></tr>
{% endfor %}</tbody></table></div>
"""

# ── Blocklists Page ──
PAGE_BL = """
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
<div><h2 style="font-size:18px;font-weight:700">Fortress Threat & Ad Feeds</h2>
<p style="font-size:12px;color:var(--mut)">{{ lists|length }} curated feeds across {{ cats|length }} categories</p>
<p style="font-size:11px;color:var(--mut);margin-top:6px">DNS can block domains, not page paths or ads served from the same host as content. YouTube video CDN domains are deliberately not blocked.</p></div>
<form method="POST" action="/blocklists/update_all">
<button class="btn bp" type="submit"><i class="fa-solid fa-arrows-rotate"></i> Refresh Enabled</button></form></div>
<div class="card"><table class="tbl"><thead><tr>
<th>Feed</th><th>Category</th><th>Status</th><th>Rules</th><th>Synced</th><th>Enable</th><th></th>
</tr></thead><tbody>
{% for lid, st in lists.items() %}<tr>
<td><div style="font-weight:600">{{ st.name }}</div>
<div style="font-size:10px;color:var(--mut)">{{ lid }}</div></td>
<td><span class="bdg" style="background:rgba(255,255,255,.05);color:{{ cats[st.cat].color }}">
<i class="fa-solid {{ cats[st.cat].icon }}"></i> {{ cats[st.cat].name }}</span></td>
<td>{% if st.state=='active' %}<span class="bdg" style="background:rgba(16,185,129,.15);color:var(--grn)"><i class="fa-solid fa-check"></i> Active</span>
{% elif st.state=='downloading' %}<span class="bdg" style="background:rgba(245,158,11,.15);color:var(--yel)"><i class="fa-solid fa-spinner fa-spin"></i> Syncing</span>
{% elif st.state=='stale' %}<span class="bdg" title="{{ st.error }}" style="background:rgba(245,158,11,.15);color:var(--yel)">Stale cache</span>
{% elif st.state=='error' %}<span class="bdg" style="background:rgba(239,68,68,.15);color:var(--red)">{{ st.error }}</span>
{% else %}<span class="bdg" style="background:rgba(255,255,255,.05);color:var(--mut)">Idle</span>{% endif %}</td>
<td style="font-weight:700">{{ "{:,}".format(st.count) }}</td>
<td style="color:var(--mut)">{{ st.last_updated }}</td>
<td><form method="POST" action="/blocklists/toggle" id="f-{{ lid }}">
<input type="hidden" name="lid" value="{{ lid }}">
<label class="sw"><input type="checkbox" name="enabled" value="1"
{% if st.enabled %}checked{% endif %}
onchange="document.getElementById('f-{{ lid }}').submit()"><span class="sl2"></span></label></form></td>
<td><form method="POST" action="/blocklists/download_single">
<input type="hidden" name="lid" value="{{ lid }}">
<button class="btn b2 bs2" type="submit"><i class="fa-solid fa-download"></i></button></form></td>
</tr>{% endfor %}</tbody></table></div>
<script>
setInterval(function(){fetch('/api/list_status').then(r=>r.json()).then(d=>{
let s=Object.values(d).some(v=>v.state==='downloading');if(s)setTimeout(()=>location.reload(),1500);});},2000);
</script>
"""

# ── Modes Page ──
PAGE_MODES = """
<div style="margin-bottom:20px"><h2 style="font-size:18px;font-weight:700">Protection Profiles</h2>
<p style="font-size:12px;color:var(--mut)">Choose a curated DNS domain policy. Aggressive profiles can break apps; use Query Inspector and the allowlist to tune them.</p></div>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px">
<div class="card" style="border-top:3px solid var(--grn)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Balanced</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Core ad and threat feeds with lower overlap.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>Major ad domains</li><li>Malware and phishing domains</li><li>Social feeds stay off</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="balanced">
<button class="btn {% if cur_mode=='balanced' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='balanced' %}Active{% else %}Activate{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid var(--pri)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Strict</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Max privacy. Telemetry, trackers, cryptojacking.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>All Balanced rules</li><li>SmartTV & Windows Spy blocked</li>
<li>Cryptojacking prevention</li><li>CNAME + DGA analysis</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="strict">
<button class="btn {% if cur_mode=='strict' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='strict' %}Active{% else %}Activate{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid var(--red)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Aggressive Ads</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Highest DNS-level ad and tracker coverage; increased false-positive and app-breakage risk.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>HaGeZi Pro++ plus other ad-domain feeds</li><li>Tracker and threat-intelligence feeds</li><li>No broad Googlevideo/CDN blocking</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="aggressive_ads">
<button class="btn {% if cur_mode=='aggressive_ads' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='aggressive_ads' %}Active{% else %}Activate{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid var(--sec)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Family & Safe</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Strict profile plus adult and gambling domain lists.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>All Strict rules</li><li>Adult & NSFW domains blocked</li>
<li>Gambling domains blocked</li><li>Use device/router controls for SafeSearch</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="family">
<button class="btn {% if cur_mode=='family' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='family' %}Active{% else %}Activate{% endif %}</button></form></div></div>
"""

# ── Logs Page ──
PAGE_LOGS = """
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
<div><h2 style="font-size:18px;font-weight:700">Query Inspector</h2>
<p style="font-size:12px;color:var(--mut)">Newest 300 events from the rotating audit log (client IPs included; logging can be disabled in Settings).</p></div>
<form method="POST" action="/logs/clear">
<button class="btn b2 bs2" type="submit"><i class="fa-solid fa-trash"></i> Clear</button></form></div>
<div class="card"><table class="tbl"><thead><tr>
<th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Status</th><th>Audit</th><th>Matched rule</th><th>Feed / source</th>
</tr></thead><tbody>
{% for l in logs %}<tr>
<td style="color:var(--mut)">{{ l.time }}</td><td><code>{{ l.client }}</code></td>
<td style="font-weight:600">{{ l.domain }}</td><td style="color:var(--mut)">{{ l.type }}</td>
<td>{% if l.status=='Blocked' %}<span class="bdg" style="background:rgba(239,68,68,.15);color:var(--red)">BLOCKED</span>
{% else %}<span class="bdg" style="background:rgba(16,185,129,.15);color:var(--grn)">ALLOWED</span>{% endif %}</td>
<td><span class="bdg" style="background:rgba(255,255,255,.05);color:{{ l.color }}">{{ l.reason }}</span></td>
<td><code>{{ l.matched_rule or "—" }}</code></td><td style="color:var(--mut)">{{ l.source or "—" }}</td></tr>
{% else %}<tr><td colspan="8" style="text-align:center;color:var(--mut);padding:30px">No queries yet.</td></tr>{% endfor %}
</tbody></table></div>
"""

# ── Custom Page ──
PAGE_CUSTOM = """
<div style="margin-bottom:20px"><h2 style="font-size:18px;font-weight:700">Custom Domain Rules</h2>
<p style="font-size:12px;color:var(--mut)">Override block/allow per domain</p></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-ban" style="color:var(--pri)"></i> Blacklist</div></div>
<form method="POST" action="/custom/save_block"><div class="fg">
<label class="lbl">Domains to Block (one per line)</label>
<textarea class="inp" name="domains" rows="12" style="width:100%;font-family:monospace;font-size:12px;line-height:1.6">{{ b_txt }}</textarea></div>
<button class="btn bp" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save</button></form></div>
<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-check" style="color:var(--grn)"></i> Whitelist</div></div>
<form method="POST" action="/custom/save_white"><div class="fg">
<label class="lbl">Domains to Allow (never block)</label>
<textarea class="inp" name="domains" rows="12" style="width:100%;font-family:monospace;font-size:12px;line-height:1.6">{{ w_txt }}</textarea></div>
<button class="btn bp" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save</button></form></div></div>
"""

# ── Settings Page ──
PAGE_SETTINGS = """
<div style="margin-bottom:20px"><h2 style="font-size:18px;font-weight:700">Fortress Configuration</h2>
<p style="font-size:12px;color:var(--mut)">Credentials, DNS, logging, and security settings</p></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">

<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-user-shield"></i> Admin Credentials</div></div>
<form method="POST" action="/settings"><input type="hidden" name="change_pw" value="1">
<div class="fg"><label class="lbl">Username</label>
<input class="inp" type="text" name="new_username" value="{{ cfg.admin_username }}" required style="width:100%"></div>
<div class="fg"><label class="lbl">Current Password</label>
<input class="inp" type="password" name="cur_pw" required style="width:100%" placeholder="Current password"></div>
<div class="fg"><label class="lbl">New Password (blank = keep)</label>
<input class="inp" type="password" name="new_pw" style="width:100%" placeholder="Min 8 characters"></div>
<div class="fg"><label class="lbl">Confirm New Password</label>
<input class="inp" type="password" name="confirm_pw" style="width:100%" placeholder="Re-type"></div>
<button class="btn bp" type="submit"><i class="fa-solid fa-key"></i> Update</button></form></div>

<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-shield-halved" style="color:var(--pri)"></i> Defense Engine</div></div>
<form method="POST" action="/settings"><input type="hidden" name="save_sec" value="1">
<div style="display:flex;flex-direction:column;gap:14px">
{% for key, label, desc in [
  ('rebinding_protection','DNS Rebinding Protection','Blocks public→private IP redirects'),
  ('dga_protection','DGA Threat Analysis','Entropy-based malware domain detection'),
  ('cname_uncloaking','CNAME Uncloaking','Checks the actual upstream answer chain for cloaked trackers'),
  ('amplification_protection','Amplification Defense','Refuses DNS ANY queries (DDoS)'),
  ('rate_limiting','Rate Limiting','Per-client queries/second cap')
] %}
<div style="display:flex;justify-content:space-between;align-items:center">
<div><div style="font-weight:600;font-size:12px">{{ label }}</div>
<div style="font-size:10px;color:var(--mut)">{{ desc }}</div></div>
<label class="sw"><input type="checkbox" name="{{ key }}" value="1" {% if cfg[key] %}checked{% endif %}><span class="sl2"></span></label></div>
{% endfor %}</div>
<div style="margin-top:16px"><button class="btn bp" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save Defense</button></div>
</form></div>

<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-network-wired"></i> DNS & Updates</div></div>
<form method="POST" action="/settings"><input type="hidden" name="save_dns" value="1">
<div class="fg"><label class="lbl">Upstream DNS IP address</label>
<input class="inp" type="text" name="dns_upstream" value="{{ cfg.dns_upstream }}" style="width:100%" placeholder="1.1.1.1 or 2606:4700:4700::1111"></div>
<div class="fg"><label class="lbl">Refresh Interval (hours)</label>
<input class="inp" type="number" name="refresh_hours" value="{{ cfg.refresh_hours }}" style="width:100%" min="1" max="168"></div>
<div class="fg"><label class="lbl">Rate Limit (queries/sec per client)</label>
<input class="inp" type="number" name="rate_limit_rps" value="{{ cfg.rate_limit_rps }}" style="width:100%" min="10" max="10000"></div>
<div style="display:flex;justify-content:space-between;align-items:center;margin:8px 0 16px">
<div><div style="font-weight:600;font-size:12px">Persist query audit log</div>
<div style="font-size:10px;color:var(--mut)">Rotating local log, up to 20 MiB; includes client IPs.</div></div>
<label class="sw"><input type="checkbox" name="query_logging" value="1" {% if cfg.query_logging %}checked{% endif %}><span class="sl2"></span></label></div>
<button class="btn bp" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save</button></form></div>
</div>
"""

# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def page_login():
    err = ""
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p_hash = hashlib.sha256(p.encode()).hexdigest()
        vu = CFG.get("admin_username", "admin").strip()
        if hmac.compare_digest(u.casefold(), vu.casefold()) and hmac.compare_digest(p_hash, CFG.get("password_hash", "")):
            session["logged_in"] = True
            return redirect("/")
        err = "Invalid username or password"
    return render_template_string(LOGIN_HTML, err=err)

@app.route("/logout")
def page_logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_req
def page_dashboard():
    up = int(time.time() - START_TIME)
    uptime = f"{up // 3600}h {(up % 3600) // 60}m"
    with STATS_LOCK:
        total_queries = TOTAL_QUERIES
        blocked_queries = BLOCKED_QUERIES
    activity = client_activity_snapshot()
    bw = blocked_queries * 125 * 1024
    bw_str = f"{bw / (1024**3):.2f} GB" if bw > 1024**3 else f"{bw / 1024**2:.1f} MB"
    ts = int(blocked_queries * 1.5)
    time_str = f"{ts / 3600:.1f} hours" if ts > 3600 else f"{ts // 60} mins"
    br = f"{blocked_queries / total_queries * 100:.1f}" if total_queries else "0.0"

    cat_counts = defaultdict(int)
    for d, c in DOMAIN_CATEGORIES.items():
        cat_counts[c] += 1
    total_rules = max(1, len(BLOCKED_DOMAINS))
    cat_summary = {}
    for cid, cinfo in CAT.items():
        cnt = cat_counts[cid]
        cat_summary[cid] = {"name": cinfo["name"], "color": cinfo["color"],
            "icon": cinfo["icon"], "count": cnt,
            "pct": min(100, int(cnt / total_rules * 100))}

    return render_page(PAGE_DASH, "dash", "Network Overview",
        total_queries=total_queries, blocked_queries=blocked_queries,
        block_rate=br, bandwidth_saved=bw_str, time_saved=time_str,
        client_count=len(activity), rule_count=len(BLOCKED_DOMAINS),
        uptime_str=uptime, cat_summary=cat_summary,
        recent_logs=query_log_snapshot(8),
        rebinding_enabled=CFG.get("rebinding_protection", True),
        dga_enabled=CFG.get("dga_protection", True),
        cname_enabled=CFG.get("cname_uncloaking", True))

@app.route("/security")
@login_req
def page_security():
    now = time.time()
    activity = client_activity_snapshot()
    with SECURITY_EVENTS_LOCK:
        security_events = list(SECURITY_EVENTS)
    susp = sum(1 for d in activity.values() if d["threats"] > 0)
    cvs = {}
    for ip, d in activity.items():
        delta = int(now - d["last_seen"])
        ls = f"{delta}s ago" if delta < 60 else f"{delta // 60}m ago" if delta < 3600 else f"{delta // 3600}h ago"
        cvs[ip] = {"total": d["total"], "blocked": d["blocked"], "threats": d["threats"], "last_seen_str": ls}
    return render_page(PAGE_SEC, "sec", "Security Center",
        events=security_events, clients=cvs, suspicious=susp)

@app.route("/blocklists")
@login_req
def page_blocklists():
    return render_page(PAGE_BL, "bl", f"Blocklists ({len(ALL_LISTS)} Feeds)",
        lists=list_status_snapshot(), cats=CAT)

@app.route("/blocklists/toggle", methods=["POST"])
@login_req
def bl_toggle():
    lid = request.form.get("lid")
    if lid in ALL_LISTS:
        enabled_ids = list(CFG.get("enabled_lists", []))
        enable = "enabled" in request.form
        if enable and lid not in enabled_ids:
            enabled_ids.append(lid)
        elif not enable and lid in enabled_ids:
            enabled_ids.remove(lid)
        CFG["enabled_lists"] = enabled_ids
        with LIST_STATUS_LOCK:
            LIST_STATUS[lid]["enabled"] = enable
        save_config(); save_list_status(); rebuild_master_blocklist()
        if enable and not (LIST_DIR / f"{lid}.txt").exists():
            threading.Thread(target=download_list_and_rebuild, args=(lid,), daemon=True).start()
    return redirect("/blocklists")

@app.route("/blocklists/download_single", methods=["POST"])
@login_req
def bl_dl():
    lid = request.form.get("lid")
    if lid in ALL_LISTS:
        threading.Thread(target=download_list_and_rebuild, args=(lid,), daemon=True).start()
    return redirect("/blocklists")

@app.route("/blocklists/update_all", methods=["POST"])
@login_req
def bl_update_all():
    threading.Thread(target=update_enabled_lists, args=(list(CFG.get("enabled_lists", [])),), daemon=True).start()
    return redirect("/blocklists")

@app.route("/api/list_status")
@login_req
def api_status():
    return jsonify(list_status_snapshot())

@app.route("/modes")
@login_req
def page_modes():
    return render_page(PAGE_MODES, "modes", "Protection Profiles",
        cur_mode=CFG.get("block_mode", "strict"))

@app.route("/modes/set", methods=["POST"])
@login_req
def mode_set():
    mode = request.form.get("mode", "")
    if mode not in PROFILE_LISTS:
        return redirect("/modes")
    CFG["block_mode"] = mode
    CFG["enabled_lists"] = list(PROFILE_LISTS[mode])
    with LIST_STATUS_LOCK:
        for lid in ALL_LISTS:
            LIST_STATUS[lid]["enabled"] = lid in CFG["enabled_lists"]
    save_config(); save_list_status(); rebuild_master_blocklist()
    missing = [lid for lid in CFG["enabled_lists"] if not (LIST_DIR / f"{lid}.txt").exists()]
    if missing:
        threading.Thread(target=update_enabled_lists, args=(missing,), daemon=True).start()
    return redirect("/modes")

@app.route("/logs")
@login_req
def page_logs():
    return render_page(PAGE_LOGS, "logs", "Query Inspector", logs=query_log_snapshot())

@app.route("/logs/clear", methods=["POST"])
@login_req
def logs_clear():
    clear_query_logs()
    return redirect("/logs")

@app.route("/custom")
@login_req
def page_custom():
    b = CUSTOM_BLOCK.read_text() if CUSTOM_BLOCK.exists() else ""
    w = CUSTOM_WHITE.read_text() if CUSTOM_WHITE.exists() else ""
    return render_page(PAGE_CUSTOM, "cust", "Custom Rules", b_txt=b, w_txt=w)

@app.route("/custom/save_block", methods=["POST"])
@login_req
def cust_block():
    CUSTOM_BLOCK.write_text(request.form.get("domains", ""))
    load_custom_lists(); rebuild_master_blocklist()
    return redirect("/custom")

@app.route("/custom/save_white", methods=["POST"])
@login_req
def cust_white():
    CUSTOM_WHITE.write_text(request.form.get("domains", ""))
    load_custom_lists(); rebuild_master_blocklist()
    return redirect("/custom")

@app.route("/settings", methods=["GET", "POST"])
@login_req
def page_settings():
    msg, msg_type = "", "ok"
    if request.method == "POST":
        if "change_pw" in request.form:
            cur = hashlib.sha256(request.form.get("cur_pw", "").encode()).hexdigest()
            new_u = request.form.get("new_username", "").strip()
            npw = request.form.get("new_pw", "")
            cpw = request.form.get("confirm_pw", "")
            if not hmac.compare_digest(cur, CFG.get("password_hash", "")):
                msg, msg_type = "Current password incorrect!", "err"
            elif npw and len(npw) < 8:
                msg, msg_type = "Password must be at least 8 characters!", "err"
            elif npw and npw != cpw:
                msg, msg_type = "Passwords don't match!", "err"
            else:
                if new_u:
                    CFG["admin_username"] = new_u
                if npw:
                    CFG["password_hash"] = hashlib.sha256(npw.encode()).hexdigest()
                save_config()
                msg = "Credentials updated!"

        elif "save_sec" in request.form:
            for key in ("rebinding_protection", "dga_protection", "cname_uncloaking",
                        "amplification_protection", "rate_limiting"):
                CFG[key] = key in request.form
            save_config(); msg = "Defense settings saved!"

        elif "save_dns" in request.form:
            upstream_text = request.form.get("dns_upstream", "1.1.1.1").strip()
            try:
                upstream = str(ipaddress.ip_address(upstream_text))
                refresh_hours = int(request.form.get("refresh_hours", 24))
                rate_limit_rps = int(request.form.get("rate_limit_rps", 100))
                if not 1 <= refresh_hours <= 168 or not 10 <= rate_limit_rps <= 10000:
                    raise ValueError("Values are outside the allowed range")
                CFG["dns_upstream"] = upstream
                CFG["refresh_hours"] = refresh_hours
                CFG["rate_limit_rps"] = rate_limit_rps
                CFG["query_logging"] = "query_logging" in request.form
                save_config(); msg = "DNS settings saved!"
            except ValueError as exc:
                msg, msg_type = f"Invalid DNS settings: {exc}", "err"

    return render_page(PAGE_SETTINGS, "sett", "Settings",
        msg=msg, msg_type=msg_type, cfg=CFG)

# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
if __name__ == "__main__":
    port = int(CFG.get("web_port", 8080))
    print(f"[*] NetBlock Fortress v19.0 | Web: {port} | DNS UDP/TCP: {CFG.get('dns_port', 53)}")
    print(f"[*] Data: {DATA_DIR}")
    print(f"[*] Lists: {len(ALL_LISTS)} sources across {len(CAT)} categories")
    app.run(host="0.0.0.0", port=port, debug=False)
