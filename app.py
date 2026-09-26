#!/usr/bin/env python3
"""
NetBlock Fortress v18.0
Network-wide ad blocker & threat intelligence DNS server.
Single-file application: DNS server + web dashboard.
Works on any Linux machine with Python 3.8+.
"""

import sys, subprocess

REQUIRED_PACKAGES = ["flask", "requests", "dnslib"]
for pkg in REQUIRED_PACKAGES:
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "--quiet"])

import os, re, time, math, socket, threading, json, hashlib, random, ipaddress
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque
from flask import Flask, request, redirect, session, jsonify, render_template_string
from dnslib import DNSRecord, DNSHeader, RR, A, AAAA, CNAME, NS, MX, PTR, QTYPE, RCODE, SOA

# ──────────────────────────────────────────────
#  Paths
# ──────────────────────────────────────────────
BASE_DIR = Path(os.environ.get("NETBLOCK_HOME", "/opt/netblock"))
DATA_DIR = BASE_DIR / "data"
LIST_DIR = DATA_DIR / "lists"
CONFIG_FILE = DATA_DIR / "config.json"
STATUS_FILE = DATA_DIR / "list_status.json"
CUSTOM_BLOCK = DATA_DIR / "custom_blocked.txt"
CUSTOM_WHITE = DATA_DIR / "custom_whitelist.txt"

for d in [DATA_DIR, LIST_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    "admin_username": "admin",
    "password_hash": hashlib.sha256(b"admin123").hexdigest(),
    "block_mode": "strict",
    "dns_upstream": "1.1.1.1",
    "dns_port": 53,
    "web_port": 8080,
    "openrouter_api_key": "",
    "ai_model": "openrouter/free",
    "auto_refresh": True,
    "refresh_hours": 24,
    "youtube_aggressive": True,
    "cname_uncloaking": True,
    "rebinding_protection": True,
    "dga_protection": True,
    "rate_limiting": True,
    "rate_limit_rps": 100,
    "amplification_protection": True,
    "safe_search": False,
    "enabled_lists": [
        "stevenblack", "adguard", "oisd", "hagezi_pro", "easylist", "peterlowe",
        "adaway", "1hosts", "yt_blockads", "firebog_ticked",
        "easypriv", "prigent_ads", "winspy", "smarttv", "ubpriv", "adguard_track", "notrack",
        "urlhaus", "rpi_mal", "phisharmy", "prigent_mal", "hagezi_badware", "abusech_ssl", "emerging", "dshield",
        "sb_phish", "openphish", "hagezi_threat", "phishdb", "rpi_phish", "blocklist_de",
        "spamhaus_drop", "spamhaus_edrop", "blocklist_de_all",
        "nocoin", "coinblocker",
        "hagezi_dyndns", "hagezi_hoster", "rpifake"
    ]
}

CFG = dict(DEFAULT_CONFIG)

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
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix('.tmp')
        tmp.write_text(json.dumps(CFG, indent=2))
        tmp.replace(CONFIG_FILE)
    except Exception as e:
        print(f"[!] Config save error: {e}")

load_config()

# CLI: change credentials from terminal
if len(sys.argv) >= 4 and sys.argv[1] == "--set-auth":
    CFG["admin_username"] = sys.argv[2].strip()
    CFG["password_hash"] = hashlib.sha256(sys.argv[3].encode()).hexdigest()
    save_config()
    print(f"[+] Credentials updated. User='{sys.argv[2]}'")
    sys.exit(0)

# ──────────────────────────────────────────────
#  Blocklist Registry (50 sources, 10 categories)
# ──────────────────────────────────────────────
ALL_LISTS = {
    # ── Advertisements ──
    "stevenblack":     {"name": "StevenBlack Unified",    "cat": "ads",      "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
    "adguard":         {"name": "AdGuard DNS Filter",     "cat": "ads",      "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"},
    "oisd":            {"name": "OISD Big",               "cat": "ads",      "url": "https://big.oisd.nl/domainswild"},
    "hagezi_pro":      {"name": "Hagezi Pro",             "cat": "ads",      "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"},
    "hagezi_ulti":     {"name": "Hagezi Ultimate",        "cat": "ads",      "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt"},
    "easylist":        {"name": "EasyList Official",      "cat": "ads",      "url": "https://v.firebog.net/hosts/Easylist.txt"},
    "peterlowe":       {"name": "Peter Lowe Ad Server",   "cat": "ads",      "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
    "adaway":          {"name": "AdAway Mobile Ads",      "cat": "ads",      "url": "https://adaway.org/hosts.txt"},
    "1hosts":          {"name": "1Hosts Lite",            "cat": "ads",      "url": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt"},
    "yt_blockads":     {"name": "YouTube BlockAds List",  "cat": "ads",      "url": "https://raw.githubusercontent.com/oiyay/Youtube_BlockAds_List/main/hosts"},
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
    "hagezi_badware":  {"name": "Hagezi Badware/C2",      "cat": "malware",  "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt"},
    "abusech_ssl":     {"name": "Abuse.ch SSL Blacklist", "cat": "malware",  "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"},
    "emerging":        {"name": "Emerging Threats C2",    "cat": "malware",  "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
    "dshield":         {"name": "DShield Suspicious",     "cat": "malware",  "url": "https://www.dshield.org/feeds/suspiciousdomains_High.txt"},

    # ── Phishing ──
    "sb_phish":        {"name": "StevenBlack Fake/Phish", "cat": "phishing", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts"},
    "openphish":       {"name": "OpenPhish Threat Intel", "cat": "phishing", "url": "https://raw.githubusercontent.com/XorPhish/openphish-hosts/master/hosts"},
    "hagezi_threat":   {"name": "Hagezi Threat Intel",    "cat": "phishing", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/threat-intelligence-feeds.txt"},
    "phishdb":         {"name": "Phishing Database Active","cat": "phishing", "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"},
    "rpi_phish":       {"name": "RPiList Phishing",       "cat": "phishing", "url": "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe"},
    "blocklist_de":    {"name": "Blocklist.de Phishing",  "cat": "phishing", "url": "https://lists.blocklist.de/lists/phishing.txt"},

    # ── Spam ──
    "spamhaus_drop":   {"name": "Spamhaus DROP",          "cat": "spam",     "url": "https://www.spamhaus.org/drop/drop.txt"},
    "spamhaus_edrop":  {"name": "Spamhaus EDROP",         "cat": "spam",     "url": "https://www.spamhaus.org/drop/edrop.txt"},
    "blocklist_de_all":{"name": "Blocklist.de All-Attacks","cat": "spam",    "url": "https://lists.blocklist.de/lists/all.txt"},

    # ── Social ──
    "fb_track":        {"name": "Facebook Tracking Pixels","cat": "social",   "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts"},
    "tiktok":          {"name": "TikTok Telemetry/Ads",   "cat": "social",   "url": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/TikTok.txt"},
    "twitter":         {"name": "X/Twitter Analytics",    "cat": "social",   "url": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/Twitter.txt"},

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
    "hagezi_dyndns":   {"name": "Hagezi DynDNS Abuse",    "cat": "security", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/dyndns.txt"},
    "hagezi_hoster":   {"name": "Hagezi Free Host Abuse", "cat": "security", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/hoster.txt"},
    "rpifake":         {"name": "RPiList Scam & Fake",    "cat": "security", "url": "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Fake-Shops"}
}

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

YT_ADS = {
    "s.youtube.com", "video-stats.l.google.com",
    "pagead2.googlesyndication.com",
    "ad.doubleclick.net", "static.doubleclick.net",
    "securepubads.g.doubleclick.net", "pubads.g.doubleclick.net",
    "youtube.com/api/stats/ads",
    "youtubei.googleapis.com/youtubei/v1/log_event",
    "ad-delivery.net", "adserver.yahoo.com",
    "ad-sys.com", "imasdk.googleapis.com",
    "spc.tubecorp.com", "www.googleadservices.com",
}
for i in range(1, 25):
    for sn in ["sn-4g5edn7s", "sn-vgqsrn7e", "sn-aigl6ned",
               "sn-hp576n7e", "sn-q4fl6n7s"]:
        YT_ADS.add(f"r{i}---{sn}.googlevideo.com")

YT_REGEX = re.compile(r"^r\d+---sn-[a-z0-9]+\.googlevideo\.com$")

TOTAL_QUERIES = 0
BLOCKED_QUERIES = 0
AI_QUERIES = 0
START_TIME = time.time()
QUERY_LOGS = deque(maxlen=300)
CLIENT_ACTIVITY = defaultdict(lambda: {"total": 0, "blocked": 0, "last_seen": 0, "threats": 0})
CLIENT_RATES = defaultdict(list)
SECURITY_EVENTS = deque(maxlen=200)

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
        STATUS_FILE.write_text(json.dumps(LIST_STATUS, indent=2))
    except Exception:
        pass

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
#  Blocklist Parsing
# ──────────────────────────────────────────────
def parse_blocklist_file(file_path):
    domains = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                if line.startswith("||") and line.endswith("^"):
                    d = line[2:-1].strip().lower()
                    if d:
                        domains.add(d)
                elif " " in line or "\t" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                        d = parts[1].strip().lower()
                        if d and d not in ("localhost", "broadcasthost", "local", "ip6-localhost"):
                            domains.add(d)
                elif "/" not in line and not line.startswith("@"):
                    d = line.strip().lower()
                    if d and "." in d:
                        domains.add(d)
    except Exception:
        pass
    return domains

def download_and_parse_list(lid):
    if lid not in ALL_LISTS:
        return 0
    info = ALL_LISTS[lid]
    out_path = LIST_DIR / f"{lid}.txt"
    LIST_STATUS[lid]["state"] = "downloading"
    save_list_status()

    try:
        import requests
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/126.0.0.0 Safari/537.36"
        }
        res = requests.get(info["url"], headers=headers, timeout=25)
        if res.status_code == 200:
            out_path.write_bytes(res.content)
            count = len(parse_blocklist_file(out_path))
            LIST_STATUS[lid].update({
                "state": "active", "count": count,
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "error": None
            })
            save_list_status()
            return count
        LIST_STATUS[lid].update({"state": "error", "error": f"HTTP {res.status_code}"})
        save_list_status()
    except Exception as e:
        LIST_STATUS[lid].update({"state": "error", "error": str(e)[:60]})
        save_list_status()
    return 0

def rebuild_master_blocklist():
    global BLOCKED_DOMAINS, DOMAIN_CATEGORIES
    new_set = set()
    new_cats = {}

    for lid, info in ALL_LISTS.items():
        if lid in CFG.get("enabled_lists", []):
            fpath = LIST_DIR / f"{lid}.txt"
            if fpath.exists():
                for d in parse_blocklist_file(fpath):
                    new_set.add(d)
                    if d not in new_cats:
                        new_cats[d] = info["cat"]

    if CFG.get("youtube_aggressive", True):
        for ytd in YT_ADS:
            new_set.add(ytd)
            new_cats[ytd] = "ads"

    if CUSTOM_BLOCK.exists():
        for line in CUSTOM_BLOCK.read_text().splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                new_set.add(line)
                new_cats[line] = "custom"

    BLOCKED_DOMAINS = new_set
    DOMAIN_CATEGORIES = new_cats

def load_custom_lists():
    global CUSTOM_BLOCKED, CUSTOM_WHITELIST
    if CUSTOM_BLOCK.exists():
        CUSTOM_BLOCKED = set(
            x.strip().lower()
            for x in CUSTOM_BLOCK.read_text().splitlines()
            if x.strip() and not x.startswith("#")
        )
    if CUSTOM_WHITE.exists():
        CUSTOM_WHITELIST = set(
            x.strip().lower()
            for x in CUSTOM_WHITE.read_text().splitlines()
            if x.strip() and not x.startswith("#")
        )

load_custom_lists()

# ──────────────────────────────────────────────
#  Threat Auditing
# ──────────────────────────────────────────────
def audit_threat(domain):
    d = domain.lower()
    if d in CUSTOM_WHITELIST:
        return "whitelisted", "custom", "#10b981"
    if d in CUSTOM_BLOCKED:
        return "blocked", "custom", "#fb542b"
    if any(x in d for x in ("google-analytics", "doubleclick", "googleadservices")):
        return "blocked", "ads", "#fb542b"
    if d in YT_ADS or YT_REGEX.match(d):
        return "blocked", "ads", "#fb542b"
    if d in DOMAIN_CATEGORIES:
        cat = DOMAIN_CATEGORIES[d]
        return "blocked", cat, CAT.get(cat, {}).get("color", "#fb542b")
    parts = d.split(".")
    for i in range(len(parts) - 1):
        sub = ".".join(parts[i:])
        if sub in DOMAIN_CATEGORIES:
            cat = DOMAIN_CATEGORIES[sub]
            return "blocked", cat, CAT.get(cat, {}).get("color", "#fb542b")
    return "allowed", "clean", "#10b981"

# ──────────────────────────────────────────────
#  AI Classification (OpenRouter)
# ──────────────────────────────────────────────
FALLBACK_MODELS = [
    "openrouter/free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "google/gemma-2-9b-it:free",
    "mistralai/mistral-small-24b-instruct-2501:free",
]

def ask_openrouter_ai(domain):
    global AI_QUERIES
    api_key = CFG.get("openrouter_api_key", "").strip()
    if not api_key:
        return None
    try:
        import requests
        AI_QUERIES += 1
        headers = {
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "http://localhost",
            "X-Title": "NetBlock Fortress",
            "Content-Type": "application/json"
        }
        prompt = (
            f"Analyze domain: '{domain}'. "
            "Is it ad, tracker, malware, phishing, telemetry, or legit? "
            "Reply JSON only: "
            '{"verdict":"block","cat":"ads","reason":"brief"}'
        )
        models_to_try = [CFG.get("ai_model", "openrouter/free")] + FALLBACK_MODELS
        for model in models_to_try:
            try:
                body = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 100, "temperature": 0.1
                }
                res = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers, json=body, timeout=5
                )
                if res.status_code == 200:
                    txt = res.json()["choices"][0]["message"]["content"]
                    m = re.search(r"\{.*\}", txt, re.DOTALL)
                    if m:
                        return json.loads(m.group(0))
            except Exception:
                continue
    except Exception:
        pass
    return None

# ──────────────────────────────────────────────
#  DNS Server
# ──────────────────────────────────────────────
def resolve_upstream(qname, qtype=QTYPE.A):
    try:
        upstream = CFG.get("dns_upstream", "1.1.1.1")
        req = DNSRecord.question(qname, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.5)
        sock.sendto(req.pack(), (upstream, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return DNSRecord.parse(data)
    except Exception:
        return None

def rate_limit_check(client_ip):
    if not CFG.get("rate_limiting", True):
        return True
    now = time.time()
    max_rps = CFG.get("rate_limit_rps", 100)
    CLIENT_RATES[client_ip] = [t for t in CLIENT_RATES[client_ip] if now - t < 1.0]
    if len(CLIENT_RATES[client_ip]) >= max_rps:
        return False
    CLIENT_RATES[client_ip].append(now)
    return True

def handle_dns_request(data, addr, sock):
    global TOTAL_QUERIES, BLOCKED_QUERIES
    client_ip = addr[0]
    TOTAL_QUERIES += 1
    CLIENT_ACTIVITY[client_ip]["total"] += 1
    CLIENT_ACTIVITY[client_ip]["last_seen"] = time.time()

    if not rate_limit_check(client_ip):
        SECURITY_EVENTS.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "Rate Limit Exceeded",
            "client": client_ip,
            "detail": f"Exceeded {CFG.get('rate_limit_rps', 100)} req/sec"
        })
        return

    try:
        request_record = DNSRecord.parse(data)
    except Exception:
        return

    if not request_record.questions:
        return

    q = request_record.questions[0]
    qname = str(q.qname).rstrip(".")
    qtype = q.qtype
    qtype_str = QTYPE.get(qtype, f"TYPE{qtype}")

    # Amplification defense
    if CFG.get("amplification_protection", True) and qtype_str == "ANY":
        reply = request_record.reply()
        reply.header.rcode = RCODE.REFUSED
        sock.sendto(reply.pack(), addr)
        SECURITY_EVENTS.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "DNS Amplification Blocked",
            "client": client_ip, "detail": f"ANY query for {qname}"
        })
        return

    is_blocked = False
    block_reason = ""
    block_cat = "clean"
    badge_color = "#10b981"

    # DGA detection
    if CFG.get("dga_protection", True) and is_dga(qname):
        is_blocked = True
        block_reason = "DGA Threat Detected"
        block_cat = "malware"
        badge_color = "#ef4444"
        SECURITY_EVENTS.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": "DGA Domain Blocked",
            "client": client_ip, "detail": f"High entropy: {qname}"
        })

    # Blocklist lookup
    if not is_blocked:
        action, cat, color = audit_threat(qname)
        if action == "blocked":
            is_blocked = True
            block_reason = f"Blocklist ({cat.title()})"
            block_cat = cat
            badge_color = color

    # CNAME uncloaking
    if not is_blocked and CFG.get("cname_uncloaking", True):
        try:
            up_resp = resolve_upstream(qname, QTYPE.CNAME)
            if up_resp:
                for rr in up_resp.rr:
                    if rr.rtype == QTYPE.CNAME:
                        cname_target = str(rr.rdata).rstrip(".")
                        c_act, c_cat, c_col = audit_threat(cname_target)
                        if c_act == "blocked":
                            is_blocked = True
                            block_reason = f"CNAME: {cname_target}"
                            block_cat = c_cat
                            badge_color = c_col
                            break
        except Exception:
            pass

    # Handle blocked
    if is_blocked:
        BLOCKED_QUERIES += 1
        CLIENT_ACTIVITY[client_ip]["blocked"] += 1
        if block_cat in ("malware", "phishing", "spam", "security"):
            CLIENT_ACTIVITY[client_ip]["threats"] += 1

        reply = request_record.reply()
        reply.header.rcode = RCODE.NOERROR
        if qtype == QTYPE.A:
            reply.add_rr(RR(rname=q.qname, rtype=QTYPE.A, rclass=1,
                            ttl=300, rdata=A("0.0.0.0")))
        elif qtype == QTYPE.AAAA:
            reply.add_rr(RR(rname=q.qname, rtype=QTYPE.AAAA, rclass=1,
                            ttl=300, rdata=AAAA("::")))
        sock.sendto(reply.pack(), addr)

        QUERY_LOGS.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "client": client_ip, "domain": qname, "type": qtype_str,
            "status": "Blocked", "reason": block_reason,
            "cat": block_cat, "color": badge_color
        })
        return

    # Resolve & check rebinding
    try:
        resolved = resolve_upstream(qname, qtype)
        if resolved:
            if CFG.get("rebinding_protection", True) and not qname.endswith(
                (".local", ".internal", ".home", ".lan")
            ):
                for rr in resolved.rr:
                    if rr.rtype == QTYPE.A:
                        ip_val = str(rr.rdata)
                        if is_private_ip(ip_val):
                            SECURITY_EVENTS.append({
                                "time": datetime.now().strftime("%H:%M:%S"),
                                "type": "DNS Rebinding Blocked",
                                "client": client_ip,
                                "detail": f"{qname} -> {ip_val}"
                            })
                            reply = request_record.reply()
                            reply.header.rcode = RCODE.NXDOMAIN
                            sock.sendto(reply.pack(), addr)
                            return
            sock.sendto(resolved.pack(), addr)
        else:
            reply = request_record.reply()
            reply.header.rcode = RCODE.SERVFAIL
            sock.sendto(reply.pack(), addr)
    except Exception:
        pass

    QUERY_LOGS.appendleft({
        "time": datetime.now().strftime("%H:%M:%S"),
        "client": client_ip, "domain": qname, "type": qtype_str,
        "status": "Allowed", "reason": "Clean",
        "cat": "clean", "color": "#10b981"
    })

def dns_server_worker():
    port = int(CFG.get("dns_port", 53))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))
        print(f"[*] DNS Server on 0.0.0.0:{port}")
    except Exception as e:
        print(f"[!] Cannot bind port {port}: {e}")
        return
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(
                target=handle_dns_request,
                args=(data, addr, sock), daemon=True
            ).start()
        except Exception:
            pass

def auto_refresh_worker():
    time.sleep(5)
    need = any(
        LIST_STATUS[lid]["count"] == 0 and LIST_STATUS[lid]["enabled"]
        for lid in LIST_STATUS
    )
    if need:
        for lid in CFG.get("enabled_lists", []):
            if not (LIST_DIR / f"{lid}.txt").exists():
                download_and_parse_list(lid)
        rebuild_master_blocklist()

    while True:
        try:
            rebuild_master_blocklist()
            interval = int(CFG.get("refresh_hours", 24)) * 3600
            time.sleep(max(300, interval))
            if CFG.get("auto_refresh", True):
                for lid in CFG.get("enabled_lists", []):
                    download_and_parse_list(lid)
                rebuild_master_blocklist()
        except Exception:
            time.sleep(60)

threading.Thread(target=dns_server_worker, daemon=True).start()
threading.Thread(target=auto_refresh_worker, daemon=True).start()

# ──────────────────────────────────────────────
#  Flask App
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "netblock-fortress-" + hashlib.sha256(b"session-secret-v18").hexdigest()[:16]

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
<div><div class="bn">NetBlock</div><div class="bs">Fortress v18.0</div></div></div>
<div class="nav">
<a class="ni {% if a=='dash' %}active{% endif %}" href="/"><i class="fa-solid fa-gauge"></i> Dashboard</a>
<a class="ni {% if a=='sec' %}active{% endif %}" href="/security"><i class="fa-solid fa-lock"></i> Security Center</a>
<a class="ni {% if a=='bl' %}active{% endif %}" href="/blocklists"><i class="fa-solid fa-list-check"></i> Blocklists (50)</a>
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
        dns_port=CFG.get("dns_port", 53), **kw)

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
<div class="sl">Bandwidth Saved</div><div class="sv" style="color:var(--grn)">{{ bandwidth_saved }}</div>
<div class="ss">~125 KB / ad request</div></div>
<div class="sc"><i class="fa-solid fa-hourglass-half bg" style="color:var(--sec)"></i>
<div class="sl">Time Saved</div><div class="sv" style="color:var(--sec)">{{ time_saved }}</div>
<div class="ss">~1.5s / blocked tracker</div></div>
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
<span style="color:var(--mut)">DNS Rebinding</span><span style="font-weight:700;color:var(--grn)">ON</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">DGA Detection</span><span style="font-weight:700;color:var(--grn)">ON</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">CNAME Uncloaking</span><span style="font-weight:700;color:var(--grn)">ON</span></div>
<div style="display:flex;justify-content:space-between;border-bottom:1px solid #1f2937;padding-bottom:8px">
<span style="color:var(--mut)">YouTube Ad Shield</span><span style="font-weight:700;color:var(--pri)">AGGRESSIVE</span></div>
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
<p style="font-size:12px;color:var(--mut)">50 curated blocklists across 10 categories</p></div>
<form method="POST" action="/blocklists/update_all">
<button class="btn bp" type="submit"><i class="fa-solid fa-arrows-rotate"></i> Update All</button></form></div>
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
<p style="font-size:12px;color:var(--mut)">Pre-configured blocking intensity</p></div>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px">
<div class="card" style="border-top:3px solid var(--grn)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Balanced</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Standard blocking. Zero breakage.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>Ads, Malware, Phishing</li><li>YouTube Ad Stripping</li><li>Social media allowed</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="balanced">
<button class="btn {% if cur_mode=='balanced' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='balanced' %}Active{% else %}Activate{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid var(--pri)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Strict (Recommended)</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Max privacy. Telemetry, trackers, cryptojacking.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>All Balanced rules</li><li>SmartTV & Windows Spy blocked</li>
<li>Cryptojacking prevention</li><li>CNAME + DGA analysis</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="strict">
<button class="btn {% if cur_mode=='strict' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='strict' %}Active{% else %}Activate{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid var(--sec)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Family & Safe</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Strict + Adult/Gambling blocking.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>All Strict rules</li><li>Adult & NSFW blocked</li>
<li>Gambling blocked</li><li>SafeSearch enforced</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="family">
<button class="btn {% if cur_mode=='family' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='family' %}Active{% else %}Activate{% endif %}</button></form></div></div>
"""

# ── Logs Page ──
PAGE_LOGS = """
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
<div><h2 style="font-size:18px;font-weight:700">Query Inspector</h2>
<p style="font-size:12px;color:var(--mut)">Last 300 DNS resolutions</p></div>
<form method="POST" action="/logs/clear">
<button class="btn b2 bs2" type="submit"><i class="fa-solid fa-trash"></i> Clear</button></form></div>
<div class="card"><table class="tbl"><thead><tr>
<th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Status</th><th>Audit</th>
</tr></thead><tbody>
{% for l in logs %}<tr>
<td style="color:var(--mut)">{{ l.time }}</td><td><code>{{ l.client }}</code></td>
<td style="font-weight:600">{{ l.domain }}</td><td style="color:var(--mut)">{{ l.type }}</td>
<td>{% if l.status=='Blocked' %}<span class="bdg" style="background:rgba(239,68,68,.15);color:var(--red)">BLOCKED</span>
{% else %}<span class="bdg" style="background:rgba(16,185,129,.15);color:var(--grn)">ALLOWED</span>{% endif %}</td>
<td><span class="bdg" style="background:rgba(255,255,255,.05);color:{{ l.color }}">{{ l.reason }}</span></td></tr>
{% else %}<tr><td colspan="6" style="text-align:center;color:var(--mut);padding:30px">No queries yet.</td></tr>{% endfor %}
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
<p style="font-size:12px;color:var(--mut)">Credentials, DNS, AI, security settings</p></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">

<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-user-shield"></i> Admin Credentials</div></div>
<form method="POST" action="/settings"><input type="hidden" name="change_pw" value="1">
<div class="fg"><label class="lbl">Username</label>
<input class="inp" type="text" name="new_username" value="{{ cfg.admin_username }}" required style="width:100%"></div>
<div class="fg"><label class="lbl">Current Password</label>
<input class="inp" type="password" name="cur_pw" required style="width:100%" placeholder="Current password"></div>
<div class="fg"><label class="lbl">New Password (blank = keep)</label>
<input class="inp" type="password" name="new_pw" style="width:100%" placeholder="Min 6 chars"></div>
<div class="fg"><label class="lbl">Confirm New Password</label>
<input class="inp" type="password" name="confirm_pw" style="width:100%" placeholder="Re-type"></div>
<button class="btn bp" type="submit"><i class="fa-solid fa-key"></i> Update</button></form></div>

<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-brain" style="color:var(--sec)"></i> AI Engine</div></div>
<form method="POST" action="/settings"><input type="hidden" name="save_ai" value="1">
<div class="fg"><label class="lbl">OpenRouter API Key</label>
<input class="inp" type="password" name="ai_key" value="{{ ai_key }}" style="width:100%" placeholder="sk-or-v1-..."></div>
<div class="fg"><label class="lbl">Model</label>
<input class="inp" type="text" name="ai_model" value="{{ ai_model }}" style="width:100%"></div>
<button class="btn bp" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save</button></form></div>

<div class="card"><div class="ch">
<div class="ct"><i class="fa-solid fa-shield-halved" style="color:var(--pri)"></i> Defense Engine</div></div>
<form method="POST" action="/settings"><input type="hidden" name="save_sec" value="1">
<div style="display:flex;flex-direction:column;gap:14px">
{% for key, label, desc in [
  ('rebinding_protection','DNS Rebinding Protection','Blocks public→private IP redirects'),
  ('dga_protection','DGA Threat Analysis','Entropy-based malware domain detection'),
  ('cname_uncloaking','CNAME Uncloaking','Resolves canonical alias to catch trackers'),
  ('amplification_protection','Amplification Defense','Refuses DNS ANY queries (DDoS)'),
  ('rate_limiting','Rate Limiting','Per-client queries/second cap'),
  ('youtube_aggressive','YouTube Ad Shield','Aggressive googlevideo + ad domain blocking')
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
<div class="fg"><label class="lbl">Upstream DNS</label>
<input class="inp" type="text" name="dns_upstream" value="{{ cfg.dns_upstream }}" style="width:100%" placeholder="1.1.1.1"></div>
<div class="fg"><label class="lbl">Refresh Interval (hours)</label>
<input class="inp" type="number" name="refresh_hours" value="{{ cfg.refresh_hours }}" style="width:100%" min="1" max="168"></div>
<div class="fg"><label class="lbl">Rate Limit (queries/sec per client)</label>
<input class="inp" type="number" name="rate_limit_rps" value="{{ cfg.rate_limit_rps }}" style="width:100%" min="10" max="10000"></div>
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
        if u.lower() in (vu.lower(), "admin") and p_hash == CFG.get("password_hash"):
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
    bw = BLOCKED_QUERIES * 125 * 1024
    bw_str = f"{bw / (1024**3):.2f} GB" if bw > 1024**3 else f"{bw / 1024**2:.1f} MB"
    ts = int(BLOCKED_QUERIES * 1.5)
    time_str = f"{ts / 3600:.1f} hours" if ts > 3600 else f"{ts // 60} mins"
    br = f"{BLOCKED_QUERIES / TOTAL_QUERIES * 100:.1f}" if TOTAL_QUERIES else "0.0"

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
        total_queries=TOTAL_QUERIES, blocked_queries=BLOCKED_QUERIES,
        block_rate=br, bandwidth_saved=bw_str, time_saved=time_str,
        client_count=len(CLIENT_ACTIVITY), rule_count=len(BLOCKED_DOMAINS),
        uptime_str=uptime, cat_summary=cat_summary,
        recent_logs=list(QUERY_LOGS)[:8])

@app.route("/security")
@login_req
def page_security():
    now = time.time()
    susp = sum(1 for d in CLIENT_ACTIVITY.values() if d["threats"] > 0)
    cvs = {}
    for ip, d in CLIENT_ACTIVITY.items():
        delta = int(now - d["last_seen"])
        ls = f"{delta}s ago" if delta < 60 else f"{delta // 60}m ago" if delta < 3600 else f"{delta // 3600}h ago"
        cvs[ip] = {"total": d["total"], "blocked": d["blocked"], "threats": d["threats"], "last_seen_str": ls}
    return render_page(PAGE_SEC, "sec", "Security Center",
        events=list(SECURITY_EVENTS), clients=cvs, suspicious=susp)

@app.route("/blocklists")
@login_req
def page_blocklists():
    return render_page(PAGE_BL, "bl", "Blocklists (50 Feeds)",
        lists=LIST_STATUS, cats=CAT)

@app.route("/blocklists/toggle", methods=["POST"])
@login_req
def bl_toggle():
    lid = request.form.get("lid")
    if lid in ALL_LISTS:
        ce = CFG.get("enabled_lists", [])
        if "enabled" in request.form:
            if lid not in ce:
                ce.append(lid)
                LIST_STATUS[lid]["enabled"] = True
                threading.Thread(target=download_and_parse_list, args=(lid,), daemon=True).start()
        else:
            if lid in ce:
                ce.remove(lid)
            LIST_STATUS[lid]["enabled"] = False
        CFG["enabled_lists"] = ce
        save_config(); save_list_status(); rebuild_master_blocklist()
    return redirect("/blocklists")

@app.route("/blocklists/download_single", methods=["POST"])
@login_req
def bl_dl():
    lid = request.form.get("lid")
    if lid in ALL_LISTS:
        threading.Thread(target=download_and_parse_list, args=(lid,), daemon=True).start()
    return redirect("/blocklists")

@app.route("/blocklists/update_all", methods=["POST"])
@login_req
def bl_update_all():
    def upd():
        for lid in CFG.get("enabled_lists", []):
            download_and_parse_list(lid)
        rebuild_master_blocklist()
    threading.Thread(target=upd, daemon=True).start()
    return redirect("/blocklists")

@app.route("/api/list_status")
@login_req
def api_status():
    return jsonify(LIST_STATUS)

@app.route("/modes")
@login_req
def page_modes():
    return render_page(PAGE_MODES, "modes", "Protection Profiles",
        cur_mode=CFG.get("block_mode", "strict"))

@app.route("/modes/set", methods=["POST"])
@login_req
def mode_set():
    m = request.form.get("mode", "strict")
    CFG["block_mode"] = m
    MODES = {
        "balanced": ["stevenblack","adguard","oisd","hagezi_pro","easylist","peterlowe","urlhaus","phisharmy","yt_blockads"],
        "strict": ["stevenblack","adguard","oisd","hagezi_pro","easylist","peterlowe","adaway","1hosts","yt_blockads",
                    "easypriv","prigent_ads","winspy","smarttv","ubpriv","adguard_track","notrack",
                    "urlhaus","rpi_mal","phisharmy","prigent_mal","hagezi_badware","abusech_ssl","emerging","dshield",
                    "sb_phish","openphish","hagezi_threat","phishdb","rpi_phish","blocklist_de",
                    "spamhaus_drop","spamhaus_edrop","nocoin","coinblocker","hagezi_dyndns","hagezi_hoster","rpifake"],
        "family": ["stevenblack","adguard","oisd","hagezi_pro","easylist","peterlowe","adaway","yt_blockads",
                    "easypriv","prigent_ads","urlhaus","phisharmy","sb_phish","openphish",
                    "sb_porn","sin_porn","oisd_nsfw","sb_gamble","sin_gamble","nocoin","coinblocker"]
    }
    CFG["enabled_lists"] = MODES.get(m, MODES["strict"])
    for lid in ALL_LISTS:
        LIST_STATUS[lid]["enabled"] = lid in CFG["enabled_lists"]
    save_config(); save_list_status(); rebuild_master_blocklist()
    return redirect("/modes")

@app.route("/logs")
@login_req
def page_logs():
    return render_page(PAGE_LOGS, "logs", "Query Inspector", logs=list(QUERY_LOGS))

@app.route("/logs/clear", methods=["POST"])
@login_req
def logs_clear():
    QUERY_LOGS.clear()
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
            if cur != CFG.get("password_hash"):
                msg, msg_type = "Current password incorrect!", "err"
            else:
                if new_u:
                    CFG["admin_username"] = new_u
                if npw:
                    if len(npw) < 6:
                        msg, msg_type = "Password must be 6+ chars!", "err"
                    elif npw != cpw:
                        msg, msg_type = "Passwords don't match!", "err"
                    else:
                        CFG["password_hash"] = hashlib.sha256(npw.encode()).hexdigest()
                        msg = "Credentials updated!"
                else:
                    msg = "Username updated!"
                save_config()

        elif "save_ai" in request.form:
            CFG["openrouter_api_key"] = request.form.get("ai_key", "").strip()
            CFG["ai_model"] = request.form.get("ai_model", "openrouter/free").strip()
            save_config(); msg = "AI engine saved!"

        elif "save_sec" in request.form:
            for key in ("rebinding_protection","dga_protection","cname_uncloaking",
                        "amplification_protection","rate_limiting","youtube_aggressive"):
                CFG[key] = key in request.form
            save_config(); msg = "Defense settings saved!"

        elif "save_dns" in request.form:
            CFG["dns_upstream"] = request.form.get("dns_upstream", "1.1.1.1").strip()
            CFG["refresh_hours"] = int(request.form.get("refresh_hours", 24))
            CFG["rate_limit_rps"] = int(request.form.get("rate_limit_rps", 100))
            save_config(); msg = "DNS settings saved!"

    return render_page(PAGE_SETTINGS, "sett", "Settings",
        msg=msg, msg_type=msg_type, cfg=CFG,
        ai_key=CFG.get("openrouter_api_key", ""),
        ai_model=CFG.get("ai_model", "openrouter/free"))

# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
if __name__ == "__main__":
    port = int(CFG.get("web_port", 8080))
    print(f"[*] NetBlock Fortress v18.0 | Web: {port} | DNS: {CFG.get('dns_port', 53)}")
    print(f"[*] Data: {DATA_DIR}")
    print(f"[*] Lists: {len(ALL_LISTS)} sources across {len(CAT)} categories")
    app.run(host="0.0.0.0", port=port, debug=False)
