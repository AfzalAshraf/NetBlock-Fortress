#!/usr/bin/env python3
"""
NetBlock Fortress "Omni-Shield" v19.0 - network-wide micro & macro ad shield.

Single-file application: authoritative DNS sinkhole + ad-creative sinkhole
server + threat-intelligence web dashboard.  Runs on any Linux/macOS box with
Python 3.8+ and is driven by the `adquit` command-line tool.

  110+ blocklist feeds | 20 categories | 14 ad vectors (micro + macro)
  wildcard engine | ad-subdomain pattern engine | CNAME uncloaking
  DGA + entropy defence | DNS-rebinding guard | DoH upstream | response cache
  zero-pixel creative sinkhole | YouTube / in-video ad stripping | AI triage

CLI (also usable directly, no `adquit` needed):
  python3 app.py --stats            python3 app.py --block doubleclick.net
  python3 app.py --mode strict      python3 app.py --update-lists
"""

import sys
import os
import re
import time
import math
import json
import gzip
import hmac
import socket
import pickle
import hashlib
import logging
import threading
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor

VERSION = "19.1"
CODENAME = "Omni-Shield"
CONFIG_VERSION = 19
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 NetBlockFortress/" + VERSION
)

# ──────────────────────────────────────────────
#  Dependencies (auto-install once, then never again)
# ──────────────────────────────────────────────
REQUIRED_PACKAGES = ["flask", "requests", "dnslib"]


def _ensure_packages():
    if os.environ.get("ADQUIT_NO_PIP") == "1":
        return
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    print("[*] Installing missing Python packages: %s" % ", ".join(missing))
    cmds = [
        [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade"] + missing,
        [sys.executable, "-m", "pip", "install", "--quiet", "--user"] + missing,
        [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages"] + missing,
    ]
    for cmd in cmds:
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception:
            continue
    print("[!] Could not install %s automatically." % ", ".join(missing))
    print("    Run: sudo python3 -m pip install %s" % " ".join(missing))
    sys.exit(1)


_ensure_packages()

# ─────────────────────────────────────────────────────────────────────────────
#  Dependency gate.
#  flask/requests/dnslib are required to *serve* traffic, but a box whose venv
#  was removed (or a `python3 app.py` run outside the installer) must still be
#  able to answer --version / --help and, most usefully, --doctor - with
#  instructions rather than a ModuleNotFoundError traceback.
# ─────────────────────────────────────────────────────────────────────────────
def _missing_packages():
    """Packages the fortress needs but cannot load. A partially removed venv can
    make the import machinery raise instead of reporting absence, so a broken
    finder counts as 'missing' - the gate below explains it, a traceback would not."""
    import importlib.util
    out = []
    for pkg in REQUIRED_PACKAGES:
        try:
            if importlib.util.find_spec(pkg) is None:
                out.append(pkg)
        except Exception:
            out.append(pkg)
    return out


def _dependency_instructions(missing):
    return ("[!] NetBlock Fortress needs the Python package(s): %s\n"
            "    Recommended - the one-command installer (private venv, service, CLI):\n"
            "        curl -fsSL https://raw.githubusercontent.com/AfzalAshraf/NetBlock-Fortress/main/install.sh | sudo bash\n"
            "    Or just the packages:\n"
            "        python3 -m pip install %s\n"
            "    Or, from a checkout:  ./install.sh   (rootless: ADQUIT_USER=1 ./install.sh)"
            % (", ".join(missing), " ".join(missing)))


def _offline_doctor(missing):
    """Minimal health report for an install whose dependencies are broken."""
    home = os.environ.get("ADQUIT_HOME") or os.environ.get("NETBLOCK_HOME")
    if not home:
        home = "/opt/adquit" if os.geteuid() == 0 else os.path.expanduser("~/.adquit")
    cfg_path = os.path.join(home, "data", "config.json")
    print("NetBlock Fortress %s - offline doctor (full checks need %s)"
          % (VERSION, ", ".join(missing)))
    print("  python     %s (%s)" % (sys.version.split()[0], sys.executable))
    print("  home       %s%s" % (home, "" if os.access(home, os.W_OK) else "  [not writable]"))
    print("  config     %s" % (cfg_path if os.path.isfile(cfg_path) else cfg_path + "  [missing - not installed?]"))
    for pkg in REQUIRED_PACKAGES:
        print("  package    %-9s %s" % (pkg, "MISSING" if pkg in missing else "ok"))
    ports = {}
    try:
        with open(cfg_path) as fh:
            cfg = json.load(fh)
        ports = {"dns_port": cfg.get("dns_port", 53), "web_port": cfg.get("web_port", 8080)}
    except Exception:
        pass
    for label, port in (("dns", ports.get("dns_port")), ("web", ports.get("web_port"))):
        if not port:
            continue
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.4)
        listening = probe.connect_ex(("127.0.0.1", int(port))) == 0
        probe.close()
        print("  %-11s :%s %s" % (label + " port", port, "answered" if listening else "nothing listening"))
    if not os.path.isfile(os.path.join(home, "app.py")):
        print("  app.py     %s  [missing - run the installer]" % os.path.join(home, "app.py"))
    print()
    print(_dependency_instructions(missing))


_MISSING = _missing_packages()
if _MISSING:
    _first = sys.argv[1] if len(sys.argv) > 1 else ""
    if _first in ("--version", "-v"):
        print("NetBlock Fortress %s (%s) - installed without its Python deps (%s)"
              % (VERSION, CODENAME, ", ".join(_MISSING)))
        sys.exit(0)
    if _first in ("--help", "-h"):
        print(__doc__.strip())
        print()
        print(_dependency_instructions(_MISSING))
        sys.exit(0)
    if _first in ("--doctor", "doctor", "-D"):
        _offline_doctor(_MISSING)
        sys.exit(1)
    sys.stderr.write(_dependency_instructions(_MISSING) + "\n")
    sys.exit(3)

import requests
from flask import (Flask, request, redirect, session, jsonify,
                   render_template_string, make_response, Response)
from dnslib import DNSRecord, RR, A, AAAA, CNAME, QTYPE, RCODE

# ──────────────────────────────────────────────
#  Paths
# ──────────────────────────────────────────────
BASE_DIR = Path(os.environ.get("ADQUIT_HOME") or os.environ.get("NETBLOCK_HOME")
                or ("/opt/adquit" if os.geteuid() == 0 else str(Path.home() / ".adquit")))
DATA_DIR = BASE_DIR / "data"
LIST_DIR = DATA_DIR / "lists"
META_DIR = DATA_DIR / "meta"
CONFIG_FILE = DATA_DIR / "config.json"
STATUS_FILE = DATA_DIR / "list_status.json"
CUSTOM_BLOCK = DATA_DIR / "custom_blocked.txt"
CUSTOM_WHITE = DATA_DIR / "custom_whitelist.txt"
GRAVITY_CACHE = DATA_DIR / "gravity.cache"
SNAPSHOT_FILE = DATA_DIR / "snapshot.json"
ACCESS_LOG = DATA_DIR / "adquit.log"
QUERY_LOG = DATA_DIR / "queries.jsonl"

for _d in (DATA_DIR, LIST_DIR, META_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print("[!] No write access to %s - rerun with sudo or set ADQUIT_HOME." % BASE_DIR)
        sys.exit(1)


def _setup_logging():
    """Console stays quiet for one-shot CLI calls (so `adquit json | jq` works),
    chatty for the long-running service."""
    quiet_cli = bool(sys.argv[1:]) and sys.argv[1] not in ("--serve", "--daemon", "-d", "run") \
        and sys.argv[1].startswith("-")
    logger = logging.getLogger("adquit")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.WARNING if quiet_cli else logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    try:
        from logging.handlers import RotatingFileHandler
        fh = RotatingFileHandler(str(ACCESS_LOG), maxBytes=4 * 1024 * 1024, backupCount=2)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass
    return logger


LOG = _setup_logging()


def atomic_write(path, text):
    """Write a file crash-safely: unique temp file + atomic rename, with a direct
    write fallback so a filesystem quirk can never cost us the config."""
    path = Path(path)
    tmp = Path("%s.%s.%s.tmp" % (path, os.getpid(), os.urandom(4).hex()))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        os.replace(str(tmp), str(path))
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        try:
            path.write_text(text, encoding="utf-8")
        except Exception as exc:
            LOG.debug("write %s failed: %s", path, exc)


def now_hm():
    return datetime.now().strftime("%H:%M:%S")


# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    # --- access ---
    "admin_username": "admin",
    "password_hash": hashlib.sha256(b"admin123").hexdigest(),
    "api_token": "",
    # --- network ---
    "dns_port": 53,
    "web_port": 8080,
    "dns_upstream": "1.1.1.1",
    "upstream_mode": "auto",          # auto | udp | doh
    "doh_upstream": "https://cloudflare-dns.com/dns-query",
    "dns_workers": 32,
    "block_ttl": 300,
    "cache_ttl": 300,
    "neg_ttl": 60,
    "cache_size": 40000,
    # --- the micro/macro switchboard ---
    "block_mode": "strict",
    "macro_ads": True,                # banners, units, shopping, native placements
    "micro_ads": True,                # pixels, beacons, SDK calls, fingerprinting
    "invideo_ads": True,              # pre/mid-roll + player telemetry
    "ctv_ads": True,                  # smart TV, consoles, set-top boxes
    "push_ads": True,                 # push-notification + popup/interstitial
    "adtech_endpoints": True,         # exchanges / SSP / mediation SDKs
    "email_tracking": True,           # open & click tracking pixels
    "youtube_aggressive": True,       # YouTube ad endpoint stripping
    "safe_search": False,             # force Google/YouTube/Bing safe results
    "wildcard_engine": True,          # *.adnetwork.com style blocking
    "pattern_engine": True,           # ad-infrastructure subdomain heuristics
    "pattern_action": "enforce",      # enforce | shadow (log only)
    "cname_uncloaking": True,         # resolve cloaked first-party aliases
    "rebinding_protection": True,
    "dga_protection": True,
    "typosquat_protection": False,
    "rate_limiting": True,
    "rate_limit_rps": 500,
    "amplification_protection": True,
    "ai_triage": False,               # ask an LLM about unknown domains
    # --- responses ---
    "sinkhole_mode": "zeroip",        # zeroip | nxdomain | fortress
    "sinkhole_ip": "",                # empty = auto-detect outbound IP
    "sinkhole_port": 80,
    "sinkhole_splash": True,
    # --- hygiene ---
    "auto_refresh": True,
    "refresh_hours": 24,
    "log_enabled": True,
    "log_max": 3000,
    "openrouter_api_key": "",
    "ai_model": "openrouter/free",
    "enabled_lists": [],              # filled from registry defaults on first boot
    "custom_lists": {},               # user supplied {"id": {"name","url","cat"}}
    "always_allow": ["netblock.local", "adquit.local"],
}

CFG = dict(DEFAULT_CONFIG)


def _migrate_config(saved):
    """Merge a stored config on top of defaults, keeping the schema current."""
    merged = dict(DEFAULT_CONFIG)
    for k, v in (saved or {}).items():
        if k in merged or k.startswith(("legacy_",)):
            merged[k] = v
    if merged.get("config_version") != CONFIG_VERSION:
        # v18 -> v19 rename map
        renames = {"youtube_ads": "youtube_aggressive", "ai_enabled": "ai_triage",
                   "nxdomain": "sinkhole_mode"}
        for old, new in renames.items():
            if old in (saved or {}):
                merged[new] = saved[old]
        merged["config_version"] = CONFIG_VERSION
    return merged


def load_config():
    global CFG
    if os.environ.get("ADQUIT_PASSWORD"):
        CFG["password_hash"] = hashlib.sha256(
            os.environ["ADQUIT_PASSWORD"].encode()).hexdigest()
    if CONFIG_FILE.exists():
        try:
            CFG = _migrate_config(json.loads(CONFIG_FILE.read_text()))
        except Exception as exc:
            LOG.warning("config unreadable (%s) - using defaults", exc)
    else:
        CFG["config_version"] = CONFIG_VERSION
    if not CFG.get("api_token"):
        import secrets
        CFG["api_token"] = secrets.token_hex(16)
    if not CFG.get("enabled_lists"):
        CFG["enabled_lists"] = list(DEFAULT_ENABLED)
    # env overrides used by docker / adquit --user
    env_map = {"ADQUIT_DNS_PORT": ("dns_port", int), "ADQUIT_WEB_PORT": ("web_port", int),
               "ADQUIT_UPSTREAM": ("dns_upstream", str), "ADQUIT_MODE": ("block_mode", str),
               "ADQUIT_SINKHOLE": ("sinkhole_mode", str)}
    for env, (key, cast) in env_map.items():
        if os.environ.get(env):
            try:
                CFG[key] = cast(os.environ[env])
            except Exception:
                pass
    save_config()


def save_config():
    atomic_write(CONFIG_FILE, json.dumps(CFG, indent=2))


def cfg_bool(key, default=True):
    v = CFG.get(key, default)
    return bool(v) if not isinstance(v, str) else v.lower() not in ("0", "false", "off", "no")

# ──────────────────────────────────────────────
#  Ad vectors: what kind of advertising traffic we kill
#  kind = "macro" (visible ad units) or "micro" (pixels, SDKs, telemetry)
# ──────────────────────────────────────────────
VECTORS = {
    "banner":      {"name": "Display & Banner Ads",      "kind": "macro", "icon": "fa-rectangle-ad",      "color": "#fb542b", "desc": "Ad networks, banners, MPU/leaderboard creatives, ad frames"},
    "video":       {"name": "In-Video & Pre-Roll",       "kind": "macro", "icon": "fa-film",              "color": "#f97316", "desc": "YouTube/Twitch pre, mid & post-roll endpoints, VAST/VMAP tags"},
    "popup":       {"name": "Popups & Interstitials",    "kind": "macro", "icon": "fa-up-right-and-down-left-from-center", "color": "#f59e0b", "desc": "Pop-unders, interstitials, modals, exit offers"},
    "native":      {"name": "Native & Sponsored Units",  "kind": "macro", "icon": "fa-thumbtack",         "color": "#eab308", "desc": "Recommended/sponsored content widgets, in-feed ads"},
    "ctv":         {"name": "Smart TV, Console & OTT",   "kind": "macro", "icon": "fa-tv",                "color": "#84cc16", "desc": "Samsung/LG/Roku/FireTV/Apple TV ad + audit beacons"},
    "push":        {"name": "Push-Notification Ads",     "kind": "macro", "icon": "fa-bell",              "color": "#22c55e", "desc": "Browser push ad gateways (OneSignal-style abuse) & in-app messaging"},
    "shopping":    {"name": "Shopping & Affiliate Ads",  "kind": "macro", "icon": "fa-cart-shopping",     "color": "#14b8a6", "desc": "Product feeds, price comparison, coupon/affiliate injection"},
    "pixel":       {"name": "Ad Pixels & Beacons",       "kind": "micro", "icon": "fa-crosshairs",        "color": "#06b6d4", "desc": "1x1 tracking pixels, impression & conversion beacons"},
    "sdk":         {"name": "In-App Ad SDKs",             "kind": "micro", "icon": "fa-mobile-screen",    "color": "#3b82f6", "desc": "AdMob/Unity/AppLovin/ironSource & mediation SDK traffic"},
    "adx":         {"name": "Exchanges, SSP/DSP & Bidding", "kind": "micro", "icon": "fa-arrow-right-arrow-left", "color": "#6366f1", "desc": "Real-time bidding endpoints, OpenPrebid wrappers, ad servers"},
    "retarget":    {"name": "Retargeting & Audiences",    "kind": "micro", "icon": "fa-bullseye",          "color": "#8b5cf6", "desc": "Audience sync, segments, DMPs, look-alike matching"},
    "fingerprint": {"name": "Device Fingerprinting",      "kind": "micro", "icon": "fa-fingerprint",       "color": "#a855f7", "desc": "Canvas/font/browser fingerprint & device-ID services"},
    "telemetry":   {"name": "Telemetry & Crash Pings",    "kind": "micro", "icon": "fa-satellite-dish",    "color": "#d946ef", "desc": "OS/app analytics, Kinesis/Pendo/Hotjar-style session capture"},
    "email":       {"name": "Email Open & Click Tracking", "kind": "micro", "icon": "fa-envelope-circle-check", "color": "#ec4899", "desc": "Newsletters pixels, rlink/click forwarders, read receipts"},
    "shortlink":   {"name": "Ad Redirectors & Shorteners", "kind": "micro", "icon": "fa-link-slash",       "color": "#f43f5e", "desc": "Trackers hidden in link shorteners & ad cloaking redirects"},
    "malvertising": {"name": "Malvertising & Adware",     "kind": "micro", "icon": "fa-virus",             "color": "#ef4444", "desc": "Malicious ads, exploit hosts, PUP/adware installers"},
}

MACRO_VECTORS = [v for v, i in VECTORS.items() if i["kind"] == "macro"]
MICRO_VECTORS = [v for v, i in VECTORS.items() if i["kind"] == "micro"]

# vector -> the config switch that can turn it off
VECTOR_SWITCH = {
    "banner": "macro_ads", "native": "macro_ads", "popup": "push_ads", "push": "push_ads",
    "shopping": "macro_ads", "video": "invideo_ads", "ctv": "ctv_ads",
    "pixel": "micro_ads", "sdk": "micro_ads", "retarget": "micro_ads",
    "fingerprint": "micro_ads", "telemetry": "micro_ads", "email": "email_tracking",
    "shortlink": "micro_ads", "adx": "adtech_endpoints", "malvertising": "micro_ads",
}

# ──────────────────────────────────────────────
#  Categories (20)
# ──────────────────────────────────────────────
CAT = {
    "ads":         {"name": "Advertisements",       "color": "#fb542b", "icon": "fa-bullhorn",          "vec": "banner"},
    "video":       {"name": "Video & Streaming Ads","color": "#f97316", "icon": "fa-film",              "vec": "video"},
    "mobile":      {"name": "Mobile In-App Ads",    "color": "#3b82f6", "icon": "fa-mobile-screen",     "vec": "sdk"},
    "ctv":         {"name": "Smart TV & OTT",       "color": "#84cc16", "icon": "fa-tv",                "vec": "ctv"},
    "native":      {"name": "Native, Popup & Push", "color": "#f59e0b", "icon": "fa-bell",              "vec": "popup"},
    "adtech":      {"name": "Ad Exchange / SSP",    "color": "#6366f1", "icon": "fa-arrow-right-arrow-left", "vec": "adx"},
    "trackers":    {"name": "Trackers & Analytics", "color": "#8b5cf6", "icon": "fa-user-secret",        "vec": "pixel"},
    "fingerprint": {"name": "Fingerprinting",       "color": "#a855f7", "icon": "fa-fingerprint",       "vec": "fingerprint"},
    "telemetry":   {"name": "Telemetry & Spyware",  "color": "#d946ef", "icon": "fa-satellite-dish",    "vec": "telemetry"},
    "mail":        {"name": "Email Tracking",       "color": "#ec4899", "icon": "fa-envelope-open-text","vec": "email"},
    "shortlink":   {"name": "Shorteners & Redirects","color": "#f43f5e","icon": "fa-link-slash",        "vec": "shortlink"},
    "malware":     {"name": "Malware, C2 & Adware", "color": "#ef4444", "icon": "fa-skull-crossbones",  "vec": "malvertising"},
    "phishing":    {"name": "Phishing & Fraud",     "color": "#f59e0b", "icon": "fa-fish",              "vec": "malvertising"},
    "spam":        {"name": "Spam & Botnets",       "color": "#eab308", "icon": "fa-spam",              "vec": "shortlink"},
    "abuse":       {"name": "Abuse & Free Hosting", "color": "#14b8a6", "icon": "fa-user-shield",       "vec": "malvertising"},
    "crypto":      {"name": "Cryptojacking",        "color": "#22c55e", "icon": "fa-coins",             "vec": "micro"},
    "social":      {"name": "Social Widgets",       "color": "#06b6d4", "icon": "fa-share-nodes",       "vec": "pixel"},
    "adult":       {"name": "Adult & NSFW",         "color": "#f43f5e", "icon": "fa-ban",               "vec": "native"},
    "gambling":    {"name": "Gambling & Casino",    "color": "#14b8a6", "icon": "fa-dice",              "vec": "native"},
    "security":    {"name": "Threat Intelligence",  "color": "#3b82f6", "icon": "fa-shield-halved",     "vec": "malvertising"},
    "regional":    {"name": "Regional Ad Filters",  "color": "#0ea5e9", "icon": "fa-earth-europe",      "vec": "banner"},
}

# ──────────────────────────────────────────────
#  Blocklist registry: 110+ feeds
# ──────────────────────────────────────────────
_HZ_W = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
_HZ_A = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/"
_HZ_S = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/share/"
_UAS = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/"
_AGR = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/"
_AGS = "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/"
_SB = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
_SWB = "https://raw.githubusercontent.com/ShadowWhisperer/Blocklists/master/Lists/"
_PFL = "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/"
_1H = "https://raw.githubusercontent.com/badmojr/1Hosts/master/"
_ELP = "https://easylist-downloads.adblockplus.org/"
_UCS = "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/"

ALL_LISTS = {}


def _L(lid, name, cat, vec, url, enabled=0):
    ALL_LISTS[lid] = {"name": name, "cat": cat, "vec": vec, "url": url}
    if enabled:
        DEFAULT_ENABLED.append(lid)


DEFAULT_ENABLED = []

# ── Macro display / banner ads ──
_L("stevenblack", "StevenBlack Unified (ads+trackers)", "ads", "banner", _SB + "hosts", 1)
_L("adguard_dns", "AdGuard DNS Filter", "ads", "banner", _AGS + "filter.txt", 1)
_L("adguard_base", "AdGuard Base Filter", "ads", "banner", _AGR + "filter_2_Base/filter.txt", 1)
_L("oisd_big", "OISD Big (ads+trackers)", "ads", "banner", "https://big.oisd.nl/domainswild", 1)
_L("oisd_nic", "OISD NIC (never-break)", "ads", "banner", "https://nic.oisd.nl/domainswild", 1)
_L("hagezi_pro", "Hagezi Pro (wildcard)", "ads", "banner", _HZ_W + "pro-onlydomains.txt", 1)
_L("hagezi_pro_plus", "Hagezi Pro++ (wildcard)", "ads", "banner", _HZ_W + "pro.plus-onlydomains.txt")
_L("hagezi_ultimate", "Hagezi Ultimate (wildcard)", "ads", "banner", _HZ_W + "ultimate-onlydomains.txt")
_L("hagezi_light", "Hagezi Light (safe set)", "ads", "banner", _HZ_W + "light-onlydomains.txt")
_L("hagezi_adshield", "Hagezi AdShield (creative hosts)", "ads", "banner", _HZ_S + "ad-shield-subdomains.txt", 1)
_L("easylist", "EasyList (global banners)", "ads", "banner", _ELP + "easylist.txt", 1)
_L("peterlowe", "Peter Lowe Ad Server List", "ads", "banner", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", 1)
_L("adaway", "AdAway Mobile Hosts", "ads", "banner", "https://adaway.org/hosts.txt", 1)
_L("1hosts_lite", "1Hosts Lite", "ads", "banner", _1H + "Lite/domains.txt", 1)
_L("1hosts_xtra", "1Hosts Xtra (aggressive)", "ads", "banner", _1H + "Xtra/domains.txt")
_L("d3ward", "d3ward Toolz Hosts", "ads", "banner", "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt", 1)
_L("swb_ads", "ShadowWhisperer Ads", "ads", "banner", _SWB + "Ads", 1)
_L("swb_wild_ads", "ShadowWhisperer Wildcard Ads", "ads", "banner", _SWB + "Wild_Ads", 1)
_L("ublock_filters", "uBlock Origin Filter List", "ads", "banner", _UAS + "filters.txt", 1)
_L("adguard_popups", "AdGuard Popup Overlays", "native", "popup", _AGR + "filter_19_Annoyances_Popups/filter.txt", 1)
_L("adguard_annoy", "AdGuard Annoyances", "native", "popup", _AGR + "filter_14_Annoyances/filter.txt", 1)
_L("ublock_annoy", "uBlock Annoyances", "native", "popup", _UAS + "annoyances.txt", 1)
_L("ublock_annoy_oth", "uBlock Annoyances (others)", "native", "popup", _UAS + "annoyances-others.txt", 1)
_L("hagezi_popup", "Hagezi Popup Ads", "native", "popup", _HZ_A + "popupads.txt", 1)
_L("adguard_widgets", "AdGuard Widgets", "native", "native", _AGR + "filter_22_Annoyances_Widgets/filter.txt", 1)
_L("ublock_priv", "uBlock Privacy List", "trackers", "pixel", _UAS + "privacy.txt", 1)
_L("easyprivacy", "EasyPrivacy", "trackers", "pixel", _ELP + "easyprivacy.txt", 1)
_L("swb_tracking", "ShadowWhisperer Tracking", "trackers", "pixel", _SWB + "Tracking", 1)
_L("swb_marketing", "ShadowWhisperer Marketing", "trackers", "pixel", _SWB + "Marketing", 1)
_L("swb_junk", "ShadowWhisperer Junk", "trackers", "pixel", _SWB + "Junk", 1)
_L("winspy", "Windows Spy Blocker", "telemetry", "telemetry", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", 1)
_L("win_micro", "Windows Telemetry (micro)", "telemetry", "telemetry", _UCS + "Composite-Collections/hosts/master/hosts", 1)

# ── Micro: in-app SDK / mobile / CTV / video ──
_L("adguard_mobile", "AdGuard Mobile Ads Filter", "mobile", "sdk", _AGR + "filter_11_Mobile/filter.txt", 1)
_L("adguard_mobileapp", "AdGuard In-App Banners", "mobile", "sdk", _AGR + "filter_20_Annoyances_MobileApp/filter.txt", 1)
_L("ublock_mobile", "uBlock Mobile Filter", "mobile", "sdk", _UAS + "filters-mobile.txt", 1)
_L("perflyst_android", "Android Tracking", "mobile", "sdk", _PFL + "android-tracking.txt", 1)
_L("swb_ai", "ShadowWhisperer AI/Chat Trackers", "telemetry", "telemetry", _SWB + "AI", 1)
_L("swb_chat", "ShadowWhisperer Chat Trackers", "social", "pixel", _SWB + "Chat", 1)
_L("swb_fonts", "ShadowWhisperer Font CDNs (fingerprint)", "fingerprint", "fingerprint", _SWB + "Fonts", 1)
_L("swb_apple", "ShadowWhisperer Apple Telemetry", "telemetry", "telemetry", _SWB + "Apple", 1)
_L("swb_ms", "ShadowWhisperer Microsoft Telemetry", "telemetry", "telemetry", _SWB + "Microsoft", 1)
_L("swb_tunnels", "ShadowWhisperer Tunnels & Proxies", "abuse", "shortlink", _SWB + "Tunnels", 1)
_L("swb_urlshort", "ShadowWhisperer URL Shorteners", "shortlink", "shortlink", _SWB + "UrlShortener", 1)
_L("swb_typo", "ShadowWhisperer Typosquats", "phishing", "malvertising", _SWB + "Typo", 1)
_L("swb_risk", "ShadowWhisperer Risk Domains", "abuse", "malvertising", _SWB + "Risk", 1)
_L("swb_free", "ShadowWhisperer Free Hosting", "abuse", "shortlink", _SWB + "Free", 1)
_L("swb_dynamic", "ShadowWhisperer Dynamic DNS", "abuse", "shortlink", _SWB + "Dynamic", 1)
_L("hagezi_urlshort", "Hagezi URL Shorteners", "shortlink", "shortlink", _HZ_A + "urlshortener.txt", 1)
_L("hagezi_referral", "Hagezi Referral & Adware", "shortlink", "shortlink", _HZ_W + "blocklist-referral-onlydomains.txt", 1)
_L("hagezi_native_oppo", "Oppo/Realme Native Ads", "mobile", "sdk", _HZ_A + "native.oppo-realme.txt", 1)
_L("hagezi_native_xiaomi", "Xiaomi Native Ads", "mobile", "sdk", _HZ_A + "native.xiaomi.txt", 1)
_L("hagezi_native_vivo", "Vivo Native Ads", "mobile", "sdk", _HZ_A + "native.vivo.txt", 1)
_L("hagezi_native_huawei", "Huawei Native Ads", "mobile", "sdk", _HZ_A + "native.huawei.txt", 1)
_L("hagezi_native_tiktok", "TikTok Telemetry & Ads", "social", "pixel", _HZ_A + "native.tiktok.txt", 1)
_L("yt_blockads", "YouTube BlockAds Community List", "video", "video", "https://raw.githubusercontent.com/oiyay/Youtube_BlockAds_List/main/hosts", 1)
_L("adguard_twitch", "AdGuard Twitch Ads", "video", "video", _AGR + "filter_5_Experimental/filter.txt", 1)
_L("perflyst_smarttv", "Smart TV Tracking (PiHoleBlocklist)", "ctv", "ctv", _PFL + "SmartTV.txt", 1)
_L("smarttv_agh", "Smart TV (AdGuard syntax)", "ctv", "ctv", _PFL + "SmartTV-AGH.txt", 1)
_L("perflyst_firetv", "Amazon Fire TV Ads", "ctv", "ctv", _PFL + "AmazonFireTV.txt", 1)
_L("perflyst_replay", "Session Replay / Keystroke Capture", "fingerprint", "fingerprint", _PFL + "SessionReplay.txt", 1)
_L("hagezi_native_samsung", "Samsung TV Ads & Beacon", "ctv", "ctv", _HZ_A + "native.samsung.txt", 1)
_L("hagezi_native_lg", "LG webOS TV Ads", "ctv", "ctv", _HZ_A + "native.lgwebos.txt", 1)
_L("hagezi_native_roku", "Roku Ads", "ctv", "ctv", _HZ_A + "native.roku.txt", 1)
_L("hagezi_native_amazon", "Amazon Device Ads", "ctv", "ctv", _HZ_A + "native.amazon.txt", 1)
_L("hagezi_native_apple", "Apple Telemetry & Ads", "telemetry", "telemetry", _HZ_A + "native.apple.txt", 1)
_L("hagezi_native_win", "Windows Office Telemetry", "telemetry", "telemetry", _HZ_A + "native.winoffice.txt", 1)
_L("adguard_spyware", "AdGuard Spyware Filter", "trackers", "pixel", _AGR + "filter_3_Spyware/filter.txt", 1)
_L("adguard_trackparam", "AdGuard URL Track-Params", "trackers", "pixel", _AGR + "filter_17_TrackParam/filter.txt", 1)
_L("adguard_mail", "AdGuard Mail Tracking Protection", "mail", "email", _AGR + "filter_25_Mail_Tracking_Protection/filter.txt", 1)
_L("adguard_dnsfilter", "AdGuard DNS Filter (registry)", "ads", "banner", _AGR + "filter_15_DnsFilter/filter.txt", 1)
_L("adguard_excl", "AdGuard Cookie Notices", "native", "popup", _AGR + "filter_18_Annoyances_Cookies/filter.txt", 1)
_L("ublock_badlists", "uBlock BadLists (adware/PUP)", "malware", "malvertising", _UAS + "badlists.txt", 1)
_L("ublock_resabuse", "uBlock Resource Abuse", "malware", "malvertising", _UAS + "resource-abuse.txt", 1)
_L("ubock_shorteners", "uBlock Link Shorteners", "shortlink", "shortlink", _UAS + "ubo-link-shorteners.txt", 1)
_L("hagezi_doh", "Public DoH Resolvers (bypass guard)", "abuse", "shortlink", _HZ_W + "doh-onlydomains.txt")
_L("hagezi_dyndns", "Hagezi DynDNS Abuse", "abuse", "shortlink", _HZ_W + "dyndns-onlydomains.txt", 1)
_L("hagezi_hoster", "Hagezi Free Hoster Abuse", "abuse", "shortlink", _HZ_W + "hoster-onlydomains.txt", 1)
_L("hagezi_spamtld", "Hagezi Spam TLDs", "spam", "shortlink", _HZ_A + "spam-tlds-adblock.txt", 1)
_L("hagezi_tif", "Hagezi Threat Intelligence Feeds", "security", "malvertising", _HZ_W + "tif-onlydomains.txt", 1)
_L("hagezi_fake", "Hagezi Fake-Shops & Scams", "phishing", "malvertising", _HZ_W + "fake-onlydomains.txt", 1)
_L("hagezi_piracy", "Hagezi Anti-Piracy", "gambling", "native", _HZ_A + "anti.piracy.txt")
_L("hagezi_social", "Hagezi Social Media Trackers", "social", "pixel", _HZ_A + "social.txt", 1)
_L("hagezi_nsfw", "Hagezi NSFW", "adult", "native", _HZ_A + "nsfw.txt")
_L("hagezi_gamble", "Hagezi Gambling", "gambling", "native", _HZ_A + "gambling.txt")
_L("ublock_unbreak", "uBlock Unbreak (anti-breakage)", "ads", "banner", _UAS + "unbreak.txt", 1)

# ── Malware / phishing / spam ──
_L("urlhaus", "URLhaus Malware Host Feed", "malware", "malvertising", "https://urlhaus.abuse.ch/downloads/hostfile/", 1)
_L("sslbl", "Abuse.ch SSL Blacklist", "malware", "malvertising", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", 1)
_L("rpi_mal", "RPiList Malware", "malware", "malvertising", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware", 1)
_L("rpi_mobsf", "RPiList Mobile Malware", "malware", "malvertising", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/mobile-malware", 1)
_L("rpi_crypto", "RPiList Crypto Stealers", "crypto", "malvertising", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Crypto-Blocker", 1)
_L("rpi_fake", "RPiList Fake-Shops", "phishing", "malvertising", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Fake-Shops", 1)
_L("rpi_phish", "RPiList Phishing", "phishing", "malvertising", "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe", 1)
_L("phisharmy", "Phishing Army Extended", "phishing", "malvertising", "https://phishing.army/download/phishing_army_blocklist_extended.txt", 1)
_L("openphish", "OpenPhish Active Feeds", "phishing", "malvertising", "https://openphish.com/feed.txt", 1)
_L("phishdb", "Phishing Database (active)", "phishing", "malvertising", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", 1)
_L("swb_malware", "ShadowWhisperer Malware", "malware", "malvertising", _SWB + "Malware", 1)
_L("swb_scam", "ShadowWhisperer Scam", "phishing", "malvertising", _SWB + "Scam", 1)
_L("swb_tld", "ShadowWhisperer Bad TLDs", "spam", "shortlink", _SWB + "Top_Level", 1)
_L("dshield", "DShield Suspicious Domains", "malware", "malvertising", "https://www.dshield.org/feeds/suspiciousdomains_High.txt", 1)
_L("emerging", "Emerging Threats Compromised", "malware", "malvertising", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 1)
_L("blocklist_de", "Blocklist.de Phishing", "phishing", "malvertising", "https://lists.blocklist.de/lists/phishing.txt", 1)
_L("blocklist_de_all", "Blocklist.de All Attacks", "spam", "shortlink", "https://lists.blocklist.de/lists/all.txt", 1)
_L("spamhaus_drop", "Spamhaus DROP Netblocks", "spam", "shortlink", "https://www.spamhaus.org/drop/drop.txt", 1)
_L("nocoin", "NoCoin Cryptomining", "crypto", "malvertising", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", 1)
_L("coinblocker", "CoinBlocker Pools & Miners", "crypto", "malvertising", "https://zerodot1.gitlab.io/CoinBlockerLists/hosts", 1)
_L("coinbrowser", "CoinBlocker Browser Miners", "crypto", "malvertising", "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser", 1)
_L("sb_phish", "StevenBlack Fakenews (scam bait)", "phishing", "malvertising", _SB + "alternates/fakenews/hosts", 1)

# ── Family filters (opt-in / Family mode) ──
_L("sb_porn", "StevenBlack Adult", "adult", "native", _SB + "alternates/porn/hosts")
_L("sin_porn", "Sinfonietta Adult", "adult", "native", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts")
_L("oisd_nsfw", "OISD NSFW", "adult", "native", "https://nsfw.oisd.nl/domainswild")
_L("sb_gamble", "StevenBlack Gambling", "gambling", "native", _SB + "alternates/gambling/hosts")
_L("sin_gamble", "Sinfonietta Gambling", "gambling", "native", "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts")
_L("swb_adult", "ShadowWhisperer Adult", "adult", "native", _SWB + "Adult")
_L("swb_gambling", "ShadowWhisperer Gambling", "gambling", "native", _SWB + "Gambling")
_L("hagezi_gamble_m", "Hagezi Gambling (medium)", "gambling", "native", _HZ_A + "gambling.medium.txt")

# ── Regional (macro ads in local markets) ──
_L("yhosts_cn", "yHosts China Ads & Trackers", "regional", "banner", "https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts")
_L("adguard_german", "AdGuard German Filter", "ads", "banner", _AGR + "filter_6_German/filter.txt")
_L("adguard_french", "AdGuard French Filter", "ads", "banner", _AGR + "filter_16_French/filter.txt")
_L("adguard_italian", "AdGuard Italian Filter", "ads", "banner", _AGR + "filter_26_Italian/filter.txt")
_L("adguard_spanish", "AdGuard Spanish Filter", "ads", "banner", _AGR + "filter_9_Spanish/filter.txt")
_L("adguard_dutch", "AdGuard Dutch Filter", "ads", "banner", _AGR + "filter_8_Dutch/filter.txt")
_L("adguard_turkish", "AdGuard Turkish Filter", "ads", "banner", _AGR + "filter_13_Turkish/filter.txt")
_L("adguard_japanese", "AdGuard Japanese Filter", "ads", "banner", _AGR + "filter_7_Japanese/filter.txt")
_L("easylist_de", "EasyList Germany", "ads", "banner", _ELP + "easylistgermany.txt")
_L("easylist_fr", "EasyList France", "ads", "banner", _ELP + "easylistfrance.txt")
_L("easylist_es", "EasyList Spain", "ads", "banner", _ELP + "easylistspanish.txt")
_L("easylist_it", "EasyList Italy", "ads", "banner", _ELP + "easylistitaly.txt")
_L("easylist_nl", "EasyList Dutch", "ads", "banner", _ELP + "easylistdutch.txt")

_L("adguard_polish", "AdGuard Polish Filter", "regional", "banner", _AGR + "filter_27_Polish/filter.txt")
_L("adguard_ukrainian", "AdGuard Ukrainian Filter", "regional", "banner", _AGR + "filter_23_Ukrainian/filter.txt")
_L("adguard_russian", "AdGuard Russian Filter (RU/CIS ads)", "regional", "banner", _AGR + "filter_1_Russian/filter.txt")

# ──────────────────────────────────────────────
#  Legacy-ID migration so old installs keep their toggles
# ──────────────────────────────────────────────
LEGACY_IDS = {
    "adguard": "adguard_dns", "oisd": "oisd_big", "hagezi_ulti": "hagezi_ultimate",
    "adguard_track": "adguard_spyware", "prigent_ads": "ublock_priv",
    "prigent_mal": "ublock_badlists", "hagezi_badware": "hagezi_tif",
    "hagezi_threat": "hagezi_tif", "abusech_ssl": "sslbl", "notrack": "swb_marketing",
    "firebog_ticked": "adguard_dnsfilter", "ubpriv": "ublock_priv",
    "fb_track": "hagezi_social", "tiktok": "hagezi_native_tiktok", "twitter": "swb_chat",
    "rpifake": "hagezi_fake", "rpifake_shops": "hagezi_fake", "smarttv": "perflyst_smarttv",
    "adaway_mobile": "adaway", "1hosts": "1hosts_lite", "nocoin_list": "nocoin",
    "sb_gambling": "sb_gamble", "sin_gambling": "sin_gamble", "oisd_nsfw_list": "oisd_nsfw",
}


def migrate_list_ids(cfg):
    """Translate v18 list ids to v19 ids, keeping user choices (custom feeds too)."""
    valid = set(ALL_LISTS) | set((cfg.get("custom_lists") or {}).keys())
    raw = cfg.get("enabled_lists") or []
    out = []
    for lid in raw:
        lid = LEGACY_IDS.get(lid, lid)
        if lid in valid and lid not in out:
            out.append(lid)
    cfg["enabled_lists"] = out
    return cfg


# ──────────────────────────────────────────────
#  Instant-protection seed: blocks the biggest ad/malvertising
#  infrastructure before the first list download has even finished.
# ──────────────────────────────────────────────
CORE_SEED = {
    # Google ad stack (banner, video, native, shopping)
    "doubleclick.net": "banner", "googleadservices.com": "banner",
    "googlesyndication.com": "banner", "googlesyndication.net": "banner",
    "googleadapis.com": "banner", "googleusercontent.com.g.doubleclick.net": "banner",
    "admob.com": "banner", "adsenseplatform.com": "banner", "gg.google.com": "banner",
    "pagead.l.google.com": "banner", "pagead2.googlesyndication.com": "banner",
    "static.doubleclick.net": "banner", "securepubads.g.doubleclick.net": "adx",
    "pubads.g.doubleclick.net": "adx", "partner.googleadservices.com": "banner",
    "youtube.com.ads": "video", "youtube-nocookie.com": "video",
    "2mdn.net": "video", "s0.2mdn.net": "video", "adservice.google.com": "banner",
    "g.doubleclick.net": "adx", "adservice.google.co.uk": "banner",
    "googletraveladservices.com": "shopping", "adservice.google.de": "banner",
    # Meta
    "an.facebook.com": "banner", "adx.com": "adx", "adnetworkperf.com": "adx",
    "facebook.net": "pixel", "connect.facebook.net": "pixel", "tr.snapchat.com": "pixel",
    "analytics.snapchat.com": "pixel", "adjust.com": "pixel", "adjust.net.in": "pixel",
    "appsflyer.com": "pixel", "appsflyer.net": "pixel", "oneapppixel.com": "pixel",
    "branch.io": "pixel", "go2cloud.org": "pixel", "count.ly": "pixel",
    # Big independent ad exchanges / SSPs
    "adnxs.com": "adx", "openx.net": "adx", "rubiconproject.com": "adx",
    "pubmatic.com": "adx", "casalemedia.com": "adx", "indexww.com": "adx",
    "amazon-adsystem.com": "banner", "adsystem.com": "banner", "advertising.com": "adx",
    "oath.com": "adx", "yieldmo.com": "adx", "sovrn.com": "adx", "sonobi.com": "adx",
    "sharedcount": "pixel", "smartadserver.com": "adx", "adocean.pl": "adx",
    "adform.net": "adx", "adman.gr": "adx", "admatrix.jp": "adx", "adnologies.com": "adx",
    "criteo.com": "retarget", "criteo.net": "retarget", "critero.com": "retarget",
    "taboola.com": "native", "outbrain.com": "native", "revcontent.com": "native",
    "disqusads.com": "native", "zemanta.com": "native", "ntv.io": "native",
    "mgid.com": "native", "juiceadv.com": "native", "propellerads.com": "popup",
    "popads.net": "popup", "popcash.net": "popup", "hilltopads.com": "popup",
    "exoclick.com": "popup", "exosrv.com": "popup", "revenuehits.com": "popup",
    "adsterra.com": "popup", "admatic.de": "adx", "adtrue.com": "adx",
    # Pixels / analytics / attribution
    "google-analytics.com": "pixel", "googletagmanager.com": "pixel",
    "googleoptimize.com": "pixel", "googleadservices.co": "pixel",
    "doubleverify.com": "pixel", "moatads.com": "pixel", "moatpixel.com": "pixel",
    "scorecardresearch.com": "pixel", "quantserve.com": "pixel", "chartbeat.com": "pixel",
    "segment.io": "pixel", "segment.com": "pixel", "mixpanel.com": "pixel",
    "amplitude.com": "pixel", "keen.io": "pixel", "flurry.com": "pixel",
    "kissmetrics.io": "pixel", "hotjar.com": "telemetry", "clarity.ms": "telemetry",
    "mouseflow.com": "telemetry", "fullstory.com": "telemetry", "crazyegg.com": "telemetry",
    "smartlook.com": "telemetry", "logrocket.com": "telemetry", "pendo.io": "telemetry",
    "tealiumiq.com": "pixel", "ensighten.com": "pixel", "adobedtm.com": "pixel",
    "omtrdc.net": "pixel", "demdex.net": "retarget", "adsrvr.org": "retarget",
    "mediamath.com": "retarget", "exelator.com": "retarget", "krxd.net": "retarget",
    "bluekai.com": "retarget", "tapad.com": "retarget", "nfijfd.net": "retarget",
    "innovid.com": "video", "sizmek.com": "video", "springserve.com": "video",
    "adobesc.com": "video", "freewheel.tv": "video", "fwmrm.net": "video",
    "spotxchange.com": "video", "spotx.tv": "video", "jadserve.postrelease.com": "banner",
    "adsafeprotected.com": "pixel", "iaspx.com": "pixel", "integralads.com": "video",
    "videologygroup.com": "video", "tremorhub.com": "video", "unruly.co": "video",
    # Mobile in-app SDKs
    "unityads.unity3d.com": "sdk", "game.adcolony.com": "sdk", "adcolony.com": "sdk",
    "applovin.com": "sdk", "applvn.com": "sdk", "ironsrc.com": "sdk", "inmobi.com": "sdk",
    "vungle.com": "sdk", "chartboost.com": "sdk", "unity3d.com": "sdk",
    "unity.cn": "sdk", "digimena.com": "sdk", "pubnative.net": "sdk",
    "mobidea.com": "sdk", "startapp.com": "sdk", "startappexchange.com": "sdk",
    "km0hq9.xyz": "sdk", "smaato.net": "sdk", "inmobi.cn": "sdk", "amoad.com": "sdk",
    "sigmob.cn": "sdk", "kwai-network.com": "sdk", "kwaiads.com": "sdk",
    # CTV / set-top beacons
    "ads.samsung.com": "ctv", "samsungads.com": "ctv", "ads.hulu.com": "ctv",
    "smarttv.hulu.com": "ctv", "lgtvads.com": "ctv", "ads.roku.com": "ctv",
    "amazon-adsystem.tv": "ctv", "firetveu.ads.amazon.com": "ctv",
    "ads.cmpassport.com": "ctv", "ads.hbo.com": "ctv", "applovinctv.com": "ctv",
    "vturb.com": "ctv", "amagi.tv": "ctv", "audiencenet.tv": "ctv", "ssp.amagi.tv": "ctv",
    "ads.vizio.com": "ctv", "ads.tcl.com": "ctv", "ads.xiaomi.tv": "ctv",
    "ads.cloudtv": "ctv", "ads.hisense.com": "ctv", "ads.philips.com": "ctv",
    # In-video / YouTube ad endpoints
    "s.youtube.com": "video", "video-stats.l.google.com": "video",
    "video-stats.youtube.com": "video", "youtubei.googleapis.com": "video",
    "youtubeadsdk.com": "video", "admaven.co": "video",
    "imasdk.googleapis.com": "video", "videostats.kakao.com": "video",
    # hosts a real YouTube player ad payload referenced and v18 let through
    "static.googleadsserving.cn": "video", "s2.youtube.com": "video",
    "dai.google.com": "video", "pagead.google.com": "video",
    "static.doubleclick.net": "video", "ade.googlesyndication.com": "video",
    # Google's own ad-reporting / ad-UX endpoints: the player's "My Ad Center" panel and
    # the Ad Transparency lookup both report to these. Blocking costs nothing but a button
    # that no longer opens (allow them again with: adquit allow adstransparency.google.com).
    "myadcenter.google.com": "ads", "adstransparency.google.com": "ads",
    "myactivity.google.com.ads": "ads", "adservice.google.ae": "ads",
    "pagead.googlesyndication.com": "video", "pagead.l.google.com": "video",
    # client telemetry that only exists to profile you
    "app-measurement.com": "telemetry", "firebaselogging.googleapis.com": "telemetry",
    "crashlyticsreports-pa.googleapis.com": "telemetry", "pulse.video": "fingerprint",
    "doubleverify.com": "retarget", "adsafeprotected.com": "retarget",
    
    # Push / notification ad gateways
    "onesignal.net": "push", "onesignal.com": "push", "pushnami.com": "push",
    "pushengage.com": "push", "pushwoosh.com": "push", "engageya.com": "push",
    "gepush.com": "push", "notifadz.com": "push", "adsterra.com.push": "push",
    "primelephant.com": "push", "luckyshop.com": "push", "getnotify.com": "push",
    "popmarker.com": "push", "zybrdr.com": "push", "cdn55.net": "push",
    # Fingerprinting / anti-bot ad tech
    "fingerprintjs.com": "fingerprint", "client.fingerprintjs.com": "fingerprint",
    "devicejs.com": "fingerprint", "c-profits.com": "fingerprint",
    "perimeterx.net": "fingerprint", "px-cloud.net": "fingerprint",
    "datadome.co": "fingerprint", "threatmetrix.com": "fingerprint",
    "maxmind.com": "fingerprint", "ipinfo.io": "fingerprint",
    "siftscience.com": "fingerprint", "threatmark.com": "fingerprint",
    # Cryptojacking
    "crypto-loot.com": "malvertising", "coinhive.com": "malvertising",
    "coin-hive.com": "malvertising", "cryptonight.wasm": "malvertising",
    "jsecoin.com": "malvertising", "projectpoi.com": "malvertising",
    "webminepool.com": "malvertising", "hashing.win": "malvertising",
    "minerpool.com": "malvertising", "coinimp.com": "malvertising",
    # Email open/click tracking
    "mailtrack.me": "email", "streak.com": "email", "campanja.com": "email",
    "rightinbox.com": "email", "mixmax.com": "email", "mailstat.us": "email",
    "sendpulse.com": "email", "rlets.com": "email", "list-manage.com": "email",
    "pardot.com": "email", "hs-sales-automation.net": "email", "shareasale.com": "email",
    "mailchimp.com.pixel": "email", "gumroad.com.pixel": "email",
    # Ad CDNs / creative hosts
    "adscale.de": "banner", "creativecdn.com": "banner", "adsfac.net": "banner",
    "adsfac.us": "banner", "adroll.com": "retarget", "adsbycloud.com": "banner",
    "adnami.io": "banner", "adspeed.net": "banner", "adsafety.net": "banner",
    "adscale.net": "banner", "adservice.google": "banner", "adserver.org": "banner",
    "adserve.io": "banner", "adtech.de": "banner", "adthor.com": "banner",
    "adtelligent.com": "banner", "adtimia.com": "banner", "adtrace.org": "pixel",
    "aduptech.com": "banner", "advangelists.com": "banner", "adventory.com": "banner",
    "adverticum.net": "banner", "advertise.com": "banner", "advertstream.com": "banner",
    "advisigo.com": "banner", "adwebersisterlabs.com": "banner", "adworx.be": "banner",
}
CORE_SEED_DOMAINS = set(CORE_SEED)

# ──────────────────────────────────────────────
#  Trusted zones: the pattern/heuristic engine never fires on these
#  (registrable domains only, so ads.google.com stays but
#   googleadservices.com is still fair game).
# ──────────────────────────────────────────────
TRUSTED_ZONES = {
    "google.com", "youtube.com", "googleapis.com", "gstatic.com", "googleblog.com",
    "microsoft.com", "microsoftonline.com", "windows.net", "azure.com", "github.com",
    "githubusercontent.com", "githubassets.com", "apple.com", "icloud.com", "amazon.com",
    "amazonaws.com", "amzn.to", "amzn.com", "aws.amazon.com", "netflix.com", "nflxvideo.net",
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "x.com", "twitter.com",
    "twitch.tv", "reddit.com", "redditstatic.com", "wikipedia.org", "wikimedia.org",
    "stackexchange.com", "stackoverflow.com", "medium.com", "discord.com", "discordapp.com",
    "discord.gg", "telegram.org", "t.me", "tiktok.com", "snapchat.com", "spotify.com",
    "spotifycdn.com", "soundcloud.com", "vimeo.com", "dailymotion.com", "paypal.com",
    "stripe.com", "shopify.com", "shopifycdn.com", "ebay.com", "walmart.com", "target.com",
    "bestbuy.com", "costco.com", "nike.com", "adidas.com", "samsung.com", "lg.com", "sony.com",
    "intel.com", "nvidia.com", "amd.com", "arm.com", "oracle.com", "ibm.com", "redhat.com",
    "canonical.com", "ubuntu.com", "debian.org", "python.org", "pypi.org", "npmjs.com",
    "nodejs.org", "rust-lang.org", "golang.org", "docker.com", "cloudflare.com",
    "cloudflare-dns.com", "cfar.me", "fastly.net", "akamai.net", "akamaized.net",
    "cdn77.org", "jsdelivr.net", "unpkg.com", "jquery.com", "cdnjs.com", "googleapis.cn",
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "nytimes.com", "bbc.co.uk", "bbc.com",
    "theguardian.com", "cnn.com", "foxnews.com", "reuters.com", "bloomberg.com",
    "wsj.com", "washingtonpost.com", "forbes.com", "arstechnica.com", "theverge.com",
    "engadget.com", "cnet.com", "zdnet.com", "hackernews.com", "ycombinator.com",
    "gmail.com", "outlook.com", "live.com", "hotmail.com", "yahoo.com", "proton.me",
    "protonmail.com", "icloud.com.mx", "dropbox.com", "onedrive.live.com",
    "drive.google.com", "docs.google.com", "calendar.google.com", "meet.google.com",
    "zoom.us", "zoomgov.com", "webex.com", "gotomeeting.com", "atlassian.com",
    "gitlab.com", "bitbucket.org", "sourceforge.net", "sourcegraph.com", "dev.to",
    "huggingface.co", "openai.com", "anthropic.com", "deepmind.com", "meta.com",
    "llama.com", "mozilla.org", "chromium.org", "kernel.org", "gnu.org", "fsf.org",
    "ef.org", "archive.org", "waybackmachine.org", "nasa.gov", "who.int", "un.org",
    "europa.eu", "gov.uk", "usa.gov", "irs.gov", "uscourts.gov", "sec.gov",
    "nih.gov", "cdc.gov", "ed.gov", "doe.gov", "dhs.gov", "justice.gov", "state.gov",
    ".gov", ".edu", ".mil", "myuniversity.edu", "k12.com", "googlemail.com",
    "play.google.com", "developers.google.com", "support.google.com", "accounts.google.com",
    "signin.aliyun.com", "aliyuncs.com", "alibaba.com", "taobao.com", "tmall.com",
    "jd.com", "qq.com", "weixin.qq.com", "wechat.com", "baidu.com", "zhihu.com",
    "line.me", "naver.com", "kakao.com", "yandex.ru", "vk.com", "ok.ru",
    "mail.ru", "godaddy.com", "namecheap.com", "cloudflare.net", "digitalocean.com",
    "linode.com", "hetzner.com", "ovh.com", "scaleway.com", "heroku.com", "vercel.app",
    "netlify.app", "workers.dev", "pages.dev", "github.io", "gitlab.io", "bitbucket.io",
    "sourceforge.io", "readthedocs.io", "pypi.io", "crates.io", "packagist.org",
    "rubygems.org", "cocoapods.org", "carthage.sh", "brew.sh", "archlinux.org",
    "getkirby.com", "nginx.org", "apache.org", "mysql.com", "postgresql.org",
    "mongodb.com", "redis.io", "elastic.co", "splunk.com", "datadoghq.com",
    "newrelic.com", "grafana.net", "grafana.com", "sentry.io", "bugzilla.org",
    "atlassian.net", "slack.com", "slack-edge.com", "msteams.com", "teams.microsoft.com",
    "sharepoint.com", "office.com", "office365.com", "office.net", "lync.com",
    "skype.com", "skypeassets.com", "cortana.ai", "bing.com", "bing.net",
    "msn.com", "microsofttranslator.com", "windowsupdate.com", "wpad",
}
# .gov / .edu style suffix zones are handled separately in _trusted_zone()
TRUSTED_SUFFIXES = (".gov", ".gov.uk", ".edu", ".edu.au", ".mil", ".nhs.uk", ".k12.us",
                    ".ac.uk", ".go.jp", ".gouv.fr", ".gc.ca", ".co.uk.gov")

def save_list_status():
    try:
        atomic_write(STATUS_FILE, json.dumps(LIST_STATUS, indent=1))
    except Exception:
        pass


def load_list_status():
    if not STATUS_FILE.exists():
        return
    try:
        saved = json.loads(STATUS_FILE.read_text())
        for k, v in saved.items():
            k = LEGACY_IDS.get(k, k)
            if k in LIST_STATUS:
                for field in ("count", "state", "last_updated", "error"):
                    if field in v:
                        LIST_STATUS[k][field] = v[field]
    except Exception:
        pass



# ──────────────────────────────────────────────
#  Legacy aliases kept for v18 configs / muscle memory
# ──────────────────────────────────────────────
CUSTOM_BLOCKED = set()
CUSTOM_WHITELIST = set()
BLOCKED_DOMAINS = set()
DOMAIN_CATEGORIES = {}


class _LazyView(object):
    """A set/dict built the first time someone actually touches it.

    The v18 compatibility names below used to be materialised on every boot - two more
    full copies of a 5M-rule table, about 1.5 GB and a couple of seconds before the
    dashboard could even bind its port. Nobody reads them unless a v18 template or API
    is used, so the big ones wait."""

    __slots__ = ("_build", "_obj")

    def __init__(self, build):
        self._build = build
        self._obj = None

    def _real(self):
        if self._obj is None:
            self._obj = self._build()
        return self._obj

    def __contains__(self, item):
        return item in self._real()

    def __iter__(self):
        return iter(self._real())

    def __len__(self):
        return len(self._real())

    def __bool__(self):
        return bool(self._real())

    def __getitem__(self, key):
        return self._real()[key]

    def __repr__(self):
        return repr(self._real())

    def __getattr__(self, name):
        return getattr(self._real(), name)


def _sync_legacy_views(custom_blocked=None):
    """v18 templates/APIs read these names; keep them pointing at the v19 tables."""
    global BLOCKED_DOMAINS, DOMAIN_CATEGORIES, CUSTOM_BLOCKED, CUSTOM_WHITELIST
    BLOCKED_DOMAINS = _LazyView(lambda: set(BLOCKED) | set(WILDCARDS))
    DOMAIN_CATEGORIES = _LazyView(lambda: {d: v[0] for d, v in BLOCKED.items()})
    # the dashboard reads these two per request - keep them eager, and cheap: the
    # custom sets come from the (tiny) user files, not from a scan of the feeds
    CUSTOM_BLOCKED = set(custom_blocked) if custom_blocked is not None \
        else {d for d, v in BLOCKED.items() if v[2] == "custom"}
    CUSTOM_WHITELIST = set(CUSTOM_WHITELIST_SET)


def audit_threat(domain):
    """v18 compatibility shim: (action, category, color)."""
    v = classify(domain)
    return v["action"], v["cat"], v["color"]


def _write_banners():
    banner = (
        "  ================================================================\n"
        "   NETBLOCK FORTRESS v%s \"%s\"  |  %s feeds / %s categories\n"
        "   DNS :0.%s  ->  %s | Web :%s | %s rules armed\n"
        "  ================================================================" % (
            VERSION, CODENAME, len(ALL_LISTS), len(CAT), CFG.get("dns_port", 53),
            CFG.get("dns_upstream", "1.1.1.1"), CFG.get("web_port", 8080),
            "{:,}".format(len(BLOCKED) + len(WILDCARDS)))
    )
    print(banner)

# ──────────────────────────────────────────────
#  Engine state
# ──────────────────────────────────────────────
BLOCKED = {}            # exact domain -> (cat, vector, source_list_id)
WILDCARDS = {}          # parent domain -> (cat, vector, source)   (matches the domain + any sub)
UNBREAK = set()         # adblock "@@" exceptions => never block (anti-breakage)
ENGINE_STATS = defaultdict(int)
LIST_LOCK = threading.RLock()

TOTAL_QUERIES = 0
BLOCKED_QUERIES = 0
ALLOWED_QUERIES = 0
AI_QUERIES = 0
CACHE_HITS = 0
PATTERN_HITS = 0
WILDCARD_HITS = 0
CNAME_HITS = 0
DROPPED = 0
START_TIME = time.time()

QUERY_LOGS = deque(maxlen=int(CFG.get("log_max", 3000)))
CLIENT_ACTIVITY = defaultdict(lambda: {"total": 0, "blocked": 0, "last_seen": 0, "threats": 0,
                                       "ads": 0, "names": {}})
CLIENT_RATES = defaultdict(list)
SECURITY_EVENTS = deque(maxlen=400)
TOP_BLOCKED = defaultdict(lambda: defaultdict(int))     # client -> {domain: count}
TOP_GLOBAL = defaultdict(int)
HOURLY = [0] * 24
HOURLY_BLOCKED = [0] * 24
VECTOR_COUNTS = defaultdict(int)
CAT_COUNTS = defaultdict(int)
_stats_lock = threading.Lock()

LIST_STATUS = {}


def init_list_status():
    enabled = set(CFG.get("enabled_lists", []))
    for lid, info in all_lists().items():
        prev = LIST_STATUS.get(lid, {})
        LIST_STATUS[lid] = {
            "name": info["name"], "cat": info["cat"], "vec": info.get("vec", "banner"),
            "url": info["url"], "enabled": lid in enabled,
            "state": prev.get("state", "idle"), "count": prev.get("count", 0),
            "last_updated": prev.get("last_updated", "Never"), "error": prev.get("error"),
        }


def all_lists():
    """Registry + user supplied custom feeds."""
    merged = dict(ALL_LISTS)
    for lid, info in (CFG.get("custom_lists") or {}).items():
        if isinstance(info, dict) and info.get("url"):
            merged[lid] = {"name": info.get("name", lid), "cat": info.get("cat", "ads"),
                           "vec": info.get("vec", "banner"), "url": info["url"]}
    return merged


# ──────────────────────────────────────────────
#  Domain normalisation helpers
# ──────────────────────────────────────────────
VALID_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9_\-\u0080-\uffff]{1,63}(?<!-)"
                          r"(\.(?!-)[a-z0-9_\-]{1,63}(?<!-))*\.[a-z]{2,24}$")
IP_LIKE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HOSTLINE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.[0-9]+|::1|255\.255\.255\.255|#)\s+(.*)$")


def norm_domain(token):
    """Turn one raw token into a clean lowercase domain (or None)."""
    if not token:
        return None
    d = token.strip().lower().rstrip(".,;:")
    if not d or d.startswith("#"):
        return None
    # strip scheme / path / port / options
    d = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("$")[0].strip()
    d = d.split(":")[0]
    d = d.lstrip(".").rstrip(".")
    d = d.replace(" ", "")
    if not d or IP_LIKE.match(d) or "." not in d:
        return None
    if d.endswith((".png", ".jpg", ".gif", ".css", ".js", ".php", ".html", ".ico")):
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        pass
    if not VALID_DOMAIN.match(d):
        return None
    if len(d.split(".")[-1]) < 2:
        return None
    return d


def registrable(domain):
    """Best-effort registrable domain: last two labels (three for public 2nd level TLDs)."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    if len(parts) >= 3 and parts[-2] in (
            "co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "in", "mil", "sch"):
        if len(parts[-1]) == 2:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_trusted(domain):
    rd = registrable(domain)
    if rd in TRUSTED_ZONES or domain in TRUSTED_ZONES:
        return True
    if domain.endswith(TRUSTED_SUFFIXES) or rd.endswith(TRUSTED_SUFFIXES):
        return True
    return False


# ──────────────────────────────────────────────
#  Blocklist parsing (hosts, adblock, plain, wildcard, dnsmasq, regex)
# ──────────────────────────────────────────────
def parse_source_bytes(raw):
    """Return (exact_domains, wildcard_domains, unbreak_domains) from any feed format."""
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    text = raw.decode("utf-8", "ignore")
    exact, wild, unb = set(), set(), set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!" or line.startswith(("[Adblock", "![Adblock", "---", "==")):
            continue
        # adblock exception line -> anti-breakage allowlist
        is_exception = False
        if line.startswith("@@"):
            is_exception, line = True, line[2:].strip()
        line = re.sub(r"[ \t]+#.*$", "", line).strip()   # drop inline comments
        if not line:
            continue
        # adblock element selectors / cosmetic rules carry no DNS meaning
        if "##" in line or (line[:1] in ".#" and "$" in line) or line.startswith(("#@", "$~")):
            continue
        hosts = []
        m = HOSTLINE.match(line)
        if m:
            hosts = m.group(1).split()
        elif line.startswith(("||", "|")):
            body = line.lstrip("|")
            body = body.split("$")[0]
            body = body.replace("^", " ").replace("/", " ").strip()
            hosts = body.split()
        elif line.startswith("*"):
            hosts = [line.lstrip("*.").lstrip("*.")]
        elif line.startswith("address=/") or line.startswith("server=/"):
            body = line.split("=", 1)[1] if "=" in line else ""
            hosts = [p for p in body.split("/") if p]
        else:
            hosts = [line]
        for tok in hosts:
            tok = tok.strip()
            leading_wild = tok.startswith("*") or tok.startswith(".")
            d = norm_domain(tok)
            if not d:
                continue
            if is_exception:
                unb.add(d)
            elif leading_wild or (tok.endswith("^") and d.count(".") > 1 and len(d.split(".")[0]) <= 2):
                wild.add(d)
            else:
                exact.add(d)
                # a bare "ads.example.com" entry also implies the sub-tree for CTV/SDK hosts
    return exact, wild, unb


def list_file(path):
    """Cached parse of one downloaded feed (re-parses only when the file changes)."""
    try:
        st = path.stat()
    except Exception:
        return frozenset(), frozenset(), frozenset()
    meta = META_DIR / (path.stem + ".parse.meta")
    mark = "%s:%s" % (st.st_mtime_ns, st.st_size)
    cache_path = META_DIR / (path.stem + ".parse.pkl")
    try:
        if cache_path.exists() and meta.exists() and meta.read_text() == mark:
            with open(cache_path, "rb") as fh:
                e, w, u = pickle.load(fh)
            return e, w, u
    except Exception:
        pass
    raw = path.read_bytes()
    e, w, u = parse_source_bytes(raw)
    try:
        meta.write_text(mark)
        with open(cache_path, "wb") as fh:
            pickle.dump((frozenset(e), frozenset(w), frozenset(u)), fh, protocol=4)
    except Exception:
        pass
    return frozenset(e), frozenset(w), frozenset(u)


# ──────────────────────────────────────────────
#  Micro/macro pattern engine
#  Tier A: ad-infrastructure keywords (safe everywhere)
#  Tier B: advertising sub-domain labels (strict + nuclear only)
# ──────────────────────────────────────────────
AD_KEYWORDS = (
    # (keyword substring in registrable domain, category, vector, reason)
    ("adsystem", "ads", "banner", "Ad system"),
    ("adsafeprotected", "ads", "pixel", "Ad verification"),
    ("doubleclick", "ads", "adx", "DoubleClick"),
    ("googlesyndication", "ads", "banner", "Google Syndication"),
    ("googleadservices", "ads", "banner", "Google Ad Services"),
    ("googleadapis", "ads", "adx", "Google Ad APIs"),
    ("googleoptimize", "trackers", "pixel", "Google Optimize"),
    ("adservice", "ads", "banner", "Ad service"),
    ("adservices", "ads", "banner", "Ad services"),
    ("adnetwork", "adtech", "adx", "Ad network"),
    ("adexchange", "adtech", "adx", "Ad exchange"),
    ("adtech", "adtech", "adx", "Ad tech"),
    ("adscale", "ads", "banner", "AdScale"),
    ("adserver", "ads", "banner", "Ad server"),
    ("adserv", "ads", "banner", "Ad serving"),
    ("adsterra", "native", "popup", "Adsterra pop-unders"),
    ("admanmedia", "adtech", "adx", "Adman"),
    ("adform", "adtech", "adx", "Adform DSP"),
    ("adnxs", "adtech", "adx", "AppNexus/X"),
    ("adobedtm", "trackers", "pixel", "Adobe DTM tags"),
    ("adobedtm2", "trackers", "pixel", "Adobe DTM"),
    ("adtrue", "adtech", "adx", "AdTrue exchange"),
    ("advertising", "ads", "banner", "Ad serving"),
    ("admatic", "adtech", "adx", "AdMatic"),
    ("admixer", "adtech", "adx", "AdMixer"),
    ("adrta", "trackers", "pixel", "adRta"),
    ("adsbynimbus", "mobile", "sdk", "Nimbus mediation"),
    ("adcolony", "mobile", "sdk", "Ad Colony SDK"),
    ("admob", "mobile", "sdk", "AdMob SDK"),
    ("applovin", "mobile", "sdk", "AppLovin SDK"),
    ("ironsrc", "mobile", "sdk", "ironSource SDK"),
    ("unityads", "mobile", "sdk", "Unity Ads SDK"),
    ("unity3d", "mobile", "sdk", "Unity engine ads"),
    ("vungle", "mobile", "sdk", "Vungle SDK"),
    ("inmobi", "mobile", "sdk", "inMobi SDK"),
    ("startapp", "mobile", "sdk", "StartApp SDK"),
    ("pubnative", "mobile", "sdk", "PubNative SDK"),
    ("smaato", "mobile", "sdk", "Smaato SDK"),
    ("taboola", "native", "native", "Taboola native ads"),
    ("outbrain", "native", "native", "Outbrain native ads"),
    ("revcontent", "native", "native", "RevContent"),
    ("mgid", "native", "native", "MGID"),
    ("zedo", "adtech", "adx", "Zedo"),
    ("openx", "adtech", "adx", "OpenX"),
    ("pubmatic", "adtech", "adx", "PubMatic"),
    ("rubiconproject", "adtech", "adx", "Rubicon"),
    ("casalemedia", "adtech", "adx", "Casale Media"),
    ("indexww", "adtech", "adx", "Index Exchange"),
    ("sovrn", "adtech", "adx", "Sovrn"),
    ("sonobi", "adtech", "adx", "Sonobi"),
    ("yieldmo", "adtech", "adx", "YieldMo"),
    ("sharethrough", "adtech", "adx", "Sharethrough"),
    ("smartadserver", "adtech", "adx", "Smart AdServer"),
    ("criteo", "trackers", "retarget", "Criteo retargeting"),
    ("crsspxl", "trackers", "retarget", "Criteo pixel"),
    ("adsrvr", "trackers", "retarget", "Adobe AdServer"),
    ("adroll", "trackers", "retarget", "AdRoll"),
    ("bluekai", "trackers", "retarget", "BlueKai DMP"),
    ("demdex", "trackers", "retarget", "Adobe Audience Mgr"),
    ("exelator", "trackers", "retarget", "Exelator"),
    ("mediamath", "trackers", "retarget", "MediaMath"),
    ("invocacg", "trackers", "retarget", "Invoca"),
    ("moatads", "ads", "pixel", "moat ad verification"),
    ("scorecardresearch", "trackers", "pixel", "Comscore"),
    ("quantserve", "trackers", "pixel", "Quantcast"),
    ("chartbeat", "trackers", "pixel", "Chartbeat"),
    ("kissmetrics", "trackers", "pixel", "Kissmetrics"),
    ("mixpanel", "trackers", "pixel", "Mixpanel"),
    ("amplitude", "trackers", "pixel", "Amplitude"),
    ("flurry", "mobile", "pixel", "Flurry SDK"),
    ("segment", "trackers", "pixel", "Segment CDN"),
    ("tealium", "trackers", "pixel", "Tealium tags"),
    ("ensighten", "trackers", "pixel", "Ensighten tags"),
    ("hotjar", "telemetry", "telemetry", "Hotjar session capture"),
    ("clarity.ms", "telemetry", "telemetry", "MS Clarity"),
    ("crazyegg", "telemetry", "telemetry", "CrazyEgg"),
    ("mouseflow", "telemetry", "telemetry", "Mouseflow"),
    ("smartlook", "telemetry", "telemetry", "Smartlook"),
    ("logrocket", "telemetry", "telemetry", "LogRocket"),
    ("pendo", "telemetry", "telemetry", "Pendo"),
    ("qualtrics", "telemetry", "telemetry", "Qualtrics"),
    ("fullstory", "telemetry", "telemetry", "FullStory"),
    ("fingerprintjs", "fingerprint", "fingerprint", "FingerprintJS"),
    ("perimeterx", "fingerprint", "fingerprint", "PerimeterX"),
    ("pxcloud", "fingerprint", "fingerprint", "Human Security"),
    ("datadome", "fingerprint", "fingerprint", "DataDome"),
    ("ipify", "fingerprint", "fingerprint", "IP echo"),
    ("ipinfo", "fingerprint", "fingerprint", "IP info"),
    ("maxmind", "fingerprint", "fingerprint", "GeoIP lookup"),
    ("onesignal", "native", "push", "OneSignal push ads"),
    ("pushwoosh", "native", "push", "Pushwoosh"),
    ("pushnami", "native", "push", "PushNami"),
    ("engageya", "native", "push", "Engageya"),
    ("popcash", "native", "popup", "PopCash"),
    ("popads", "native", "popup", "PopAds"),
    ("propellerads", "native", "popup", "PropellerAds"),
    ("hilltopads", "native", "popup", "HilltopAds"),
    ("exoclick", "native", "popup", "ExoClick"),
    ("exosrv", "native", "popup", "ExoClick srv"),
    ("revenuehits", "native", "popup", "RevenueHits"),
    ("popmarker", "native", "popup", "PopMarker"),
    ("zybrdr", "native", "popup", "Zybrdr pop-ups"),
    ("imasdk", "video", "video", "IMA SDK"),
    ("innovid", "video", "video", "Innovid"),
    ("springserve", "video", "video", "SpringServe"),
    ("spotx", "video", "video", "SpotX"),
    ("tremorhub", "video", "video", "Tremor"),
    ("unruly", "video", "video", "Unruly"),
    ("videology", "video", "video", "Videology"),
    ("fwmrm", "video", "video", "FreeWheel"),
    ("adn.playwire", "video", "video", "Playwire"),
    ("smartclip", "video", "video", "Smartclip"),
    ("adsrv", "ads", "banner", "Ad server"),
    ("adxadserv", "adtech", "adx", "ADX serving"),
    ("amazon-adsystem", "ads", "banner", "Amazon Ads"),
    ("aax-us-east", "ads", "banner", "Amazon AX"),
    ("assoc-amazon", "ads", "shopping", "Amazon affiliate"),
    ("adscale", "ads", "banner", "AdScale"),
    ("adition", "adtech", "adx", "Adition"),
    ("adswizz", "adtech", "adx", "Adswizz audio ads"),
    ("aduptech", "adtech", "adx", "AdUp"),
    ("adspirit", "adtech", "adx", "AdSpirit"),
    ("adtarget", "trackers", "retarget", "AdTarget"),
    ("adtrace", "trackers", "pixel", "AdTrace"),
    ("advalanche", "adtech", "adx", "AdVanche"),
    ("adview", "ads", "banner", "AdView"),
    ("adworx", "adtech", "adx", "Adworx"),
    ("adzerk", "adtech", "adx", "Adzerk"),
    ("adzip", "adtech", "adx", "Adzip"),
    ("crypto-loot", "crypto", "malvertising", "Crypto miner"),
    ("coinhive", "crypto", "malvertising", "CoinHive"),
    ("coin-imp", "crypto", "malvertising", "CoinImp"),
    ("jsecoin", "crypto", "malvertising", "JSEcoin"),
    ("webminepool", "crypto", "malvertising", "WebMinePool"),
    ("hashing.win", "crypto", "malvertising", "hashing.win"),
    ("samsungads", "ctv", "ctv", "Samsung TV ads"),
)

AD_LABELS = frozenset([
    "ad", "ads", "ad1", "ad2", "ad3", "ad4", "ad5", "ad01", "ad02", "ad03", "ads1", "ads2",
    "adx", "adx1", "adn", "adn1", "adv", "advert", "advertising", "adserver", "adserver1",
    "adserv", "adserv1", "adservices", "adservice", "adcode", "adjs", "adjs2", "adimg",
    "adimg1", "adimg2", "adimgs", "adimage", "adimages", "admedia", "adnetwork", "adtech",
    "adexchange", "adsupply", "adupload", "adupload2", "adlog", "adlogos", "adlogger",
    "adlogserver", "admetrics", "adpixie", "adping", "adproxy", "adreport", "adreporting",
    "adsstatic", "adsstatics", "adsdata", "adstatic", "adstatics", "adstg", "adtest",
    "adtracking", "adtracker", "adunit", "adunits", "adframe", "adframes", "adbidding",
    "bid", "bids", "bidder", "biddr", "prebid", "adbid", "adsbid", "dfp", "doubleclick",
    "pubads", "pagead", "pagead2", "pagead46", "securepubads", "imasdk", "adnxs",
    "banner", "banners", "bannerads", "banneradserv", "sponsor", "sponsored", "sponsors",
    "sponsorad", "sponsoredads", "nativead", "nativeads", "in-feed-ads", "feedads",
    "pop", "popunder", "popunders", "popupads", "popads", "interstitial", "interstitials",
    "preroll", "midroll", "postroll", "instream", "instreamads", "videoads", "vast",
    "vastads", "adserver-vast", "adroll-sync", "sync2ad", "adsync", "adsync2", "adsync3",
    "match", "match.ads", "ib.adnxs", "cm", "cm1", "seg", "segments", "pixel", "pixels",
    "tpsc", "tpsc1", "tpsc-video", "adscout", "adspeed", "adspirit", "adtarget",
])

# 3rd-party ad "sync/segment" endpoints that live on publisher domains
SYNC_PATH_HOSTS = frozenset(["cm.g.doubleclick.net", "sync.1rx.io", "adsync.com",
                             "ib.adnxs.com", "match.adsrvr.org", "cms.quantserve.com"])

LABEL_TLD_GUARD = re.compile(r"^(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|co|io|me|tv|cc|xyz|online|site|shop|live|top|ru|cn|in|br|uk|de|fr|es|it|nl|pl|tr|jp|kr|au|ca|ch|se|no|dk|fi|be|at|ie|cz|gr|pt|ro|hu|ua|ru|za|mx|ar|cl|co\.id|co\.in|com\.br|com\.mx|co\.uk|com\.au|com\.sg|co\.jp|or\.kr)$")

# Hosts that *look* ad-ish but must keep working (advertiser dashboards, etc.)
AD_PORTAL_HOSTS = {
    "ads.tiktok.com", "ads.google.com", "ads.x.com", "ads.apple.com", "ads.microsoft.com",
    "ads.shopify.com", "ads.linkedin.com", "business.facebook.com", "marketing.linkedin.com",
    "business.tiktok.com", "ads.t.me", "ads_snap", "adservice.google.com",
    "business.twitter.com", "ads.nsf", "admanager.google.com", "adsmanager.facebook.com",
}


def _compile_patterns():
    """Compile the keyword table into one alternation regex + a lookup for metadata."""
    lookup, keys = {}, []
    for item in AD_KEYWORDS:
        if not isinstance(item, tuple) or len(item) != 4:
            continue
        if item[0] not in lookup:
            lookup[item[0]] = item[1:]
            keys.append(item[0])
    keys.sort(key=len, reverse=True)
    regex = re.compile("|".join(re.escape(k) for k in keys))
    return regex, lookup


PATTERN_RE, PATTERN_LOOKUP = _compile_patterns()

# High-confidence "this is an ad CDN edge" hostnames matched anywhere in the name
AD_HOST_RE = re.compile(
    r"(?:^|\.)(?:ads?|adx|adn|adv|adserver|adserv|adframe|adimg|adjs|adlog|admedia|adnetwork|"
    r"adtech|adexchange|adsupply|adupload|adbidding|prebid|bidder|banner|banners|popunder|"
    r"popup|interstitial|preroll|midroll|postroll|instream|videoads|nativeads?|sponsored|"
    r"doubleclick|pagead|pubads|imasdk|creative|creatives|trackads?|adtrk|adtrack|adlogos)"
    r"[0-9]{0,3}(?:\.|$)")

SUSPECT_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link",
                ".download", ".stream", ".party", ".win", ".bid", ".date", ".racing",
                ".trade", ".science", ".webcam", ".cam", ".adult", ".xxx", ".porn", ".bet")

BRAND_LOOKALIKES = ("google", "facebook", "instagram", "microsoft", "paypal", "amazon",
                    "apple", "netflix", "chase", "wellsfargo", "bankofamerica", "citibank",
                    "github", "coinbase", "binance", "telegram", "whatsapp", "tiktok",
                    "linkedin", "gmail", "outlook", "yahoo", "binance", "revolut", "n26")


GENERIC_TLDS = (".com", ".net", ".org", ".info", ".biz", ".co", ".io", ".shop",
                ".online", ".site", ".live", ".xyz", ".click", ".link")


def is_homograph(domain):
    """Punycode-encoded label on a generic TLD used to spoof an ASCII brand, e.g.
    xn--pple-43d.com -> apple.com.  IDN names on their own ccTLD/.eu style zones
    are left alone so legitimate international domains keep working."""
    labels = domain.split(".")
    if not any(lab.startswith("xn--") for lab in labels):
        return False
    joined = ".".join(labels)
    if not domain.endswith(GENERIC_TLDS):
        return False
    for brand in BRAND_LOOKALIKES:
        if brand in joined:
            return True
    for lab in labels:
        if lab.startswith("xn--") and len(lab) >= 8:
            return True
    return False


def is_dga(domain):
    """Entropy + consonant-cluster heuristics for algorithmically generated malware domains."""
    try:
        rd = registrable(domain)
        sld = rd.split(".")[0]
        if len(sld) < 9 or sld in ("www", "xn--"):
            return False
        if "-" in sld and sld.count("-") > 3:
            return True
        counts = {}
        for c in sld:
            counts[c] = counts.get(c, 0) + 1
        entropy = -sum((n / len(sld)) * math.log2(n / len(sld)) for n in counts.values())
        vowels = sum(1 for c in sld if c in "aeiou")
        digits = sum(1 for c in sld if c.isdigit())
        if entropy > 3.85 and len(sld) >= 12:
            return True
        if len(sld) >= 14 and entropy > 3.5 and vowels / float(max(1, len(sld))) < 0.25:
            return True
        if digits >= 4 and entropy > 3.3 and len(sld) >= 12:
            return True
        return False
    except Exception:
        return False


def is_typosquat(domain):
    try:
        rd = registrable(domain).split(".")[0]
        if len(rd) < 4 or "-" in rd:
            return False
        for brand in BRAND_LOOKALIKES:
            if rd == brand or rd in brand or brand in rd:
                continue
            if abs(len(rd) - len(brand)) > 2:
                continue
            if difflib_get_close(rd, brand):
                return True
    except Exception:
        pass
    return False


def difflib_get_close(a, b):
    import difflib
    return difflib.SequenceMatcher(None, a, b).ratio() > 0.80


# ──────────────────────────────────────────────
#  Gravity: build the in-memory blocklist
# ──────────────────────────────────────────────
def vector_active(vec, cat):
    if cat in SAFETY_CATS:
        return True
    switch = VECTOR_SWITCH.get(vec)
    if not switch:
        return True
    return cfg_bool(switch, True)


SAFETY_CATS = {"malware", "phishing", "spam", "security", "abuse", "crypto", "adult", "gambling"}

CUSTOM_PROTECTED = set()   # set by load_custom_lists(): users' own dashboard host etc.


def rebuild_master_blocklist(persist=True):
    """Merge every enabled feed + seed + patterns into the live lookup tables."""
    global BLOCKED, WILDCARDS, UNBREAK
    with LIST_LOCK:
        blocked, wildcards, unbreak = {}, {}, set()
        srcs = defaultdict(int)
        registry = all_lists()

        # 1. instant-protection seed (always on)
        for dom, vec in CORE_SEED.items():
            d = norm_domain(dom)
            if d:
                blocked[d] = ("ads" if vec in ("banner", "native") else "trackers", vec, "seed")

        # 2. enabled feeds
        for lid, info in registry.items():
            if lid not in CFG.get("enabled_lists", []):
                continue
            fpath = LIST_DIR / ("%s.txt" % lid)
            if not fpath.exists():
                continue
            e, w, u = list_file(fpath)
            cat, vec = info["cat"], info.get("vec", CAT.get(info["cat"], {}).get("vec", "banner"))
            if vector_active(vec, cat):
                for d in e:
                    if d not in blocked:
                        blocked[d] = (cat, vec, lid)
                for d in w:
                    if d not in wildcards:
                        wildcards[d] = (cat, vec, lid)
            unbreak |= u
            srcs[lid] = len(e) + len(w)

        # 3. user blacklist
        if CUSTOM_BLOCK.exists():
            for line in CUSTOM_BLOCK.read_text(errors="ignore").splitlines():
                d = norm_domain(line)
                if d:
                    blocked[d] = ("custom", "banner", "custom")
                    if d.count(".") > 1:
                        wildcards.setdefault(d, ("custom", "banner", "custom"))

        BLOCKED = blocked
        WILDCARDS = wildcards
        UNBREAK = unbreak
        stats = defaultdict(int), defaultdict(int)
        vcount, ccount = stats
        custom = set()
        for d, (cat, vec, _src) in blocked.items():
            vcount[vec] += 1
            ccount[cat] += 1
            if _src == "custom":
                custom.add(d)
        for d, (cat, vec, _src) in wildcards.items():
            vcount[vec] += 1
        VECTOR_COUNTS.clear()
        VECTOR_COUNTS.update(vcount)
        CAT_COUNTS.clear()
        CAT_COUNTS.update(ccount)
        if persist:
            save_gravity_cache(custom=custom)
        LOG.info("gravity rebuilt: %s exact + %s wildcard rules from %s feeds",
                 "{:,}".format(len(blocked)), "{:,}".format(len(wildcards)), len(srcs))
        return len(blocked)


def save_gravity_cache(custom=None):
    try:
        srcs = {}
        for lid in CFG.get("enabled_lists", []):
            p = LIST_DIR / ("%s.txt" % lid)
            if p.exists():
                st = p.stat()
                srcs[lid] = (st.st_mtime_ns, st.st_size)
        with open(GRAVITY_CACHE, "wb") as fh:
            pickle.dump({"v": CONFIG_VERSION, "srcs": srcs, "blocked": BLOCKED,
                         "wild": WILDCARDS, "unbreak": UNBREAK,
                         "vcounts": dict(VECTOR_COUNTS), "ccounts": dict(CAT_COUNTS)},
                        fh, protocol=4)
        # The custom tally goes in a sidecar: the main cache is hundreds of MB, and
        # rewriting it because one line was added to custom.block is not worth it.
        try:
            mark = None
            if CUSTOM_BLOCK.exists():
                st = CUSTOM_BLOCK.stat()
                mark = (st.st_mtime_ns, st.st_size)
            with open(META_DIR / "gravity.custom", "wb") as fh:
                pickle.dump({"mark": mark, "custom": set(custom or [])}, fh, protocol=4)
        except Exception:
            pass
    except Exception as exc:
        LOG.debug("gravity cache save skipped: %s", exc)


GRAVITY_CUSTOM = None


def load_gravity_cache():
    """Load the compiled blocklist so protection starts in milliseconds."""
    global BLOCKED, WILDCARDS, UNBREAK
    _t0 = time.time()
    if not GRAVITY_CACHE.exists():
        return False
    try:
        with open(GRAVITY_CACHE, "rb") as fh:
            data = pickle.load(fh)
        if data.get("v") != CONFIG_VERSION:
            return False
        srcs = data.get("srcs") or {}
        for lid, mark in srcs.items():
            p = LIST_DIR / ("%s.txt" % lid)
            if not p.exists():
                if lid in CFG.get("enabled_lists", []):
                    return False
                continue
            st = p.stat()
            if (st.st_mtime_ns, st.st_size) != tuple(mark):
                return False
        BLOCKED = data["blocked"]
        WILDCARDS = data["wild"]
        UNBREAK = data["unbreak"]
        # The vector/category tallies are stored with the cache: recounting 5M rules at
        # boot just to fill two small dicts was a second avoidable stall.
        vc, cc = data.get("vcounts"), data.get("ccounts")
        if vc is not None and cc is not None:
            VECTOR_COUNTS.clear(); CAT_COUNTS.clear()
            VECTOR_COUNTS.update(vc); CAT_COUNTS.update(cc)
        else:
            vcount, ccount = defaultdict(int), defaultdict(int)
            for d, (cat, vec, _s) in BLOCKED.items():
                vcount[vec] += 1
                ccount[cat] += 1
            for d, (cat, vec, _s) in WILDCARDS.items():
                vcount[vec] += 1
            VECTOR_COUNTS.clear(); CAT_COUNTS.clear()
            VECTOR_COUNTS.update(vcount); CAT_COUNTS.update(ccount)
        global GRAVITY_CUSTOM
        # The sidecar holds the custom entries the cache was built with. The file
        # itself is expected to differ - that is the whole point: whatever changed is
        # a small set of hand-written lines, applied by apply_custom_overrides().
        try:
            with open(META_DIR / "gravity.custom", "rb") as fh:
                side = pickle.load(fh)
            GRAVITY_CUSTOM = set(side.get("custom") or ()) if side.get("custom") is not None else None
        except Exception:
            GRAVITY_CUSTOM = None
        LOG.info("gravity cache restored: %s rules in %.1fs", "{:,}".format(len(BLOCKED)),
                 time.time() - _t0)
        return True
    except Exception as exc:
        LOG.debug("gravity cache unusable: %s", exc)
        return False


def apply_custom_overrides(custom_blocked):
    """Fold the operator's own block file into a restored cache.

    Rebuilding re-reads every feed: at 5M rules that is tens of seconds of silence
    while the supervisor waits for a health endpoint that cannot bind yet - long
    enough to look like a broken install, and it only ever has to learn about a
    handful of hand-written lines. Returns False when the cache cannot be trusted
    (no sidecar, or custom.block changed underneath it) so the caller rebuilds.
    """
    global GRAVITY_CUSTOM
    if GRAVITY_CUSTOM is None:
        return False
    changed = False
    for d in custom_blocked - GRAVITY_CUSTOM:
        BLOCKED[d] = ("custom", "banner", "custom")
        if d.count(".") > 1:
            WILDCARDS.setdefault(d, ("custom", "banner", "custom"))
        VECTOR_COUNTS["banner"] += 1
        CAT_COUNTS["custom"] += 1
        changed = True
    for d in GRAVITY_CUSTOM - custom_blocked:
        if BLOCKED.get(d, ("", "", ""))[2] == "custom":
            BLOCKED.pop(d, None)
            WILDCARDS.pop(d, None)
            VECTOR_COUNTS["banner"] = max(0, VECTOR_COUNTS.get("banner", 0) - 1)
            CAT_COUNTS["custom"] = max(0, CAT_COUNTS.get("custom", 0) - 1)
            changed = True
    if changed:
        GRAVITY_CUSTOM = set(custom_blocked)
        try:
            mark = None
            if CUSTOM_BLOCK.exists():
                st = CUSTOM_BLOCK.stat()
                mark = (st.st_mtime_ns, st.st_size)
            with open(META_DIR / "gravity.custom", "wb") as fh:
                pickle.dump({"mark": mark, "custom": GRAVITY_CUSTOM}, fh, protocol=4)
        except Exception as exc:
            LOG.debug("custom tally sidecar skipped: %s", exc)
    flush_caches()
    return True


def load_custom_lists():
    """User black/white lists + the fortress' own hostnames (never self-blocked)."""
    global CUSTOM_WHITELIST_SET
    blocked, allowed = set(), set()
    if CUSTOM_BLOCK.exists():
        for line in CUSTOM_BLOCK.read_text(errors="ignore").splitlines():
            d = norm_domain(line)
            if d:
                blocked.add(d)
    if CUSTOM_WHITE.exists():
        for line in CUSTOM_WHITE.read_text(errors="ignore").splitlines():
            d = norm_domain(line.lstrip("@!").strip())
            if d:
                allowed.add(d)
    CUSTOM_WHITELIST_SET = allowed | {d for d in CFG.get("always_allow", []) if norm_domain(d)}
    return blocked, allowed


CUSTOM_WHITELIST_SET = set()


def save_whitelist_entry(domain):
    domain = norm_domain(domain)
    if not domain:
        return None
    lines = []
    if CUSTOM_WHITE.exists():
        lines = [l.strip() for l in CUSTOM_WHITE.read_text(errors="ignore").splitlines() if l.strip()]
    if domain not in lines:
        lines.append(domain)
    atomic_write(CUSTOM_WHITE, "\n".join(lines) + "\n")
    load_custom_lists()
    return domain


def remove_block_entry(domain):
    domain = norm_domain(domain)
    if not domain or not CUSTOM_BLOCK.exists():
        return False
    lines = [l.strip() for l in CUSTOM_BLOCK.read_text(errors="ignore").splitlines()
             if l.strip() and l.strip() != domain and not l.startswith("#")]
    atomic_write(CUSTOM_BLOCK, "\n".join(lines) + ("\n" if lines else ""))
    rebuild_master_blocklist()
    return True

# ──────────────────────────────────────────────
#  Boot: config -> registry -> gravity
# ──────────────────────────────────────────────
load_config()
migrate_list_ids(CFG)
if not CFG.get("enabled_lists"):
    CFG["enabled_lists"] = list(DEFAULT_ENABLED)
    save_config()
init_list_status()
load_list_status()
load_custom_lists()
try:
    QUERY_LOGS = deque(QUERY_LOGS, maxlen=max(200, int(CFG.get("log_max", 3000))))
except Exception:
    pass
if not BLOCKED and not load_gravity_cache():
    rebuild_master_blocklist()
_sync_legacy_views()

# ──────────────────────────────────────────────
#  Decision cache (TTL + LRU) so repeat lookups never touch the lists
# ──────────────────────────────────────────────
class TTLCache(object):
    __slots__ = ("data", "maxsize", "lock")

    def __init__(self, maxsize=20000):
        self.data = OrderedDict()
        self.maxsize = maxsize
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            item = self.data.get(key)
            if not item:
                return None
            expiry, value = item
            if expiry < time.time():
                self.data.pop(key, None)
                return None
            self.data.move_to_end(key)
            return value

    def set(self, key, value, ttl):
        with self.lock:
            self.data[key] = (time.time() + ttl, value)
            self.data.move_to_end(key)
            while len(self.data) > self.maxsize:
                self.data.popitem(last=False)

    def clear(self):
        with self.lock:
            self.data = OrderedDict()

    def __len__(self):
        return len(self.data)


DECISION_CACHE = TTLCache(int(CFG.get("cache_size", 40000)))
UPSTREAM_CACHE = TTLCache(20000)


def flush_caches():
    DECISION_CACHE.clear()
    UPSTREAM_CACHE.clear()


# ──────────────────────────────────────────────
#  Layered classification engine
# ──────────────────────────────────────────────
def _allow(reason, cat="allow", vec="clean"):
    return {"action": "allow", "cat": cat, "vec": vec, "reason": reason,
            "color": "#10b981", "source": ""}


def _deny(cat, vec, reason, source=""):
    color = CAT.get(cat, {}).get("color", "#fb542b")
    if cat == "custom":
        color = "#fb542b"
    return {"action": "block", "cat": cat, "vec": vec, "reason": reason,
            "color": color, "source": source}


def classify(domain):
    """
    Full verdict for a hostname.  Layer order (first match wins):

      0. self-protection / explicit whitelist   -> allow
      1. exact blocklist hit                    -> block (feed category)
      2. wildcard hit (*.network)               -> block
      3. ad-portal exemption                    -> allow
      4. unbreak / anti-breakage exceptions     -> allow
      5. YouTube + in-video endpoints           -> block
      6. keyword pattern engine (micro/macro)   -> block
      7. label pattern engine (strict/nuclear)  -> block
      8. adware/malware heuristics (DGA, homograph, typosquat)
    """
    d = (domain or "").strip().rstrip(".").lower()
    if not d or "." not in d:
        return _allow("single-label")
    cached = DECISION_CACHE.get(d)
    if cached is not None:
        global CACHE_HITS
        CACHE_HITS += 1
        return cached

    res = _classify_uncached(d)
    ttl = CFG.get("cache_ttl", 300) if res["action"] == "allow" else CFG.get("block_ttl", 300)
    try:
        DECISION_CACHE.set(d, res, max(10, int(ttl)))
    except Exception:
        pass
    return res


def _classify_uncached(d):
    global PATTERN_HITS, WILDCARD_HITS

    # 0 - never block the fortress itself or the user allowlist
    if d in CUSTOM_WHITELIST_SET or any(d.endswith("." + w) for w in CUSTOM_WHITELIST_SET):
        return _allow("Whitelisted", "custom")

    parts = d.split(".")
    parents = [".".join(parts[i:]) for i in range(1, len(parts))]

    def feed_hit(dom):
        hit = BLOCKED.get(dom)
        if not hit:
            return None
        cat, vec, src = hit
        if not vector_active(vec, cat):
            return None
        return _deny(cat, vec, "Blocklist (%s)" % CAT.get(cat, {}).get("name", cat), src)

    # 1 - safety feeds always win, even over anti-breakage exceptions
    direct = feed_hit(d)
    if direct and direct["cat"] in SAFETY_CATS:
        return direct

    # 2 - anti-breakage exceptions (uBlock "unbreak" style) protect legit services
    if d in UNBREAK or any(p in UNBREAK for p in parents):
        return _allow("Unbreak rule")

    # 3 - curated ad/tracker feeds
    if direct:
        return direct
    for parent in parents:
        if CFG.get("wildcard_engine", True):
            wc = WILDCARDS.get(parent)
            if wc:
                cat, vec, src = wc
                if vector_active(vec, cat):
                    WILDCARD_HITS += 1
                    return _deny(cat, vec, "Wildcard (*.%s)" % parent, src)
        hit = feed_hit(parent)
        if hit:
            return hit

    # 4 - advertiser dashboards stay reachable (and so does the personalized-ads opt-out
    # panel at adssettings.google.com, which is a control, not an ad)
    if d in AD_PORTAL_HOSTS or d == "adssettings.google.com":
        return _allow("Ad portal" if d in AD_PORTAL_HOSTS else "Ad opt-out controls")

    # 5 - YouTube / in-video ad + player telemetry endpoints
    if d in YT_AD_HOSTS or (CFG.get("youtube_aggressive", True) and YT_EDGE_RE.search(d)):
        if cfg_bool("invideo_ads", True) or cfg_bool("youtube_aggressive", True):
            return _deny("video", "video", "In-video ad endpoint", "youtube")

    if CFG.get("block_mode") == "nuclear" and d in NUCLEAR_ONLY_HOSTS:
        return _deny("telemetry", "telemetry", "Nuclear-only endpoint", "heuristics")

    # 5b - hard ad labels: armed even inside trusted zones.  google.com is trusted so
    # "ads.google.com" must survive, but adservice.google.<cc> / pagead.google.<cc> are
    # pure ad endpoints wearing a trusted family name, so they die here regardless.
    head = d.split(".", 1)[0]
    if head in HARD_AD_LABELS and in_google_estate(d):
        return _deny("ads", "banner", "Ad endpoint in a trusted zone", "patterns")

    # 6 - keyword engine on the registrable domain (all modes)
    if cfg_bool("pattern_engine", True) and not is_trusted(d):
        rd = registrable(d)
        m = PATTERN_RE.search(rd)
        if m:
            cat, vec, reason = PATTERN_LOOKUP.get(m.group(0), ("ads", "banner", "Ad pattern"))
            if vector_active(vec, cat):
                PATTERN_HITS += 1
                if CFG.get("pattern_action", "enforce") == "shadow" or CFG.get("block_mode") == "balanced":
                    return _allow("Shadow: %s" % reason, "patterns", vec)
                return _deny(cat, vec, "Pattern (%s)" % reason, "patterns")

    # 7 - ad-infrastructure host label engine (strict / nuclear only)
    if CFG.get("block_mode") in ("strict", "nuclear") and len(parts) >= 3 and not is_trusted(d):
        label = parts[0]
        parent = ".".join(parts[1:])
        if (label in AD_LABELS or AD_HOST_RE.match(label + ".")) and not is_trusted(parent) \
                and LABEL_TLD_GUARD.search(parent):
            if cfg_bool("micro_ads", True):
                PATTERN_HITS += 1
                if CFG.get("pattern_action", "enforce") == "shadow":
                    return _allow("Shadow: %s. host" % label, "patterns", "banner")
                return _deny("ads", "banner", "Ad infra host (%s.)" % label, "labels")

    # 8 - malware / adware heuristics
    if cfg_bool("dga_protection", True) and is_dga(d):
        return _deny("malware", "malvertising", "DGA / algorithmic domain", "heuristics")
    if is_homograph(d):
        return _deny("phishing", "malvertising", "Homograph / IDN spoof", "heuristics")
    if cfg_bool("typosquat_protection", False) and is_typosquat(d):
        return _deny("phishing", "malvertising", "Brand typosquat", "heuristics")
    if CFG.get("block_mode") == "nuclear" and d.endswith(SUSPECT_TLDS):
        return _deny("spam", "shortlink", "Low-reputation TLD", "heuristics")

    return _allow("Clean")


# ──────────────────────────────────────────────
#  YouTube / in-video ad endpoints (DNS-visible part)
# ──────────────────────────────────────────────
YT_AD_HOSTS = set()
_YT_EXACT = [
    "s.youtube.com", "video-stats.l.google.com", "video-stats.youtube.com",
    "pagead2.googlesyndication.com", "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net", "static.doubleclick.net", "ad.doubleclick.net",
    "imasdk.googleapis.com", "youtubeadsdk.com",
    "googleadservices.com", "partner.googleadservices.com", "adservice.google.com",
    "ad-delivery.net", "ad-sys.com", "adserver.yahoo.com",
    "spc.tubecorp.com", "api.ad.xiaomi.com",
    "admaven.co", "pubads.g.doubleclick.net", "staticads.youtube.com",
    "yt-ad-ua.googlevideo.com", "youtubei.googleapis.com",
]
YT_AD_HOSTS.update(_YT_EXACT)
for _i in range(1, 26):
    for _sn in ("sn-4g5edn7s", "sn-vgqsrn7e", "sn-aigl6ned", "hp576n7e", "q4fl6n7s",
                "axq-n02xo", "5uaeznrz6", "4w-a0qmge", "5uaeznr6", "ux3-cxxs", "n6-3obd"):
        YT_AD_HOSTS.add("r%d---sn-%s.googlevideo.com" % (_i, _sn))
YT_EDGE_RE = re.compile(
    r"^(?:r\d+---sn-(?:4g5edn7s|vgqsrn7e|aigl6ned|hp576n7e|q4fl6n7s)\.googlevideo\.com$"
    r"|(?:staticads|ad|ads|adstats|adservice|pagead)\.youtube\.com$"
    r"|ads\.(?:tv\.)?(?:youtube|google)\.com$)")

# Google owns the ad tech *and* the trusted zones, so "adservice.google.ae" and
# "pagead.google.com" are ad endpoints wearing a family name we otherwise protect.
# The override is scoped to that estate only, so unrelated hosts that merely share a
# label (dart.dev, admaven.co) stay reachable.
GOOGLE_ESTATE_RE = re.compile(
    r"(?:^|\.)(?:google(?:\.[a-z]{2,3}){1,2}|googleapis\.com|gstatic\.com|googlevideo\.com"
    r"|googlesyndication\.com|googleadservices\.com|ggpht\.com|youtube\.com|youtube-nocookie\.com)$")


def in_google_estate(domain):
    return bool(GOOGLE_ESTATE_RE.search(norm_domain(domain)))


# First-label ad endpoints that live under a trusted zone (blocked before the guard).
HARD_AD_LABELS = frozenset([
    "adservice", "pagead", "googleadsserving", "adsense", "admob", "doubleclick",
    "googlesyndication", "googleadservices", "adinterax", "adsystem",
])

# Only armed in `nuclear`: these carry player/analytics config, so blocking them can
# inconvenience a client (GA UI, third-party YouTube apps) as much as it stops tracking.
NUCLEAR_ONLY_HOSTS = frozenset([
    "youtube.googleapis.com", "analytics.google.com", "secure-data-reporting.googleapis.com",
])

# ──────────────────────────────────────────────
#  AI triage (OpenRouter, optional)
# ──────────────────────────────────────────────
FALLBACK_MODELS = [
    "openrouter/free", "meta-llama/llama-3.2-3b-instruct:free",
    "google/gemma-2-9b-it:free", "mistralai/mistral-small-24b-instruct-2501:free",
]
AI_CACHE = TTLCache(5000)


def ask_openrouter_ai(domain):
    """Ask a free-tier LLM to classify an unknown domain. Returns dict or None."""
    global AI_QUERIES
    api_key = (CFG.get("openrouter_api_key") or "").strip()
    if not api_key or not cfg_bool("ai_triage", False):
        return None
    cached = AI_CACHE.get(domain)
    if cached is not None:
        return cached
    try:
        AI_QUERIES += 1
        headers = {"Authorization": "Bearer %s" % api_key,
                   "HTTP-Referer": "http://localhost", "X-Title": "NetBlock Fortress",
                   "Content-Type": "application/json"}
        prompt = ("Classify the domain '%s' for a network ad blocker. Is it advertising, "
                  "tracking, malware, phishing, telemetry or a legitimate service? "
                  'Reply JSON only: {"verdict":"block|allow","cat":"ads|trackers|malware|'
                  'phishing|telemetry|clean","reason":"short"}' % domain)
        for model in [CFG.get("ai_model", "openrouter/free")] + FALLBACK_MODELS:
            try:
                res = requests.post("https://openrouter.ai/api/v1/chat/completions",
                                    headers=headers, timeout=6,
                                    json={"model": model, "max_tokens": 120, "temperature": 0.1,
                                          "messages": [{"role": "user", "content": prompt}]})
                if res.status_code == 200:
                    txt = res.json()["choices"][0]["message"]["content"]
                    m = re.search(r"\{.*\}", txt, re.DOTALL)
                    if m:
                        parsed = json.loads(m.group(0))
                        AI_CACHE.set(domain, parsed, 86400)
                        return parsed
            except Exception:
                continue
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────
#  Upstream resolution: plain UDP or DNS-over-HTTPS, both cached
# ──────────────────────────────────────────────
_qtype_names = {QTYPE.A: "A", QTYPE.AAAA: "AAAA", QTYPE.CNAME: "CNAME", QTYPE.MX: "MX",
                QTYPE.TXT: "TXT", QTYPE.NS: "NS", QTYPE.SOA: "SOA", QTYPE.PTR: "PTR"}


def upstream_name(qtype):
    return _qtype_names.get(qtype, "A")


def _doh_resolve(qname, qtype_str):
    """DNS-over-HTTPS (RFC 8484 wire format) - used when UDP/53 is filtered."""
    try:
        req = DNSRecord.question(qname, qtype_str)
        resp = requests.post(CFG.get("doh_upstream", "https://cloudflare-dns.com/dns-query"),
                             data=req.pack(), timeout=3.0,
                             headers={"Content-Type": "application/dns-message",
                                      "User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return None
        return DNSRecord.parse(resp.content)
    except Exception:
        return None


def _udp_resolve(qname, qtype_str):
    sock = None
    try:
        req = DNSRecord.question(qname, qtype_str)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(req.pack(), (CFG.get("dns_upstream", "1.1.1.1"), 53))
        data, _ = sock.recvfrom(65535)
        return DNSRecord.parse(data)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def resolve_upstream(qname, qtype=QTYPE.A, use_cache=True):
    qtype_str = qtype if isinstance(qtype, str) else upstream_name(qtype)
    key = (qname, qtype_str)
    if use_cache:
        hit = UPSTREAM_CACHE.get(key)
        if hit is not None:
            return hit[0] if hit[0] is not None else None
    mode = CFG.get("upstream_mode", "auto")
    answer = None
    if mode in ("doh", "auto"):
        answer = _doh_resolve(qname, qtype_str)
        if answer is None and mode == "auto":
            answer = _udp_resolve(qname, qtype_str)
    else:
        answer = _udp_resolve(qname, qtype_str)
    if answer is None and mode == "udp":
        answer = _doh_resolve(qname, qtype_str)
    try:
        UPSTREAM_CACHE.set(key, (answer, time.time()),
                           max(15, int(CFG.get("cache_ttl", 300)) if answer else int(CFG.get("neg_ttl", 60))))
    except Exception:
        pass
    return answer


def is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved)
    except Exception:
        return False

# ──────────────────────────────────────────────
#  Protection profiles (shared by web UI + `adquit mode`)
# ──────────────────────────────────────────────
def _ids(*names):
    return list(names)


AD_CORE = _ids("stevenblack", "adguard_dns", "oisd_big", "hagezi_pro", "easylist",
               "peterlowe", "yt_blockads", "d3ward", "swb_ads", "swb_wild_ads", "1hosts_lite",
               "adguard_base", "ublock_filters", "hagezi_adshield")
AD_MACRO = AD_CORE + _ids("adguard_popups", "adguard_annoy", "ublock_annoy", "ublock_annoy_oth",
                          "hagezi_popup", "adguard_widgets", "adguard_dnsfilter",
                          "hagezi_native_samsung", "hagezi_native_lg", "hagezi_native_roku",
                          "hagezi_native_amazon", "perflyst_smarttv", "smarttv_agh",
                          "perflyst_firetv", "ublock_unbreak")
AD_MICRO = _ids("ublock_priv", "easyprivacy", "swb_tracking", "swb_marketing", "swb_junk",
                "adguard_spyware", "adguard_trackparam", "adguard_mail", "perflyst_replay",
                "winspy", "hagezi_native_apple", "hagezi_native_win", "swb_apple", "swb_ms",
                "swb_ai", "swb_fonts", "hagezi_social", "adguard_mobile", "adguard_mobileapp",
                "ublock_mobile", "perflyst_android", "hagezi_native_oppo", "hagezi_native_xiaomi",
                "hagezi_native_vivo", "hagezi_native_huawei", "hagezi_native_tiktok",
                "ublock_resabuse", "adguard_excl", "swb_chat")
THREAT = _ids("urlhaus", "sslbl", "rpi_mal", "rpi_mobsf", "rpi_crypto", "rpi_fake", "rpi_phish",
              "phisharmy", "openphish", "phishdb", "swb_malware", "swb_scam", "swb_tld",
              "dshield", "emerging", "blocklist_de", "sb_phish", "hagezi_tif", "hagezi_fake",
              "swb_typo", "swb_risk")
ABUSE = _ids("spamhaus_drop", "blocklist_de_all", "nocoin", "coinblocker", "coinbrowser",
             "hagezi_dyndns", "hagezi_hoster", "hagezi_spamtld", "hagezi_urlshort",
             "ubock_shorteners", "swb_urlshort", "swb_tunnels", "swb_free", "swb_dynamic",
             "hagezi_referral")
FAMILY = _ids("sb_porn", "sin_porn", "oisd_nsfw", "sb_gamble", "sin_gamble", "swb_adult",
              "swb_gambling", "hagezi_nsfw", "hagezi_gamble", "hagezi_gamble_m", "hagezi_piracy")
REGIONAL = _ids("adguard_german", "adguard_french", "adguard_italian", "adguard_spanish",
                "adguard_dutch", "adguard_turkish", "adguard_japanese", "adguard_polish",
                "adguard_ukrainian", "adguard_russian", "yhosts_cn", "easylist_de", "easylist_fr",
                "easylist_es", "easylist_it", "easylist_nl")

MODES = {
    "off":       {"name": "Protection Off",  "lists": [],
                  "desc": "Resolver only - no blocking (downloads, updates, IoT setup)"},
    "balanced":  {"name": "Balanced",        "lists": AD_CORE + _ids("urlhaus", "phisharmy"),
                  "desc": "Heavy ad networks + malware. Zero breakage, safe for any device"},
    "strict":    {"name": "Strict",         "lists": AD_MACRO + AD_MICRO + THREAT + ABUSE,
                  "desc": "Full macro + micro coverage: banners, video, in-app SDKs, pixels, "
                          "fingerprinting, telemetry and threat feeds"},
    "family":    {"name": "Family & Safe",  "lists": AD_MACRO + AD_MICRO + THREAT + ABUSE + FAMILY,
                  "desc": "Strict plus adult, gambling and piracy blocking + SafeSearch"},
    "nuclear":   {"name": "Nuclear",        "lists": (AD_MACRO + AD_MICRO + THREAT + ABUSE +
                                                       FAMILY + REGIONAL + _ids(
                                                       "hagezi_ultimate", "hagezi_pro_plus",
                                                       "1hosts_xtra", "hagezi_doh")),
                  "desc": "Every feed, heuristics at max, low-reputation TLDs blocked. "
                          "Expect the occasional legit site to need an allow entry"},
    "custom":    {"name": "Custom",         "lists": None, "desc": "Your own selection"},
}


def mode_lists(mode):
    info = MODES.get(mode) or MODES["strict"]
    return list(info["lists"]) if info["lists"] is not None else list(CFG.get("enabled_lists", []))


def apply_mode(mode, persist=True):
    if mode not in MODES:
        return False
    CFG["block_mode"] = mode
    spec = MODES[mode]["lists"]
    if spec is not None:
        CFG["enabled_lists"] = mode_lists(mode)
    # mode level micro-tuning
    tuning = {
        "off": {},
        "balanced": {"pattern_engine": True, "pattern_action": "shadow", "typosquat_protection": False},
        "strict": {"pattern_engine": True, "pattern_action": "enforce", "typosquat_protection": False},
        "family": {"pattern_engine": True, "pattern_action": "enforce", "safe_search": True},
        "nuclear": {"pattern_engine": True, "pattern_action": "enforce", "typosquat_protection": True,
                    "safe_search": True, "wildcard_engine": True, "dga_protection": True},
    }.get(mode, {})
    CFG.update(tuning)
    for lid in all_lists():
        if lid in LIST_STATUS:
            LIST_STATUS[lid]["enabled"] = lid in CFG.get("enabled_lists", [])
    if persist:
        save_config()
        save_list_status()
        rebuild_master_blocklist()
        flush_caches()
    return True


# ──────────────────────────────────────────────
#  Feed downloader (conditional GET, retries, concurrency)
# ──────────────────────────────────────────────
def fetch_list(lid, session=None):
    registry = all_lists()
    info = registry.get(lid)
    if not info:
        return 0
    st = LIST_STATUS.setdefault(lid, {"name": info["name"], "cat": info["cat"],
                                      "vec": info.get("vec", "banner"), "url": info["url"],
                                      "enabled": True, "state": "idle", "count": 0,
                                      "last_updated": "Never", "error": None})
    out = LIST_DIR / ("%s.txt" % lid)
    meta = META_DIR / ("%s.http.json" % lid)
    st.update({"state": "downloading", "error": None})
    save_list_status()
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
    if meta.exists() and out.exists():
        try:
            headers.update(json.loads(meta.read_text()))
        except Exception:
            pass
    http = session or requests
    err = None
    for attempt in range(3):
        try:
            res = http.get(info["url"], headers=headers, timeout=45, stream=True)
            if res.status_code == 304:
                count = len(parse_source_bytes(out.read_bytes())[0])
                st.update({"state": "active", "count": count,
                           "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M") + " (fresh)",
                           "error": None})
                save_list_status()
                return count
            if res.status_code >= 400:
                err = "HTTP %s" % res.status_code
                raise RuntimeError(err)
            raw = res.content
            tmp = Path(str(out) + ".part")
            tmp.write_bytes(raw)
            tmp.replace(out)
            try:
                cache_meta = {k: res.headers[k] for k in ("ETag", "Last-Modified") if k in res.headers}
                meta.write_text(json.dumps(cache_meta))
            except Exception:
                pass
            count = len(parse_source_bytes(raw)[0])
            st.update({"state": "active", "count": count,
                       "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M"), "error": None})
            save_list_status()
            return count
        except Exception as exc:
            err = str(exc)[:120]
            time.sleep(1.5 * (attempt + 1))
    st.update({"state": "error", "error": err or "download failed"})
    if not out.exists():
        st["count"] = 0
    save_list_status()
    return st.get("count", 0)


_REFRESHING = threading.Lock()
REFRESH_PROGRESS = {"running": False, "done": 0, "total": 0, "started": None}


def refresh_all(force=False, only_missing=False):
    """Pull every enabled feed in parallel, then rebuild gravity."""
    if not _REFRESHING.acquire(blocking=False):
        return {"skipped": True, "reason": "refresh already running"}
    try:
        enabled = [l for l in CFG.get("enabled_lists", []) if l in all_lists()]
        if only_missing:
            enabled = [l for l in enabled if not (LIST_DIR / ("%s.txt" % l)).exists()]
        if not only_missing:
            stale = []
            for l in enabled:
                p = LIST_DIR / ("%s.txt" % l)
                age_hours = (time.time() - p.stat().st_mtime) / 3600.0 if p.exists() else 1e9
                if age_hours >= max(1, int(CFG.get("refresh_hours", 24))):
                    stale.append(l)
            enabled = stale or enabled
        REFRESH_PROGRESS.update({"running": True, "done": 0, "total": len(enabled),
                                 "started": datetime.now().strftime("%H:%M:%S")})
        LOG.info("pulling %s feeds...", len(enabled))
        t0 = time.time()
        if enabled:
            with ThreadPoolExecutor(max_workers=8) as pool:
                sess = requests.Session()
                adapter_args = {}
                for _lid in pool.map(lambda l: fetch_list(l, sess), enabled):
                    REFRESH_PROGRESS["done"] += 1
        rebuild_master_blocklist()
        flush_caches()
        LOG.info("gravity updated in %.1fs (%s rules)", time.time() - t0,
                 "{:,}".format(len(BLOCKED)))
        REFRESH_PROGRESS.update({"running": False, "finished": datetime.now().strftime("%H:%M:%S")})
        return {"feeds": len(enabled), "rules": len(BLOCKED), "seconds": round(time.time() - t0, 1)}
    finally:
        _REFRESHING.release()


def gravity_boot_worker():
    """First-run experience: seed immediately, download feeds in the background."""
    time.sleep(1)
    need = [l for l in CFG.get("enabled_lists", []) if not (LIST_DIR / ("%s.txt" % l)).exists()]
    if need:
        LOG.info("%s feeds missing - initial gravity pull in progress", len(need))
        refresh_all(only_missing=True)
    while True:
        try:
            interval = max(300, int(CFG.get("refresh_hours", 24)) * 3600)
            time.sleep(interval)
            if cfg_bool("auto_refresh", True):
                refresh_all()
                rebuild_master_blocklist()
        except Exception as exc:
            LOG.warning("refresh cycle failed: %s", exc)
            time.sleep(300)


# ──────────────────────────────────────────────
#  Stats plumbing
# ──────────────────────────────────────────────
def _record(client, domain, qtype, verdict, blocked):
    with _stats_lock:
        global TOTAL_QUERIES, BLOCKED_QUERIES, ALLOWED_QUERIES
        TOTAL_QUERIES += 1
        act = CLIENT_ACTIVITY[client]
        act["total"] += 1
        act["last_seen"] = time.time()
        if blocked:
            BLOCKED_QUERIES += 1
            act["blocked"] += 1
            if verdict["cat"] in SAFETY_CATS:
                act["threats"] += 1
            else:
                act["ads"] += 1
            TOP_GLOBAL[domain] += 1
            act["names"][domain] = act["names"].get(domain, 0) + 1
            if len(act["names"]) > 40:
                top = sorted(act["names"].items(), key=lambda kv: -kv[1])[:25]
                act["names"] = dict(top)
            HOURLY[datetime.now().hour] += 1
            HOURLY_BLOCKED[datetime.now().hour] += 1
        else:
            ALLOWED_QUERIES += 1
    if cfg_bool("log_enabled", True):
        QUERY_LOGS.appendleft({
            "time": now_hm(), "client": client, "domain": domain, "type": qtype,
            "status": "Blocked" if blocked else "Allowed",
            "reason": verdict["reason"], "cat": verdict.get("cat", "clean"),
            "color": verdict.get("color", "#10b981"), "vec": verdict.get("vec", ""),
        })
        _log_line(client, domain, qtype, blocked, verdict)


_log_writes = 0
_log_last = [0.0]


def _log_line(client, domain, qtype, blocked, verdict):
    """Append to data/queries.jsonl (sampled 1-in-8, plus a flush every 2s) with
    size-based rotation (10 MB, keep 1)."""
    global _log_writes
    _log_writes += 1
    now = time.time()
    if _log_writes % 8 != 0 and now - _log_last[0] > 2.0:
        return
    _log_last[0] = now
    try:
        if QUERY_LOG.exists() and QUERY_LOG.stat().st_size > 10 * 1024 * 1024:
            QUERY_LOG.replace(Path(str(QUERY_LOG) + ".1"))
        with open(QUERY_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "c": client,
                                 "d": domain, "q": qtype, "b": 1 if blocked else 0,
                                 "r": verdict.get("reason"), "cat": verdict.get("cat"),
                                 "v": verdict.get("vec")}) + "\n")
    except Exception:
        pass


def snapshot_stats():
    data = {"version": VERSION, "codename": CODENAME, "updated": int(time.time()),
            "total": TOTAL_QUERIES, "blocked": BLOCKED_QUERIES, "allowed": ALLOWED_QUERIES,
            "rules": len(BLOCKED), "wildcards": len(WILDCARDS), "clients": len(CLIENT_ACTIVITY),
            "pattern_hits": PATTERN_HITS, "wildcard_hits": WILDCARD_HITS,
            "cache_hits": CACHE_HITS, "cache_size": len(DECISION_CACHE),
            "uptime": int(time.time() - START_TIME), "mode": CFG.get("block_mode"),
            "vectors": dict(VECTOR_COUNTS), "categories": dict(CAT_COUNTS),
            "top": sorted(TOP_GLOBAL.items(), key=lambda kv: -kv[1])[:25]}
    try:
        atomic_write(SNAPSHOT_FILE, json.dumps(data))
    except Exception:
        pass
    return data


def housekeeping_worker():
    last_hour = datetime.now().hour
    while True:
        time.sleep(20)
        try:
            now = datetime.now()
            if now.hour != last_hour:
                last_hour = now.hour
                LOG.info("hour boundary - snapshotting stats")
            snapshot_stats()
            cutoff = time.time() - 120
            for ip in list(CLIENT_RATES.keys()):
                keep = [t for t in CLIENT_RATES[ip] if t > cutoff]
                if keep:
                    CLIENT_RATES[ip] = keep
                else:
                    CLIENT_RATES.pop(ip, None)
            if len(TOP_GLOBAL) > 4000:
                top = sorted(TOP_GLOBAL.items(), key=lambda kv: -kv[1])[:1000]
                TOP_GLOBAL.clear()
                TOP_GLOBAL.update(dict(top))
        except Exception:
            pass


# ──────────────────────────────────────────────
#  DNS servers (UDP + TCP, bounded thread pool)
# ──────────────────────────────────────────────
SAFE_SEARCH_TARGETS = {
    "google": ("www.google.com", "forcesafe-search.com"),
    "youtube": ("www.youtube.com", "restrict.youtube.com"),
    "bing": ("www.bing.com", "strict.bing.com"),
    "duckduckgo": ("duckduckgo.com", None),
}
SAFE_SEARCH_HOSTS = {
    "www.google.com": "forcesafe-search.com", "google.com": "forcesafe-search.com",
    "images.google.com": "forcesafe-search.com", "www.youtube.com": "restrict.youtube.com",
    "m.youtube.com": "restrict.youtube.com", "youtube.com": "restrict.youtube.com",
    "www.bing.com": "strict.bing.com", "bing.com": "strict.bing.com",
    "www.google.co.uk": "forcesafe-search.com", "www.google.de": "forcesafe-search.com",
    "www.google.fr": "forcesafe-search.com", "www.google.ca": "forcesafe-search.com",
    "www.google.com.au": "forcesafe-search.com", "www.google.co.in": "forcesafe-search.com",
    "www.google.co.jp": "forcesafe-search.com", "kids.youtube.com": "restrictedmoderesearch.com",
}


def fortress_ip():
    ip = (CFG.get("sinkhole_ip") or "").strip()
    if ip:
        return ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    CFG["sinkhole_ip"] = ip
    return ip


def build_reply(question_record, q, verdict, blocked):
    reply = question_record.reply()
    if not blocked:
        return reply, None
    mode = CFG.get("sinkhole_mode", "zeroip")
    if mode == "nxdomain":
        reply.header.rcode = RCODE.NXDOMAIN
        return reply, "nxdomain"
    if q.qtype == QTYPE.A:
        target = "0.0.0.0"
        if mode == "fortress":
            target = fortress_ip()
        reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1,
                        ttl=int(CFG.get("block_ttl", 300)), rdata=A(target)))
    elif q.qtype == QTYPE.AAAA:
        reply.add_answer(RR(rname=q.qname, rtype=QTYPE.AAAA, rclass=1,
                        ttl=int(CFG.get("block_ttl", 300)), rdata=AAAA("::")))
    return reply, "sinkhole"

def handle_dns_request(data, addr, send):
    global BLOCKED_QUERIES, DROPPED
    client_ip = addr[0]
    if cfg_bool("rate_limiting", True) and not rate_limit_check(client_ip):
        SECURITY_EVENTS.append({"time": now_hm(), "type": "Rate Limit Exceeded",
                               "client": client_ip,
                               "detail": "above %s qps" % CFG.get("rate_limit_rps", 500)})
        return
    try:
        question = DNSRecord.parse(data)
    except Exception:
        DROPPED += 1
        return
    if not question.questions:
        return
    q = question.questions[0]
    qname = str(q.qname).rstrip(".").lower()
    qtype_str = str(QTYPE.get(q.qtype, "TYPE%s" % q.qtype))

    # DNS amplification / reflection defence
    if cfg_bool("amplification_protection", True) and qtype_str in ("ANY", "AXFR", "MAILA", "MAILB"):
        reply = question.reply()
        reply.header.rcode = RCODE.REFUSED
        send(reply.pack(), addr)
        SECURITY_EVENTS.append({"time": now_hm(), "type": "Amplification Blocked",
                               "client": client_ip, "detail": "%s %s" % (qtype_str, qname)})
        return

    # never forward link/local names upstream
    if qname.endswith((".local", ".internal", ".home.arpa", ".lan", ".localdomain")) or not qname:
        reply = question.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        send(reply.pack(), addr)
        _record(client_ip, qname, qtype_str, _allow("local name"), False)
        return

    verdict = classify(qname) if qname else _allow("empty")
    blocked = verdict["action"] == "block"

    if blocked:
        reply, _mode = build_reply(question, q, verdict, True)
        send(reply.pack(), addr)
        if verdict["cat"] in SAFETY_CATS and verdict["cat"] in ("malware", "phishing", "spam",
                                                                "security", "abuse"):
            SECURITY_EVENTS.append({"time": now_hm(), "type": "%s blocked" % verdict["cat"].title(),
                                   "client": client_ip, "detail": "%s (%s)" % (qname, verdict["reason"])})
        _record(client_ip, qname, qtype_str, verdict, True)
        return

    if "shadow" in verdict.get("reason", "").lower():
        SECURITY_EVENTS.append({"time": now_hm(), "type": "Pattern Shadow Hit",
                               "client": client_ip, "detail": "%s -> %s" % (qname, verdict["reason"])})

    # SafeSearch / restricted-mode enforcement
    if cfg_bool("safe_search", False) and qtype_str == "A" and qname in SAFE_SEARCH_HOSTS:
        target = SAFE_SEARCH_HOSTS[qname]
        up = resolve_upstream(target, QTYPE.A)
        reply = question.reply()
        if up:
            for rr in up.rr:
                if rr.rtype == QTYPE.A:
                    reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1, ttl=300,
                                    rdata=A(str(rr.rdata))))
            send(reply.pack(), addr)
            _record(client_ip, qname, qtype_str, _allow("SafeSearch"), False)
            return

    # CNAME uncloaking: a "first-party" alias may hide a known tracker
    if qtype_str in ("A", "AAAA") and cfg_bool("cname_uncloaking", True):
        up = resolve_upstream(qname, QTYPE.CNAME)
        if up:
            for rr in up.rr:
                if rr.rtype != QTYPE.CNAME:
                    continue
                target = str(rr.rdata).rstrip(".").lower()
                if not target or target == qname:
                    continue
                inner = classify(target)
                if inner["action"] == "block":
                    global CNAME_HITS
                    CNAME_HITS += 1
                    v2 = dict(inner, reason="CNAME cloaked: %s" % target)
                    reply, _m = build_reply(question, q, v2, True)
                    send(reply.pack(), addr)
                    _record(client_ip, qname, qtype_str, v2, True)
                    return

    resolved = resolve_upstream(qname, q.qtype)
    if resolved is None:
        reply = question.reply()
        reply.header.rcode = RCODE.SERVFAIL
        try:
            send(reply.pack(), addr)
        except Exception:
            pass
        _record(client_ip, qname, qtype_str, _allow("upstream failure"), False)
        return

    # DNS-rebinding guard: public name answering with a private address
    if cfg_bool("rebinding_protection", True) and qtype_str == "A" and not is_trusted(qname):
        for rr in resolved.rr:
            if rr.rtype == QTYPE.A and is_private_ip(str(rr.rdata)):
                reply = question.reply()
                reply.header.rcode = RCODE.NXDOMAIN
                send(reply.pack(), addr)
                SECURITY_EVENTS.append({"time": now_hm(), "type": "DNS Rebinding Blocked",
                                       "client": client_ip,
                                       "detail": "%s -> %s" % (qname, rr.rdata)})
                _record(client_ip, qname, qtype_str,
                        _deny("security", "malvertising", "Rebinding", "heuristics"), True)
                return

    reply = question.reply()
    for rr in resolved.rr:
        reply.add_answer(rr)
    for rr in getattr(resolved, "auth", []) or []:
        reply.add_auth(rr)
    reply.header.aa = getattr(resolved.header, "aa", 0)
    payload = reply.pack()
    if len(payload) > 1232:                 # too big for UDP: tell the client to use TCP
        reply.header.tc = 1
        payload = reply.trunc().pack()
    try:
        send(payload, addr)
    except Exception:
        pass
    _record(client_ip, qname, qtype_str, verdict, False)


def rate_limit_check(client_ip):
    now = time.time()
    limit = int(CFG.get("rate_limit_rps", 500))
    bucket = CLIENT_RATES[client_ip]
    keep = [t for t in bucket if now - t < 1.0]
    if len(keep) >= limit:
        CLIENT_RATES[client_ip] = keep
        return False
    keep.append(now)
    CLIENT_RATES[client_ip] = keep
    return True


DNS_POOL = None
_udp_sock = None


def dns_udp_worker():
    global DNS_POOL, _udp_sock
    port = int(CFG.get("dns_port", 53))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except Exception as exc:
        LOG.error("cannot bind UDP/%s (%s) - another resolver owns port 53? "
                  "run `adquit doctor` or set dns_port", port, exc)
        CFG["dns_bind_error"] = str(exc)
        save_config()
        return
    _udp_sock = sock
    DNS_POOL = ThreadPoolExecutor(max_workers=max(4, int(CFG.get("dns_workers", 32))))
    LOG.info("DNS ready on 0.0.0.0:%s (udp+tcp, %s workers)", port,
             DNS_POOL._max_workers)
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            DNS_POOL.submit(_safe_handle, data, addr, sock.sendto)
        except Exception:
            continue


def _safe_handle(data, addr, send):
    global DROPPED
    try:
        handle_dns_request(data, addr, send)
    except Exception as exc:
        DROPPED += 1
        LOG.debug("query error: %s", exc)


def dns_tcp_worker():
    port = int(CFG.get("dns_port", 53))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(256)
    except Exception as exc:
        LOG.warning("TCP/%s unavailable: %s", port, exc)
        return

    def loop():
        while True:
            try:
                conn, addr = srv.accept()
            except Exception:
                return
            DNS_POOL.submit(_tcp_client, conn, addr)

    threading.Thread(target=loop, daemon=True).start()
    LOG.info("DNS TCP listener on :%s", port)


def _tcp_client(conn, addr):
    try:
        conn.settimeout(5)
        head = _recv_exact(conn, 2)
        if not head:
            return
        length = int.from_bytes(head, "big")
        payload = _recv_exact(conn, length)
        if not payload:
            return
        out = []

        def send(data, _addr=None):
            out.append(data)

        handle_dns_request(payload, addr, send)
        for chunk in out:
            conn.sendall(len(chunk).to_bytes(2, "big") + chunk)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ──────────────────────────────────────────────
#  Zero-pixel creative sinkhole: blocked ad assets get *empty* bodies,
#  so ad slots collapse instead of hanging on a spinner.
# ──────────────────────────────────────────────
PIXEL = (b"GIF89a\x01\x00\x01\x00\x80\x01\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x01\x00"
         b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
EMPTY_JS = b"/* NetBlock Fortress: ad request suppressed */\n"
EMPTY_CSS = (b"/* NetBlock Fortress */\n"
             b".ad,.ads,.adsbygoogle,[id^=google_ads],[class*=ad-container],"
             b"[id^=ad-],[class*=sponsored]{display:none!important;}\n")
SPLASH = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ad blocked</title><style>
body{background:#0a0e17;color:#e2e8f0;font:15px -apple-system,Segoe UI,Roboto,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.c{max-width:560px;padding:28px;border:1px solid #1f2937;background:#111827;border-radius:14px}
h1{font-size:19px;margin:0 0 10px;color:#fb542b}code{background:#0a0e17;padding:2px 6px;border-radius:4px}
p{color:#8892b0;font-size:13px;line-height:1.7}small{color:#4b5563;font-size:11px}
</style></head><body><div class="c"><h1>&#128737; Blocked by NetBlock Fortress</h1>
<p>The host <code>%(host)s</code> is an advertising, tracking or malware endpoint and was
sinkholed by your DNS shield. Nothing was downloaded: no creative, no pixel, no beacon.</p>
<p>Rules matched: <code>%(reason)s</code> &middot; vector <code>%(vec)s</code></p>
<small>NetBlock Fortress %(version)s - %(rules)s rules armed. This response is served by the
local fortress so pages render without broken ad frames.</small></div></body></html>"""


def start_sinkhole_server():
    if not cfg_bool("sinkhole_splash", True):
        return
    port = int(CFG.get("sinkhole_port", 80) or 0)
    if port <= 0 or CFG.get("sinkhole_mode") != "fortress":
        LOG.info("creative sinkhole idle (sinkhole_mode=%s)", CFG.get("sinkhole_mode"))
        return
    try:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    except Exception as exc:
        LOG.warning("sinkhole server unavailable: %s", exc)
        return

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Adquitsink/19"

        def _send(self, code, body=b"", ctype="text/plain; charset=utf-8"):
            try:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("X-Adquit", "sinkhole")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except Exception:
                pass

        def _serve(self):
            host = (self.headers.get("Host") or "").split(":")[0].lower().strip()
            path = self.path.lower()
            if not host or classify(host)["action"] != "block":
                if path.startswith("/favicon"):
                    return self._send(204)
                return self._send(404, b"NetBlock Fortress - not a sinkholed host\n")
            v = classify(host)
            if path.endswith((".gif", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico",
                              ".bmp", ".avif")) or "/pixel" in path or "1x1" in path:
                return self._send(200, PIXEL, "image/gif")
            if path.endswith(".js") or "/ad" in path and ".js" in path:
                return self._send(200, EMPTY_JS, "application/javascript")
            if path.endswith(".css"):
                return self._send(200, EMPTY_CSS, "text/css")
            if "image" in (self.headers.get("Accept") or ""):
                return self._send(200, PIXEL, "image/gif")
            ua = (self.headers.get("Accept") or "")
            if "text/html" in ua and CFG.get("sinkhole_splash") == "page":
                return self._send(200, (SPLASH % {
                    "host": host, "reason": v.get("reason", "blocklist"),
                    "vec": v.get("vec", "ad"), "version": VERSION,
                    "rules": "{:,}".format(len(BLOCKED))}).encode(), "text/html; charset=utf-8")
            return self._send(204)

        def do_GET(self):
            self._serve()

        def do_HEAD(self):
            self._serve()

        def do_POST(self):
            self._serve()

        def do_OPTIONS(self):
            self._send(204)

        def log_message(self, *args, **kwargs):
            return

    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    except Exception as exc:
        LOG.warning("creative sinkhole could not bind %s: %s (set sinkhole_port or "
                    "sinkhole_splash=false)", port, exc)
        return
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    LOG.info("creative sinkhole serving on :%s", port)

# ──────────────────────────────────────────────
#  Flask app + auth
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = CFG.get("api_token", "netblock-fortress")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SAMESITE="Lax",
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=86400)


def is_logged_in():
    return session.get("logged_in") is True


def login_req(f):
    from functools import wraps

    @wraps(f)
    def wrap(*args, **kwargs):
        if not is_logged_in():
            return redirect("/login")
        return f(*args, **kwargs)
    return wrap


def api_ok():
    """Session cookie or `?token=`/`X-Adquit-Token` (used by the adquit CLI)."""
    token = request.args.get("token") or request.headers.get("X-Adquit-Token") or ""
    if token and hmac.compare_digest(str(token), str(CFG.get("api_token", ""))):
        return True
    return is_logged_in()



def render_page(tpl, nav, page_title="Dashboard", msg="", msg_type="ok", **kw):
    full = BASE_TPL.replace("{% block content %}{% endblock %}", tpl)
    ctx = dict(a=nav, page_title=page_title, title=page_title, msg=msg, msg_type=msg_type,
               blocked_count=BLOCKED_QUERIES, rules_total=len(BLOCKED) + len(WILDCARDS),
               dns_port=CFG.get("dns_port", 53), web_port=CFG.get("web_port", 8080),
               version=VERSION, codename=CODENAME, mode=CFG.get("block_mode", "strict"),
               mode_name=(MODES.get(CFG.get("block_mode", "strict"), MODES["strict"]))["name"],
               feeds=len(CFG.get("enabled_lists", [])), cat_count=len(CAT),
               total_feeds=len(all_lists()),
               uptime=human_duration(time.time() - START_TIME), **kw)
    return render_template_string(full, **ctx)


def human_duration(seconds):
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return "%dd %dh %dm" % (d, h, m)
    if h:
        return "%dh %dm" % (h, m)
    if m:
        return "%dm %ds" % (m, s)
    return "%ds" % s


def coverage_summary():
    """Micro vs macro scoreboard used by the dashboard and the coverage page."""
    macro = {"rules": 0, "vectors": []}
    micro = {"rules": 0, "vectors": []}
    for vid, info in VECTORS.items():
        on = (info["kind"] == "macro" and True) or True
        switch = VECTOR_SWITCH.get(vid)
        armed = True if not switch else cfg_bool(switch, True)
        count = VECTOR_COUNTS.get(vid, 0)
        entry = {"id": vid, "name": info["name"], "kind": info["kind"], "icon": info["icon"],
                 "color": info["color"], "desc": info["desc"], "count": count,
                 "armed": armed, "switch": switch,
                 "feeds": sum(1 for l in all_lists().values() if l.get("vec") == vid)}
        (macro if info["kind"] == "macro" else micro)["rules"] += count
        (macro if info["kind"] == "macro" else micro)["vectors"].append(entry)
    for group in (macro, micro):
        group["vectors"].sort(key=lambda e: -e["count"])
        top = max([1] + [e["count"] for e in group["vectors"]])
        for e in group["vectors"]:
            e["pct"] = int(e["count"] * 100.0 / top)
    return macro, micro


def stats_payload():
    total = max(1, TOTAL_QUERIES)
    bw = BLOCKED_QUERIES * 125 * 1024
    macro, micro = coverage_summary()
    return {
        "version": VERSION, "codename": CODENAME, "mode": CFG.get("block_mode"),
        "uptime_seconds": int(time.time() - START_TIME),
        "queries": TOTAL_QUERIES, "blocked": BLOCKED_QUERIES, "allowed": ALLOWED_QUERIES,
        "block_rate": round(BLOCKED_QUERIES * 100.0 / total, 2),
        "clients": len(CLIENT_ACTIVITY), "rules": len(BLOCKED), "wildcards": len(WILDCARDS),
        "feeds_enabled": len(CFG.get("enabled_lists", [])), "feeds_total": len(all_lists()),
        "pattern_hits": PATTERN_HITS, "wildcard_hits": WILDCARD_HITS,
        "cname_uncloaks": CNAME_HITS, "ai_queries": AI_QUERIES, "cache_hits": CACHE_HITS,
        "cache_entries": len(DECISION_CACHE), "dropped": DROPPED,
        "bandwidth_saved_bytes": bw, "bandwidth_saved": human_bytes(bw),
        "time_saved": human_duration(BLOCKED_QUERIES * 1.5),
        "macro_rules": macro["rules"], "micro_rules": micro["rules"],
        "vectors": dict(VECTOR_COUNTS), "categories": dict(CAT_COUNTS),
        "top_blocked": [{"domain": d, "hits": n} for d, n in
                        sorted(TOP_GLOBAL.items(), key=lambda kv: -kv[1])[:20]],
        "hourly": {"queries": list(HOURLY), "blocked": list(HOURLY_BLOCKED)},
        "refresh": dict(REFRESH_PROGRESS),
        "security_events": list(SECURITY_EVENTS)[:40],
    }


def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f PB" % n


# feed availability self-check (used by `adquit verify-lists`)
def verify_lists(timeout=12):
    results = []
    for lid, info in sorted(all_lists().items()):
        row = {"lid": lid, "name": info["name"], "url": info["url"], "cat": info["cat"],
               "status": "unchecked"}
        try:
            res = requests.get(info["url"], timeout=timeout, stream=True,
                               headers={"User-Agent": USER_AGENT})
            row["status"] = "ok" if res.status_code < 400 else "http-%s" % res.status_code
            row["bytes"] = res.headers.get("Content-Length", "?")
            ct = res.headers.get("Content-Type", "")
            body_head = b""
            try:
                for chunk in res.iter_content(2048):
                    body_head += chunk
                    if len(body_head) > 4096:
                        break
            except Exception:
                pass
            res.close()
            if res.status_code < 400:
                e, w, _u = parse_source_bytes(body_head)
                row["sample_rules"] = len(e) + len(w)
        except Exception as exc:
            row["status"] = "unreachable"
            row["error"] = str(exc)[:80]
        results.append(row)
    return results
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
<div><div class="bn">NetBlock</div><div class="bs">Fortress v{{ version }} &middot; {{ mode_name }}</div></div></div>
<div class="nav">
<a class="ni {% if a=='dash' %}active{% endif %}" href="/"><i class="fa-solid fa-gauge"></i> Dashboard</a>
<a class="ni {% if a=='sec' %}active{% endif %}" href="/security"><i class="fa-solid fa-lock"></i> Security Center</a>
<a class="ni {% if a=='bl' %}active{% endif %}" href="/blocklists"><i class="fa-solid fa-list-check"></i> Blocklists ({{ total_feeds }})</a>
<a class="ni {% if a=='cov' %}active{% endif %}" href="/coverage"><i class="fa-solid fa-layer-group"></i> Ad Coverage Matrix</a>
<a class="ni {% if a=='lab' %}active{% endif %}" href="/lab"><i class="fa-solid fa-flask"></i> Domain Lab</a>
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
<div class="ts">
<div class="sp" title="macro + micro ad rules armed"><i class="fa-solid fa-layer-group"></i> {{ "{:,}".format(rules_total) }} rules</div>
<div class="sp" style="background:rgba(139,92,246,.12);border-color:rgba(139,92,246,.35);color:#8b5cf6"><i class="fa-solid fa-sliders"></i> {{ mode_name }}</div>
<div class="sp"><i class="fa-solid fa-shield"></i> {{ "{:,}".format(blocked_count) }} Blocked</div>
<a class="btn b2 bs2" href="/api/stats" target="_blank"><i class="fa-solid fa-code"></i></a></div></div>
<div class="content">
{% if msg %}
<div class="al {% if msg_type=='err' %}alerr{% else %}alok{% endif %}">
<i class="fa-solid {% if msg_type=='err' %}fa-circle-exclamation{% else %}fa-circle-check{% endif %}"></i> {{ msg }}
</div>
{% endif %}{% block content %}{% endblock %}</div></div></body></html>"""

# ── Dashboard Page ──
PAGE_DASH = """
<div class="sg">
<div class="sc"><i class="fa-solid fa-shield-halved bg"></i>
<div class="sl">Total Queries</div><div class="sv">{{ "{:,}".format(total_queries) }}</div>
<div class="ss">Across {{ client_count }} clients</div></div>
<div class="sc"><i class="fa-solid fa-ban bg" style="color:var(--pri)"></i>
<div class="sl">Ads & Threats Blocked</div><div class="sv" style="color:var(--pri)">{{ "{:,}".format(blocked_queries) }}</div>
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
<p style="font-size:12px;color:var(--mut)">{{ total_feeds }} curated feeds across {{ cats|length }}
categories - {{ macro_feeds }} macro-ad feeds, {{ micro_feeds }} micro-ad feeds,
{{ enabled_count }} armed</p></div>
<div style="display:flex;gap:8px"><form method="POST" action="/blocklists/update_all">
<button class="btn bp" type="submit"><i class="fa-solid fa-arrows-rotate"></i> Update All</button></form>
<form method="POST" action="/blocklists/add_feed" style="display:flex;gap:6px">
<input class="inp" style="width:230px" name="url" placeholder="https://your-feed.example/list.txt">
<input type="hidden" name="name" value="">
<button class="btn b2" type="submit"><i class="fa-solid fa-plus"></i> Add feed</button></form></div></div>
<div class="card"><table class="tbl"><thead><tr>
<th>Feed</th><th>Category</th><th>Status</th><th>Rules</th><th>Synced</th><th>Enable</th><th></th>
</tr></thead><tbody>
{% for lid, st in lists.items() %}<tr>
<td><div style="font-weight:600">{{ st.name }}</div>
<div style="font-size:10px;color:var(--mut)">{{ lid }} &middot;
<span style="color:{{ '#8b5cf6' if st.vec in ('pixel','sdk','fingerprint','telemetry','retarget','email','shortlink','adx','malvertising') else '#fb542b' }}">
{{ 'micro' if st.vec in ('pixel','sdk','fingerprint','telemetry','retarget','email','shortlink','adx','malvertising') else 'macro' }} &middot; {{ st.vec }}</span>
{% if st.url %}<div style="font-size:9px;color:#4b5563;word-break:break-all" title="{{ st.url }}">{{ st.url[:58] }}</div>{% endif %}</td>
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
#  v19 pages: Coverage matrix + Domain lab
# ──────────────────────────────────────────────
PAGE_COVERAGE = """
<div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:20px">
<div><h2 style="font-size:18px;font-weight:700">Ad Coverage Matrix</h2>
<p style="font-size:12px;color:var(--mut)">{{ macro.rules + micro.rules }} armed rules split across
macro ad units (what you see) and micro ad traffic (pixels, SDKs, telemetry you never see)</p></div>
<div style="display:flex;gap:8px">
<a class="btn b2" href="/blocklists"><i class="fa-solid fa-list-check"></i> Feeds</a>
<form method="POST" action="/coverage/rebuild"><button class="btn bp" type="submit">
<i class="fa-solid fa-bolt"></i> Recompile Rules</button></form></div></div>

<div class="sg">
<div class="sc"><i class="fa-solid fa-display bg" style="color:var(--pri)"></i>
<div class="sl">Macro Ad Rules</div><div class="sv" style="color:var(--pri)">{{ "{:,}".format(macro.rules) }}</div>
<div class="ss">{{ macro.vectors|length }} vectors &middot; banners, video, popups, CTV, push</div></div>
<div class="sc"><i class="fa-solid fa-microchip bg" style="color:var(--sec)"></i>
<div class="sl">Micro Ad Rules</div><div class="sv" style="color:var(--sec)">{{ "{:,}".format(micro.rules) }}</div>
<div class="ss">{{ micro.vectors|length }} vectors &middot; pixels, SDKs, fingerprint, telemetry</div></div>
<div class="sc"><i class="fa-solid fa-shield-halved bg" style="color:var(--grn)"></i>
<div class="sl">Heuristics</div><div class="sv" style="color:var(--grn)">{{ pattern_status }}</div>
<div class="ss">pattern engine {{ "armed" if pattern_on else "off" }},
{{ wildcard_on and "wildcards on" or "wildcards off" }}</div></div>
<div class="sc"><i class="fa-solid fa-bullseye bg"></i>
<div class="sl">Heuristic Hits</div><div class="sv">{{ "{:,}".format(pattern_hits) }}</div>
<div class="ss">{{ "{:,}".format(wild_hits) }} wildcard matches</div></div>
</div>

<div class="card"><div class="ch"><div class="ct">
<i class="fa-solid fa-desktop" style="color:var(--pri)"></i> MACRO ADS - visible ad units</div>
<span style="font-size:11px;color:var(--mut)">{{ "{:,}".format(macro.rules) }} rules</span></div>
<p style="font-size:12px;color:var(--mut);margin-bottom:16px">Everything rendered on the page:
display banners, in-video spots, pop-unders, interstitials, native/sponsored slots, smart-TV
and push-notification ads.</p>
<table class="tbl"><thead><tr><th>Vector</th><th>What it stops</th><th>Feeds</th>
<th>Rules</th><th>Share</th><th>Switch</th></tr></thead><tbody>
{% for v in macro.vectors %}<tr>
<td style="font-weight:600"><i class="fa-solid {{ v.icon }}" style="color:{{ v.color }};width:18px"></i>
{{ v.name }}</td>
<td style="color:var(--mut);font-size:11px">{{ v.desc }}</td>
<td style="color:var(--mut)">{{ v.feeds }}</td>
<td style="font-weight:700">{{ "{:,}".format(v.count) }}</td>
<td style="min-width:110px"><div style="background:#1f2937;height:6px;border-radius:3px;overflow:hidden">
<div style="background:{{ v.color }};height:100%;width:{{ v.pct }}%"></div></div></td>
<td><form method="POST" action="/coverage/toggle"><input type="hidden" name="key" value="{{ v.switch }}">
<button class="btn bs2 {% if v.armed %}b2{% else %}bp{% endif %}" type="submit">
{% if v.armed %}ON{% else %}OFF{% endif %}</button></form></td></tr>{% endfor %}</tbody></table></div>

<div class="card"><div class="ch"><div class="ct">
<i class="fa-solid fa-microchip" style="color:var(--sec)"></i> MICRO ADS - invisible traffic</div>
<span style="font-size:11px;color:var(--mut)">{{ "{:,}".format(micro.rules) }} rules</span></div>
<p style="font-size:12px;color:var(--mut);margin-bottom:16px">Tracking pixels, impression beacons,
in-app ad SDK handshakes, RTB bidding calls, device fingerprinting, session replay, telemetry pings
and email open pixels. These never render, but they are what follows you everywhere.</p>
<table class="tbl"><thead><tr><th>Vector</th><th>What it stops</th><th>Feeds</th>
<th>Rules</th><th>Coverage</th><th>Switch</th></tr></thead><tbody>
{% for v in micro.vectors %}<tr>
<td style="font-weight:600"><i class="fa-solid {{ v.icon }}" style="color:{{ v.color }};width:18px"></i>
{{ v.name }}</td>
<td style="color:var(--mut);font-size:11px">{{ v.desc }}</td>
<td style="color:var(--mut)">{{ v.feeds }}</td>
<td style="font-weight:700">{{ "{:,}".format(v.count) }}</td>
<td style="min-width:120px"><div style="background:#1f2937;height:6px;border-radius:3px;overflow:hidden">
<div style="background:{{ v.color }};height:100%;width:{{ v.pct }}%"></div></div></td>
<td><form method="POST" action="/coverage/toggle">
<input type="hidden" name="key" value="{{ v.switch }}">
<button class="btn bs2 {% if v.armed %}b2{% else %}bp{% endif %}" type="submit">
{% if v.armed %}ON{% else %}OFF{% endif %}</button></form></td></tr>
{% endfor %}</tbody></table></div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
<div class="card" style="margin-bottom:0"><div class="ch"><div class="ct">
<i class="fa-solid fa-flask"></i> Heuristic Engine</div></div>
<div style="font-size:12px;color:var(--mut);line-height:2">
<div>Ad-keyword patterns: <b style="color:var(--txt)">{{ "armed (%s)" % pattern_action }}</b></div>
<div>Ad-subdomain labels: <b style="color:var(--txt)">{{ "strict + nuclear only" if pattern_on else "off" }}</b></div>
<div>Trusted zones (anti-breakage): <b style="color:var(--txt)">{{ trusted_count }} domains</b></div>
<div>DGA / entropy: <b style="color:var(--txt)">{{ "on" if dga_on else "off" }}</b></div>
<div>Homograph &amp; typosquat: <b style="color:var(--txt)">{{ "on" if typo_on else "shadow" }}</b></div>
<div>Unbreak exceptions: <b style="color:var(--txt)">{{ "{:,}".format(unbreak_count) }} hosts</b></div>
</div>
<form method="POST" action="/coverage/heuristics" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
<button class="btn b2 bs2" name="action" value="shadow" type="submit">Shadow mode (log only)</button>
<button class="btn b2 bs2" name="action" value="enforce" type="submit">Enforce</button>
<button class="btn b2 bs2" name="action" value="disable" type="submit">Disable patterns</button>
</form></div>
<div class="card" style="margin-bottom:0"><div class="ch"><div class="ct">
<i class="fa-solid fa-tv"></i> Per-device coverage</div></div>
<table class="tbl"><tbody>
{% for row in device_rows %}<tr><td style="font-weight:600;width:38%">
<i class="fa-solid {{ row.icon }}" style="color:var(--pri);width:18px"></i>{{ row.name }}</td>
<td style="color:var(--mut);font-size:11px">{{ row.detail }}</td>
<td style="text-align:right;font-weight:700;color:{{ 'var(--grn)' if row.on else 'var(--red)' }}">
{{ "BLOCKED" if row.on else "open" }}</td></tr>{% endfor %}</tbody></table></div>
</div>
"""

PAGE_LAB = """
<div style="margin-bottom:20px"><h2 style="font-size:18px;font-weight:700">Domain Lab</h2>
<p style="font-size:12px;color:var(--mut)">Audit any hostname against the live rulebook - exact feed
match, wildcard, pattern engine, CNAME uncloaking and upstream answer.</p></div>
<div class="card"><form method="GET" action="/lab" style="display:flex;gap:10px">
<input class="inp" style="flex:1" name="domain" placeholder="ads.example.com"
value="{{ probe or '' }}" autocomplete="off">
<button class="btn bp" type="submit"><i class="fa-solid fa-magnifying-glass"></i> Audit</button></form></div>
{% if probe %}
<div class="sg">
<div class="sc"><i class="fa-solid {{ 'fa-ban' if verdict.action == 'block' else 'fa-circle-check' }} bg"
style="font-size:38px;opacity:.15;color:{{ verdict.color }}"></i>
<div class="sl">Verdict</div>
<div class="sv" style="color:{{ verdict.color }}">{{ verdict.action|upper }}</div>
<div class="ss">{{ verdict.reason }}</div></div>
<div class="sc"><div class="sl">Category</div><div class="sv" style="font-size:20px">
{{ cats.get(verdict.cat).name if cats.get(verdict.cat) else verdict.cat|title }}</div>
<div class="ss">vector: {{ verdict.vec }}</div></div>
<div class="sc"><div class="sl">Matched via</div><div class="sv" style="font-size:20px">
{{ verdict.source or '-' }}</div><div class="ss">registrable: {{ registrable_domain }}</div></div>
<div class="sc"><div class="sl">Trusted zone</div><div class="sv" style="font-size:20px">
{{ 'yes' if trusted else 'no' }}</div><div class="ss">heuristic exemptions</div></div>
</div>
<div class="card"><div class="ch"><div class="ct"><i class="fa-solid fa-layer-group"></i> Layer trace</div></div>
<table class="tbl"><thead><tr><th>#</th><th>Layer</th><th>Result</th></tr></thead><tbody>
{% for step in trace %}<tr><td style="color:var(--mut)">{{ loop.index }}</td>
<td style="font-weight:600">{{ step.0 }}</td>
<td><span class="bdg" style="background:rgba(255,255,255,.05);color:{{ step.2 }}">{{ step.1 }}</span></td>
</tr>{% endfor %}</tbody></table>
<div style="display:flex;gap:10px;margin-top:16px">
<form method="POST" action="/lab/block"><input type="hidden" name="domain" value="{{ probe }}">
<button class="btn bp" type="submit"><i class="fa-solid fa-ban"></i> Block {{ probe }}</button></form>
<form method="POST" action="/lab/allow"><input type="hidden" name="domain" value="{{ probe }}">
<button class="btn b2" type="submit"><i class="fa-solid fa-check"></i> Always allow</button></form>
<a class="btn b2" href="/logs"><i class="fa-solid fa-clock-rotate-left"></i> Recent queries</a></div></div>
{% if upstream %}
<div class="card"><div class="ch"><div class="ct"><i class="fa-solid fa-network-wired"></i>
Upstream answer ({{ upstream_mode }})</div></div>
<table class="tbl"><thead><tr><th>Type</th><th>TTL</th><th>Value</th><th>Verdict for value</th></tr></thead>
<tbody>{% for r in upstream %}<tr><td>{{ r.type }}</td><td>{{ r.ttl }}</td>
<td><code>{{ r.value }}</code></td><td>{{ r.note }}</td></tr>{% endfor %}</tbody></table></div>
{% endif %}
{% endif %}
"""

# ──────────────────────────────────────────────
#  Extra v19 cards appended to the v18 Settings / Modes pages
# ──────────────────────────────────────────────
PAGE_SETTINGS += """
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px">
<div class="card"><div class="ch"><div class="ct">
<i class="fa-solid fa-crosshairs" style="color:var(--pri)"></i> Ad Coverage &amp; Responses</div></div>
<form method="POST" action="/settings"><div class="fg">
<label class="lbl">Sinkhole response</label>
<select class="inp" name="sinkhole_mode" style="width:100%">
<option value="zeroip" {% if cfg.sinkhole_mode=='zeroip' %}selected{% endif %}>0.0.0.0 / :: (fastest)</option>
<option value="nxdomain" {% if cfg.sinkhole_mode=='nxdomain' %}selected{% endif %}>NXDOMAIN (most aggressive)</option>
<option value="fortress" {% if cfg.sinkhole_mode=='fortress' %}selected{% endif %}>Fortress IP + zero-pixel collapse</option>
</select></div>
<div class="fg"><label class="lbl">Fortress IP (fortress mode - blank = auto detect)</label>
<input class="inp" name="sinkhole_ip" value="{{ cfg.sinkhole_ip }}" style="width:100%" placeholder="192.168.1.20"></div>
<div class="fg"><label class="lbl">Creative sinkhole port</label>
<input class="inp" type="number" name="sinkhole_port" value="{{ cfg.sinkhole_port }}" style="width:100%"></div>
<div class="fg"><label class="lbl">Rule cache TTL / resolver threads</label>
<div style="display:flex;gap:8px"><input class="inp" type="number" name="cache_ttl" value="{{ cfg.cache_ttl }}" style="width:50%">
<input class="inp" type="number" name="dns_workers" value="{{ cfg.dns_workers }}" style="width:50%"></div></div>
<div style="display:flex;flex-direction:column;gap:10px;font-size:12px;margin-bottom:14px">
{% for key, label in coverage_toggles %}
<label style="display:flex;align-items:center;gap:9px;color:var(--mut)">
<input type="checkbox" name="{{ key }}" value="1" {% if cfg.get(key) %}checked{% endif %}>
<span>{{ label|safe }}</span></label>{% endfor %}</div>
<button class="btn bp" type="submit" name="save_coverage" value="1">
<i class="fa-solid fa-floppy-disk"></i> Save coverage profile</button></form></div>
<div class="card"><div class="ch"><div class="ct">
<i class="fa-solid fa-plug" style="color:var(--sec)"></i> Resolver &amp; Privacy</div></div>
<form method="POST" action="/settings"><div class="fg">
<label class="lbl">Upstream mode</label><select class="inp" name="upstream_mode" style="width:100%">
<option value="auto" {% if cfg.upstream_mode=='auto' %}selected{% endif %}>Auto (DoH first, UDP fallback)</option>
<option value="udp" {% if cfg.upstream_mode=='udp' %}selected{% endif %}>UDP only</option>
<option value="doh" {% if cfg.upstream_mode=='doh' %}selected{% endif %}>DNS-over-HTTPS only</option>
</select></div>
<div class="fg"><label class="lbl">UDP upstream</label>
<input class="inp" name="dns_upstream" value="{{ cfg.dns_upstream }}" style="width:100%"></div>
<div class="fg"><label class="lbl">DoH endpoint</label>
<input class="inp" name="doh_upstream" value="{{ cfg.doh_upstream }}" style="width:100%"></div>
<div class="fg"><label class="lbl">Ports (DNS / dashboard) &amp; query log size</label>
<div style="display:flex;gap:8px"><input class="inp" type="number" name="dns_port" value="{{ cfg.dns_port }}" style="width:34%">
<input class="inp" type="number" name="web_port" value="{{ cfg.web_port }}" style="width:33%">
<input class="inp" type="number" name="log_max" value="{{ cfg.log_max }}" style="width:33%"></div></div>
<label style="display:flex;align-items:center;gap:9px;font-size:12px;color:var(--mut);margin-bottom:14px">
<input type="checkbox" name="log_enabled" value="1" {% if cfg.get('log_enabled') %}checked{% endif %}>
Keep an on-disk query log (data/queries.jsonl)</label>
<button class="btn bp" type="submit" name="save_network" value="1">
<i class="fa-solid fa-floppy-disk"></i> Save resolver settings</button></form>
</div></div>
"""

PAGE_MODES += """
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-top:20px">
<div class="card" style="border-top:3px solid var(--red)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Nuclear</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Every feed on the box.
Max heuristics, low-rep TLDs gone.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>All Family rules + regional filters</li><li>Hagezi Ultimate &amp; Pro++</li>
<li>Typosquat + DGA + homograph blocking</li><li>SafeSearch enforced</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="nuclear">
<button class="btn {% if cur_mode=='nuclear' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='nuclear' %}Active{% else %}Go Nuclear{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid #64748b">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Paused</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">Resolver keeps answering,
blocking stops. Use for downloads, updates and IoT setup.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>No lists armed</li><li>Cache + upstream untouched</li><li>Instant re-arm</li></ul>
<form method="POST" action="/modes/set"><input type="hidden" name="mode" value="off">
<button class="btn {% if cur_mode=='off' %}b2{% else %}bp{% endif %}" style="width:100%" type="submit">
{% if cur_mode=='off' %}Paused{% else %}Pause protection{% endif %}</button></form></div>
<div class="card" style="border-top:3px solid var(--sec)">
<div style="font-size:18px;font-weight:700;margin-bottom:6px">Heuristics &amp; patterns</div>
<div style="font-size:12px;color:var(--mut);margin-bottom:16px">The engine that catches brand-new
ad hosts that no list has seen yet.</div>
<ul style="font-size:12px;color:var(--mut);margin-bottom:20px;padding-left:18px;line-height:1.8">
<li>{{ "{:,}".format(patterns|length) }} ad-infrastructure keywords</li>
<li>{{ "{:,}".format(labels|length) }} advertising sub-domain labels</li>
<li>{{ "{:,}".format(seed|length) }} hardcoded seed rules (instant)</li></ul>
<a class="btn b2" style="width:100%;justify-content:center" href="/coverage">
Open coverage matrix</a></div></div>
"""

# ──────────────────────────────────────────────
#  v19 dashboard additions
# ──────────────────────────────────────────────
PAGE_DASH += """
<div class="sg">
<div class="sc"><i class="fa-solid fa-microchip bg" style="color:var(--sec)"></i>
<div class="sl">Micro-ad Traffic Killed</div>
<div class="sv" style="color:var(--sec)">{{ "{:,}".format(micro_rules) }}</div>
<div class="ss">pixels, SDKs, fingerprint, telemetry</div></div>
<div class="sc"><i class="fa-solid fa-display bg" style="color:var(--pri)"></i>
<div class="sl">Macro-ad Rules</div><div class="sv" style="color:var(--pri)">{{ "{:,}".format(macro_rules) }}</div>
<div class="ss">banners, video, popups, CTV, push</div></div>
<div class="sc"><i class="fa-solid fa-bolt bg" style="color:var(--grn)"></i>
<div class="sl">Cache Hit Rate</div><div class="sv" style="color:var(--grn)">{{ cache_pct }}%</div>
<div class="ss">{{ "{:,}".format(cache_entries) }} cached decisions</div></div>
<div class="sc"><i class="fa-solid fa-list-ul bg"></i>
<div class="sl">Feeds / Categories</div><div class="sv">{{ feeds }} / {{ cats }}</div>
<div class="ss">{{ mode_name }} profile armed</div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
<div class="card" style="margin-bottom:0"><div class="ch"><div class="ct">
<i class="fa-solid fa-chart-simple" style="color:var(--pri)"></i> Last 24 hours</div></div>
<div style="display:flex;align-items:flex-end;gap:4px;height:110px">
{% for h in hours %}<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%;gap:2px"
title="{{ h.label }}: {{ h.queries }} queries / {{ h.blocked }} blocked">
<div style="background:#fb542b;border-radius:2px 2px 0 0;height:{{ h.pct }}%"></div>
<div style="background:#1f2937;border-radius:0 0 2px 2px;height:{{ h.rest }}%"></div></div>{% endfor %}</div>
<div style="display:flex;justify-content:space-between;font-size:10px;color:var(--mut);margin-top:6px">
<span>24h ago</span><span>now</span></div></div>
<div class="card" style="margin-bottom:0"><div class="ch"><div class="ct">
<i class="fa-solid fa-trophy" style="color:var(--yel)"></i> Most Blocked Hosts</div>
<a href="/coverage" class="btn b2 bs2">Coverage matrix</a></div>
<table class="tbl"><tbody>{% for t in top_blocked %}<tr>
<td style="font-weight:600"><code>{{ t.domain }}</code></td>
<td style="text-align:right;color:var(--pri);font-weight:700">{{ "{:,}".format(t.hits) }}</td></tr>
{% else %}<tr><td style="color:var(--mut);text-align:center;padding:18px">
Nothing blocked yet - point a device at this resolver.</td></tr>{% endfor %}</tbody></table></div>
</div>
"""


# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def page_login():
    err = ""
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        configured = (CFG.get("admin_username") or "admin").strip()
        pwhash = hashlib.sha256(p.encode()).hexdigest()
        user_ok = hmac.compare_digest(u.lower(), configured.lower())
        pass_ok = hmac.compare_digest(pwhash, CFG.get("password_hash", ""))
        if user_ok and pass_ok:
            session.clear()
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
    bw = BLOCKED_QUERIES * 125 * 1024
    ts = int(BLOCKED_QUERIES * 1.5)
    br = round(BLOCKED_QUERIES * 100.0 / TOTAL_QUERIES, 1) if TOTAL_QUERIES else 0.0
    total_rules = max(1, len(BLOCKED))
    cat_summary = {}
    for cid, cinfo in CAT.items():
        cnt = CAT_COUNTS.get(cid, 0)
        cat_summary[cid] = {"name": cinfo["name"], "color": cinfo["color"], "icon": cinfo["icon"],
                            "count": cnt, "pct": min(100, int(cnt * 100.0 / total_rules))}
    macro, micro = coverage_summary()
    now_hour = datetime.now().hour
    hours = []
    for i in range(24):
        idx = (now_hour - 23 + i) % 24
        q = HOURLY[idx]
        b = HOURLY_BLOCKED[idx]
        peak = max(1, max(HOURLY) if HOURLY else 1)
        hours.append({"label": "%02d:00" % idx, "queries": q, "blocked": b,
                      "pct": int(b * 100.0 / peak) if peak else 0,
                      "rest": int((q - b) * 100.0 / peak) if peak else 0})
    hits_total = max(1, TOTAL_QUERIES)
    return render_page(PAGE_DASH, "dash", "Network Overview",
        total_queries=TOTAL_QUERIES, blocked_queries=BLOCKED_QUERIES, block_rate=br,
        bandwidth_saved=human_bytes(bw), time_saved=human_duration(ts),
        client_count=len(CLIENT_ACTIVITY), rule_count=total_rules,
        uptime_str=human_duration(up), cat_summary=cat_summary,
        recent_logs=list(QUERY_LOGS)[:10],
        micro_rules=micro["rules"], macro_rules=macro["rules"],
        cache_pct=round(CACHE_HITS * 100.0 / hits_total, 1),
        cache_entries=len(DECISION_CACHE), hours=hours,
        top_blocked=[{"domain": d, "hits": n} for d, n in
                     sorted(TOP_GLOBAL.items(), key=lambda kv: -kv[1])[:8]])


@app.route("/security")
@login_req
def page_security():
    now = time.time()
    susp = sum(1 for d in CLIENT_ACTIVITY.values() if d["threats"] > 0)
    cvs = {}
    for ip, d in CLIENT_ACTIVITY.items():
        delta = int(now - d["last_seen"])
        ls = ("%ds ago" % delta if delta < 60 else "%dm ago" % (delta // 60) if delta < 3600
              else "%dh ago" % (delta // 3600))
        cvs[ip] = {"total": d["total"], "blocked": d["blocked"], "threats": d["threats"],
                   "ads": d.get("ads", 0), "last_seen_str": ls,
                   "top": sorted(d["names"].items(), key=lambda kv: -kv[1])[:5]}
    return render_page(PAGE_SEC, "sec", "Security Center", events=list(SECURITY_EVENTS),
                       clients=cvs, suspicious=susp,
                       wild_hits=WILDCARD_HITS, cname_hits=CNAME_HITS, dropped=DROPPED)


@app.route("/blocklists")
@login_req
def page_blocklists():
    enabled = CFG.get("enabled_lists", [])
    return render_page(PAGE_BL, "bl", "Blocklists (%d feeds)" % len(all_lists()),
                       lists=LIST_STATUS, cats=CAT, enabled_count=len(enabled),
                       micro_feeds=sum(1 for l in all_lists().values()
                                       if VECTORS.get(l.get("vec"), {}).get("kind") == "micro"),
                       macro_feeds=sum(1 for l in all_lists().values()
                                       if VECTORS.get(l.get("vec"), {}).get("kind") == "macro"))


@app.route("/blocklists/toggle", methods=["POST"])
@login_req
def bl_toggle():
    lid = request.form.get("lid")
    registry = all_lists()
    if lid in registry:
        enabled = list(CFG.get("enabled_lists", []))
        if "enabled" in request.form:
            if lid not in enabled:
                enabled.append(lid)
            threading.Thread(target=_fetch_then_build, args=(lid,), daemon=True).start()
        elif lid in enabled:
            enabled.remove(lid)
        CFG["enabled_lists"] = enabled
        CFG["block_mode"] = "custom"
        if lid in LIST_STATUS:
            LIST_STATUS[lid]["enabled"] = lid in enabled
        save_config()
        save_list_status()
        rebuild_master_blocklist()
        flush_caches()
    return redirect("/blocklists")


def _fetch_then_build(lid):
    try:
        fetch_list(lid)
    except Exception:
        pass
    rebuild_master_blocklist()
    flush_caches()


@app.route("/blocklists/download_single", methods=["POST"])
@login_req
def bl_dl():
    lid = request.form.get("lid")
    if lid in all_lists():
        threading.Thread(target=_fetch_then_build, args=(lid,), daemon=True).start()
    return redirect("/blocklists")


@app.route("/blocklists/update_all", methods=["POST"])
@login_req
def bl_update_all():
    threading.Thread(target=refresh_all, daemon=True).start()
    return redirect("/blocklists")


@app.route("/blocklists/add_feed", methods=["POST"])
@login_req
def bl_add_feed():
    url = (request.form.get("url") or "").strip()
    name = (request.form.get("name") or "").strip() or url.split("/")[2:][-1][:28]
    cat = request.form.get("cat") or "ads"
    if not url.startswith(("http://", "https://")):
        return render_page(PAGE_BL, "bl", "Blocklists", lists=LIST_STATUS, cats=CAT,
                           msg="Feed URL must start with http(s)://", msg_type="err",
                           enabled_count=len(CFG.get("enabled_lists", [])),
                           total_feeds=len(all_lists()), micro_feeds=0, macro_feeds=0)
    lid = "custom_" + hashlib.sha256(url.encode()).hexdigest()[:8]
    feeds = dict(CFG.get("custom_lists") or {})
    feeds[lid] = {"name": name[:60], "url": url, "cat": cat, "vec": "banner"}
    CFG["custom_lists"] = feeds
    CFG["enabled_lists"] = list(CFG.get("enabled_lists", [])) + [lid]
    save_config()
    init_list_status()
    save_list_status()
    threading.Thread(target=_fetch_then_build, args=(lid,), daemon=True).start()
    return redirect("/blocklists")


@app.route("/api/list_status")
@login_req
def api_status():
    return jsonify(LIST_STATUS)


@app.route("/modes")
@login_req
def page_modes():
    return render_page(PAGE_MODES, "modes", "Protection Profiles",
                       cur_mode=CFG.get("block_mode", "strict"),
                       modes=MODES, patterns=AD_KEYWORDS, labels=sorted(AD_LABELS),
                       seed=CORE_SEED,
                       vectors=VECTORS, macro_vectors=MACRO_VECTORS, micro_vectors=MICRO_VECTORS)


@app.route("/modes/set", methods=["POST"])
@login_req
def mode_set():
    mode = request.form.get("mode", "strict")
    apply_mode(mode)
    missing = [l for l in CFG.get("enabled_lists", []) if not (LIST_DIR / ("%s.txt" % l)).exists()]
    if missing:
        threading.Thread(target=refresh_all, daemon=True).start()
    return redirect("/modes")


@app.route("/coverage")
@login_req
def page_coverage():
    macro, micro = coverage_summary()
    device_rows = [
        {"name": "Desktop browser", "icon": "fa-desktop", "on": cfg_bool("macro_ads"),
         "detail": "Display, native, popup + retargeting endpoints"},
        {"name": "YouTube / streaming", "icon": "fa-circle-play",
         "on": cfg_bool("invideo_ads") or cfg_bool("youtube_aggressive"),
         "detail": "Pre/mid-roll ad servers, IMA SDK, player telemetry"},
        {"name": "Phones & tablets", "icon": "fa-mobile-screen", "on": cfg_bool("micro_ads"),
         "detail": "AdMob / AppLovin / Unity / ironSource SDK traffic"},
        {"name": "Smart TV & consoles", "icon": "fa-tv", "on": cfg_bool("ctv_ads"),
         "detail": "Samsung, LG, Roku, Fire TV, Xbox ad + audit beacons"},
        {"name": "Email newsletters", "icon": "fa-envelope", "on": cfg_bool("email_tracking"),
         "detail": "Open pixels, click forwarders, read receipts"},
        {"name": "Fingerprint & bot nets", "icon": "fa-fingerprint", "on": cfg_bool("micro_ads"),
         "detail": "Canvas/device fingerprint services, IP echo APIs"},
        {"name": "Malware & phishing", "icon": "fa-skull-crossbones", "on": True,
         "detail": "Threat feeds are always armed in every profile"},
    ]
    return render_page(PAGE_COVERAGE, "cov", "Ad Coverage Matrix", macro=macro, micro=micro,
                       pattern_on=cfg_bool("pattern_engine"), pattern_action=CFG.get("pattern_action"),
                       wildcard_on=cfg_bool("wildcard_engine"), dga_on=cfg_bool("dga_protection"),
                       typo_on=cfg_bool("typosquat_protection"),
                       pattern_hits=PATTERN_HITS, wild_hits=WILDCARD_HITS,
                       trusted_count=len(TRUSTED_ZONES), unbreak_count=len(UNBREAK),
                       device_rows=device_rows, vectors=VECTORS, cats=CAT,
                       sw_names={k: k.replace("_", " ").title() for k in VECTOR_SWITCH.values()})


@app.route("/coverage/toggle", methods=["POST"])
@login_req
def coverage_toggle():
    key = request.form.get("key")
    if key in DEFAULT_CONFIG:
        CFG[key] = not bool(CFG.get(key, True))
        save_config()
        rebuild_master_blocklist()
        flush_caches()
        LOG.info("coverage switch %s -> %s", key, CFG[key])
    return redirect("/coverage")


@app.route("/coverage/heuristics", methods=["POST"])
@login_req
def coverage_heuristics():
    action = request.form.get("action")
    if action == "shadow":
        CFG["pattern_engine"], CFG["pattern_action"] = True, "shadow"
    elif action == "enforce":
        CFG["pattern_engine"], CFG["pattern_action"] = True, "enforce"
    elif action == "disable":
        CFG["pattern_engine"], CFG["pattern_action"] = False, "enforce"
    save_config()
    flush_caches()
    return redirect("/coverage")


@app.route("/coverage/rebuild", methods=["POST"])
@login_req
def coverage_rebuild():
    rebuild_master_blocklist()
    flush_caches()
    return redirect("/coverage")


@app.route("/lab")
@login_req
def page_lab():
    probe = (request.args.get("domain") or "").strip().lower().replace("https://", "").replace("http://", "")
    probe = re.sub(r"[/:].*$", "", probe).lstrip(".")
    if not probe:
        return render_page(PAGE_LAB, "lab", "Domain Lab", probe="", trace=[], verdict={},
                           cats=CAT, upstream=[], upstream_mode="", registrable_domain="",
                           trusted=False)
    verdict = classify(probe)
    trace = [
        ("Whitelist / self-protection", "hit" if probe in CUSTOM_WHITELIST_SET else "miss", "#10b981"),
        ("Exact blocklist rule", "hit (%s)" % BLOCKED[probe][2] if probe in BLOCKED else "miss",
         "#fb542b" if probe in BLOCKED else "#8892b0"),
        ("Wildcard zone", "hit" if probe in WILDCARDS or any(p in WILDCARDS for p in
         [".".join(probe.split(".")[i:]) for i in range(1, probe.count(".") + 1)]) else "miss",
         "#8b5cf6"),
        ("Unbreak exception", "hit" if probe in UNBREAK else "miss", "#10b981"),
        ("Ad-keyword pattern", PATTERN_RE.search(registrable(probe)).group(0)
         if PATTERN_RE.search(registrable(probe)) else "no match", "#f59e0b"),
        ("Trusted zone exemption", "exempt" if is_trusted(probe) else "not exempt", "#06b6d4"),
        ("DGA / entropy", "suspect" if is_dga(probe) else "normal", "#ef4444"),
        ("Final verdict", "%s - %s" % (verdict["action"].upper(), verdict["reason"]),
         verdict["color"]),
    ]
    upstream, up_mode, rows = [], CFG.get("upstream_mode", "auto"), []
    try:
        resp = resolve_upstream(probe, QTYPE.A)
        if resp:
            for rr in resp.rr:
                val = str(rr.rdata).rstrip(".")
                note = ""
                if rr.rtype == QTYPE.CNAME:
                    inner = classify(val)
                    note = "cloaked -> %s" % inner["action"]
                elif rr.rtype == QTYPE.A and is_private_ip(val):
                    note = "private IP (rebinding risk)"
                rows.append({"type": str(QTYPE.get(rr.rtype, "R")), "ttl": rr.ttl,
                             "value": val, "note": note or "-"})
            upstream = rows
    except Exception:
        pass
    if not verdict.get("source") and cfg_bool("ai_triage", False) and CFG.get("openrouter_api_key"):
        ai = ask_openrouter_ai(probe)
        if ai:
            trace.append(("AI triage", "%s (%s)" % (ai.get("verdict"), ai.get("cat")), "#a855f7"))
    return render_page(PAGE_LAB, "lab", "Domain Lab", probe=probe, verdict=verdict, trace=trace,
                       cats=CAT, upstream=upstream, upstream_rows=rows,
                       upstream_mode=up_mode + " (%s)" % CFG.get("dns_upstream", ""),
                       registrable_domain=registrable(probe), trusted=is_trusted(probe))


@app.route("/lab/block", methods=["POST"])
@login_req
def lab_block():
    domain = norm_domain(request.form.get("domain", ""))
    if domain:
        lines = []
        if CUSTOM_BLOCK.exists():
            lines = [l.strip() for l in CUSTOM_BLOCK.read_text(errors="ignore").splitlines() if l.strip()]
        if domain not in lines:
            lines.append(domain)
        atomic_write(CUSTOM_BLOCK, "\n".join(lines) + "\n")
        rebuild_master_blocklist()
        flush_caches()
    return redirect("/lab?domain=%s" % domain)


@app.route("/lab/allow", methods=["POST"])
@login_req
def lab_allow():
    domain = save_whitelist_entry(request.form.get("domain", ""))
    rebuild_master_blocklist()
    flush_caches()
    return redirect("/lab?domain=%s" % (domain or ""))


@app.route("/logs")
@login_req
def page_logs():
    return render_page(PAGE_LOGS, "logs", "Query Inspector", logs=list(QUERY_LOGS)[:300],
                       log_file=str(QUERY_LOG))


@app.route("/logs/clear", methods=["POST"])
@login_req
def logs_clear():
    QUERY_LOGS.clear()
    return redirect("/logs")


@app.route("/custom")
@login_req
def page_custom():
    b = CUSTOM_BLOCK.read_text(errors="ignore") if CUSTOM_BLOCK.exists() else ""
    w = CUSTOM_WHITE.read_text(errors="ignore") if CUSTOM_WHITE.exists() else ""
    return render_page(PAGE_CUSTOM, "cust", "Custom Rules", b_txt=b, w_txt=w,
                       wildcard_hint=cfg_bool("wildcard_engine"),
                       blocked_custom=len(CUSTOM_BLOCKED))


@app.route("/custom/save_block", methods=["POST"])
@login_req
def cust_block():
    raw = request.form.get("domains", "")
    clean = [norm_domain(l) or l.strip() for l in raw.splitlines() if l.strip()]
    atomic_write(CUSTOM_BLOCK, "\n".join(d for d in clean if "." in d) + "\n")
    load_custom_lists()
    rebuild_master_blocklist()
    flush_caches()
    return redirect("/custom")


@app.route("/custom/save_white", methods=["POST"])
@login_req
def cust_white():
    raw = request.form.get("domains", "")
    clean = []
    for line in raw.splitlines():
        line = line.strip().lstrip("@!").strip()
        if not line:
            continue
        d = norm_domain(line)
        if d:
            clean.append(d)
    atomic_write(CUSTOM_WHITE, "\n".join(clean) + ("\n" if clean else ""))
    load_custom_lists()
    flush_caches()
    return redirect("/custom")


@app.route("/settings", methods=["GET", "POST"])
@login_req
def page_settings():
    msg, msg_type = "", "ok"
    if request.method == "POST":
        form = request.form
        if "change_pw" in form:
            cur = hashlib.sha256(form.get("cur_pw", "").encode()).hexdigest()
            new_u = (form.get("new_username") or "").strip()
            npw, cpw = form.get("new_pw", ""), form.get("confirm_pw", "")
            if not hmac.compare_digest(cur, CFG.get("password_hash", "")):
                msg, msg_type = "Current password incorrect!", "err"
            elif npw and (len(npw) < 8 or npw != cpw):
                msg, msg_type = ("Password needs 8+ chars and must match confirmation", "err")
            else:
                if new_u:
                    CFG["admin_username"] = new_u
                if npw:
                    CFG["password_hash"] = hashlib.sha256(npw.encode()).hexdigest()
                    CFG["api_token"] = CFG["api_token"]
                    msg = "Credentials updated!"
                else:
                    msg = "Username updated!"
                save_config()
        elif "save_ai" in form:
            CFG["openrouter_api_key"] = (form.get("ai_key") or "").strip()
            CFG["ai_model"] = (form.get("ai_model") or "openrouter/free").strip()
            CFG["ai_triage"] = "ai_triage" in form or bool(CFG["openrouter_api_key"])
            save_config()
            msg = "AI triage saved"
        elif "save_sec" in form:
            for key in ("rebinding_protection", "dga_protection", "cname_uncloaking",
                        "amplification_protection", "rate_limiting", "youtube_aggressive"):
                CFG[key] = key in form
            save_config()
            flush_caches()
            msg = "Defense settings saved"
        elif "save_dns" in form:
            CFG["dns_upstream"] = (form.get("dns_upstream") or "1.1.1.1").strip()
            CFG["refresh_hours"] = max(1, int(form.get("refresh_hours", 24) or 24))
            CFG["rate_limit_rps"] = max(10, int(form.get("rate_limit_rps", 500) or 500))
            save_config()
            msg = "DNS settings saved"
        elif "save_coverage" in form:
            CFG["sinkhole_mode"] = form.get("sinkhole_mode", "zeroip")
            CFG["sinkhole_ip"] = (form.get("sinkhole_ip") or "").strip()
            try:
                CFG["sinkhole_port"] = int(form.get("sinkhole_port") or 80)
                CFG["cache_ttl"] = int(form.get("cache_ttl") or 300)
                CFG["dns_workers"] = max(4, int(form.get("dns_workers") or 32))
            except ValueError:
                pass
            for key in ("macro_ads", "micro_ads", "invideo_ads", "ctv_ads", "push_ads",
                         "adtech_endpoints", "email_tracking", "wildcard_engine", "pattern_engine",
                         "dga_protection", "typosquat_protection", "safe_search",
                         "youtube_aggressive"):
                CFG[key] = key in form
            save_config()
            rebuild_master_blocklist()
            flush_caches()
            msg = "Coverage profile saved - engine recompiled"
        elif "save_network" in form:
            CFG["upstream_mode"] = form.get("upstream_mode", "auto")
            CFG["dns_upstream"] = (form.get("dns_upstream") or "1.1.1.1").strip()
            CFG["doh_upstream"] = (form.get("doh_upstream") or "https://cloudflare-dns.com/dns-query").strip()
            try:
                CFG["dns_port"] = int(form.get("dns_port") or 53)
                CFG["web_port"] = int(form.get("web_port") or 8080)
                CFG["log_max"] = max(100, int(form.get("log_max") or 3000))
            except ValueError:
                pass
            CFG["log_enabled"] = "log_enabled" in form
            save_config()
            msg = "Resolver settings saved (restart the service to move ports)"
    coverage_toggles = [
        ("macro_ads", "Macro ads (banners, video, popups, native, CTV, push)"),
        ("micro_ads", "Micro ads (pixels, beacons, in-app SDKs, fingerprinting, telemetry)"),
        ("invideo_ads", "In-video and pre-roll ad endpoints"),
        ("ctv_ads", "Smart TV, console and OTT ad traffic"),
        ("push_ads", "Push-notification and popup ad gateways"),
        ("adtech_endpoints", "Ad exchanges, SSP/DSP and bidding calls"),
        ("email_tracking", "Email open and click tracking pixels"),
        ("wildcard_engine", "Wildcard zones (*.network)"),
        ("pattern_engine", "Ad-keyword pattern engine"),
        ("dga_protection", "DGA / entropy malware defence"),
        ("typosquat_protection", "Brand typosquat detection"),
        ("safe_search", "Force SafeSearch (Google / YouTube / Bing)"),
        ("youtube_aggressive", "YouTube aggressive ad stripping"),
    ]
    return render_page(PAGE_SETTINGS, "sett", "Settings", msg=msg, msg_type=msg_type, cfg=CFG,
                       coverage_toggles=coverage_toggles,
                       ai_key=CFG.get("openrouter_api_key", ""),
                       ai_model=CFG.get("ai_model", "openrouter/free"))


@app.route("/api/stats")
def api_stats():
    if not api_ok():
        return jsonify({"error": "unauthorized", "hint": "append ?token=<api_token>"}), 401
    return jsonify(stats_payload())


@app.route("/health")
def api_health_alias():
    return api_health()


@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "version": VERSION, "rules": len(BLOCKED),
                    "wildcards": len(WILDCARDS), "mode": CFG.get("block_mode"),
                    "uptime": int(time.time() - START_TIME),
                    "dns_bind_error": CFG.get("dns_bind_error")})


@app.route("/api/lookup")
def api_lookup():
    if not api_ok():
        return jsonify({"error": "unauthorized"}), 401
    domain = norm_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"error": "bad domain"}), 400
    return jsonify(dict(classify(domain), domain=domain,
                        trusted=is_trusted(domain), dga=is_dga(domain)))


@app.route("/api/block", methods=["GET", "POST"])
def api_block():
    if not api_ok():
        return jsonify({"error": "unauthorized"}), 401
    domain = norm_domain(request.values.get("domain", ""))
    if not domain:
        return jsonify({"error": "bad domain"}), 400
    path = CUSTOM_BLOCK
    lines = [l.strip() for l in path.read_text(errors="ignore").splitlines()] if path.exists() else []
    if domain not in lines:
        lines.append(domain)
    atomic_write(path, "\n".join(lines) + "\n")
    load_custom_lists()
    rebuild_master_blocklist()
    flush_caches()
    return jsonify({"ok": True, "blocked": domain, "rules": len(BLOCKED)})


@app.route("/api/allow", methods=["GET", "POST"])
def api_allow():
    if not api_ok():
        return jsonify({"error": "unauthorized"}), 401
    domain = norm_domain(request.values.get("domain", ""))
    if not domain:
        return jsonify({"error": "bad domain"}), 400
    remove_block_entry(domain)
    save_whitelist_entry(domain)
    rebuild_master_blocklist()
    flush_caches()
    return jsonify({"ok": True, "allowed": domain})


@app.route("/api/reload", methods=["POST", "GET"])
def api_reload():
    """Re-read custom black/white lists and recompile gravity - what `adquit block`
    calls so CLI changes take effect in the running resolver immediately."""
    if not api_ok():
        return jsonify({"error": "unauthorized"}), 401
    load_custom_lists()
    n = rebuild_master_blocklist()
    flush_caches()
    return jsonify({"ok": True, "rules": n, "wildcards": len(WILDCARDS)})


@app.route("/api/refresh", methods=["POST", "GET"])
def api_refresh():
    if not api_ok():
        return jsonify({"error": "unauthorized"}), 401
    threading.Thread(target=refresh_all, daemon=True).start()
    return jsonify({"ok": True, "started": True})


@app.route("/api/mode", methods=["POST", "GET"])
def api_mode():
    if not api_ok():
        return jsonify({"error": "unauthorized"}), 401
    mode = request.values.get("mode", "")
    if mode not in MODES:
        return jsonify({"error": "unknown mode", "modes": list(MODES)}), 400
    apply_mode(mode)
    return jsonify({"ok": True, "mode": mode, "rules": len(BLOCKED),
                    "feeds": len(CFG.get("enabled_lists", []))})


# ──────────────────────────────────────────────
#  Browser-level subscription (the part DNS cannot reach)
# ──────────────────────────────────────────────
# A resolver sees hostnames only.  Ads served from a host you must keep alive
# (youtube.com, google.com) arrive as *paths* on that host, so they need a
# filter-list.  The fortress generates one from its own state so a browser
# extension and the DNS engine never disagree - subscribe to /adquit.txt.
UBLOCK_PATH_RULES = [
    "! path rules: ad pods / ad reporting that ride on a host you keep allowed",
    "||youtube.com/api/stats/ads$important",
    "||youtube.com/api/stats/adevent$important",
    "||youtube.com/api/stats/brandprofiling$important",
    "||youtube.com/ptracking$important",
    "||youtube.com/get_midroll_info$important",
    "||youtube.com/annotations_invideo$important",
    "||youtube.com/yt_ad_types_api/get_ad_types$important",
    "||youtube.com/pagead/",
    "||www.google.com/pagead/",
    "||www.google.com/ads/intent/",
    "||ggpht.com/proxy/$image",
    "||google.com/ads/$third-party",
]
UBLOCK_COSMETIC = [
    "! cosmetics: collapse the slot so the page does not leave a gap",
    "youtube.com,youtube-nocookie.com##.ytp-ad-player-overlay",
    "youtube.com,youtube-nocookie.com##.ytp-ad-survey",
    "youtube.com,youtube-nocookie.com##.ytp-visit-advertiser-link",
    "youtube.com,youtube-nocookie.com##.ytp-ad-overlay-slot",
    "youtube.com##ytd-ad-slot-renderer",
    "youtube.com###masthead-ad",
    "youtube.com##ytd-rich-item-renderer:has(ytd-ad-slot-renderer)",
    "youtube.com##ytd-item-section-renderer:has(> #sections > ytd-ad-slot-renderer)",
    r"twitter.com,x.com##.promoted-tweet, [data-testid\:cellInnerDiv] .css-175oi2r:has(.r-1pi4i0q)",
    "reddit.com,forum.*##.promotedLink, [data-promotion-root]",
]


def build_ublock_subscription(all_rules=False, cap=None):
    """Text of an EasyList-style subscription mirroring this fortress."""
    cap = cap or int(CFG.get("ublock_max_rules", 4000 if not all_rules else 200000))
    host_counts = {}
    try:
        host_counts = {h: c for h, c in TOP_BLOCKED}
    except Exception:
        host_counts = {}
    out = [
        "! Title: NetBlock Fortress (adquit) - LAN subscription",
        "! Homepage: https://github.com/AfzalAshraf/NetBlock-Fortress",
        "! Expires: 1 day",
        "! Version: %s - generated %s by the fortress at %s"
        % (VERSION, datetime.now().strftime("%Y-%m-%d %H:%M"), socket.gethostname() or "this host"),
        "! Rules below mirror the DNS engine: %s exact + %s wildcard zones armed on this box."
        % ("{:,}".format(len(BLOCKED)), "{:,}".format(len(WILDCARDS))),
        "! Blocking at the resolver already covers these; this list adds the path-level",
        "! rules a DNS sinkhole cannot express.  Safe to run next to uBlock's own lists.",
        "",
    ]
    out += UBLOCK_PATH_RULES
    out.append("")
    out += UBLOCK_COSMETIC
    out.append("")
    out.append("! ---- hosts blocked on this fortress%s ----" % (" (all)" if all_rules else " (most requested)"))
    ordered = sorted(host_counts, key=lambda h: -host_counts[h]) if host_counts else []
    seen = set()
    for host in ordered + sorted(BLOCKED):
        host = norm_domain(host)
        if not host or host in seen or len(seen) >= cap:
            continue
        # skip anything a browser must reach for the filter to be honest about breakage
        if host in AD_PORTAL_HOSTS or is_trusted(host):
            continue
        seen.add(host)
        out.append("||%s^" % host)
    for zone in sorted(WILDCARDS)[:cap]:
        zone = norm_domain(zone)
        if zone and zone not in seen and not is_trusted(zone):
            out.append("||%s^" % zone)
    return "\n".join(out) + "\n"


@app.route("/adquit.txt")
def adquit_subscription():
    """Adblock-syntax subscription for browsers/apps, generated from live engine state."""
    full = request.args.get("all") in ("1", "true", "yes")
    body = build_ublock_subscription(all_rules=full)
    resp = Response(body, mimetype="text/plain", headers={
        "Content-Disposition": 'inline; filename="adquit.txt"',
        "Cache-Control": "public, max-age=3600",
        "X-Robots-Tag": "noindex",
    })
    return resp


# ──────────────────────────────────────────────
#  Domain intel (RDAP) - who is behind a landing page
# ──────────────────────────────────────────────
RDAP_CACHE = TTLCache(2000)


def rdap_lookup(domain, timeout=8):
    """Registration facts for a hostname via public RDAP.  Network-dependent and
    deliberately never used while answering DNS; `adquit intel` calls it."""
    zone = registrable(norm_domain(domain))
    if not zone or "." not in zone:
        return {"error": "not a registrable domain"}
    hit = RDAP_CACHE.get(zone)
    if hit:
        return hit
    info = {"zone": zone}
    try:
        res = requests.get("https://rdap.org/domain/%s" % zone, timeout=timeout,
                           headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
                           allow_redirects=True)
        if res.status_code != 200:
            return {"error": "rdap http %s" % res.status_code}
        data = res.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
        reg = ""
        for ent in data.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                for v in ent.get("vcardArray", [None, []])[1] or []:
                    if v and v[0] == "fn":
                        reg = v[3]
                break
        info["registrar"] = reg or "unknown"
        info["created"] = events.get("registration") or events.get("eventDate") or ""
        info["expires"] = events.get("expiration") or ""
        info["status"] = ",".join(data.get("status", []) or [])[:80]
        info["nameservers"] = sorted({h.get("ldhName", "") for h in data.get("nameservers", []) or []})[:6]
        if info["created"]:
            try:
                d = datetime.fromisoformat(info["created"][:10])
                info["age_days"] = (datetime.now() - d).days
            except Exception:
                pass
    except Exception as exc:
        return {"error": "unreachable (%s)" % type(exc).__name__}
    RDAP_CACHE.set(zone, info, 86400)     # registration facts move slowly: cache a day
    return info


def intel_report(domain):
    """Everything the fortress knows about one hostname + how to act on it."""
    d = norm_domain(domain)
    verdict = classify(d)
    out = {"domain": d, "zone": registrable(d), "action": verdict["action"],
           "reason": verdict["reason"], "layer": verdict["source"], "category": verdict["cat"],
           "vector": verdict["vec"], "trusted_zone": is_trusted(d),
           "requests_from_lan": sum(1 for h, c in TOP_BLOCKED if h == d)}
    out["rdap"] = rdap_lookup(d)
    age = out["rdap"].get("age_days")
    hints = []
    if age is not None and age <= 30:
        hints.append("registered %s days ago - freshly-baked domains in ads are a scam signal" % age)
    elif age is not None:
        hints.append("domain age %s days" % age)
    if out["rdap"].get("status") and any(k in out["rdap"]["status"].lower()
                                         for k in ("client transfer prohibited", "redemption", "pending")):
        hints.append("registry status: %s" % out["rdap"]["status"])
    if verdict["action"] != "block":
        hints.append("not blocked yet - arm it with:  adquit block %s" % d)
        if registrable(d) != d:
            hints.append("or kill the whole zone:      adquit block %s" % registrable(d))
    else:
        hints.append("blocked by %s (%s); subdomains of %s %s covered"
                     % (verdict["source"] or "engine", verdict["vec"], registrable(d),
                        "are" if verdict["reason"].startswith("Wildcard") or registrable(d) == d else "are not"))
    out["hints"] = hints
    return out


@app.route("/metrics")
def metrics():
    p = stats_payload()
    lines = [
        "# HELP adquit_rules_total compiled blocklist rules",
        "# TYPE adquit_rules_total gauge", "adquit_rules_total %s" % p["rules"],
        "adquit_wildcard_rules_total %s" % p["wildcards"],
        "adquit_feeds_enabled %s" % p["feeds_enabled"],
        "adquit_queries_total %s" % p["queries"],
        "adquit_blocked_total %s" % p["blocked"],
        "adquit_allowed_total %s" % p["allowed"],
        "adquit_block_rate_percent %s" % p["block_rate"],
        "adquit_clients %s" % p["clients"],
        "adquit_cache_hits_total %s" % p["cache_hits"],
        "adquit_pattern_hits_total %s" % p["pattern_hits"],
        "adquit_bandwidth_saved_bytes %s" % p["bandwidth_saved_bytes"],
        "adquit_uptime_seconds %s" % p["uptime_seconds"],
    ]
    for vec, cnt in sorted(p["vectors"].items(), key=lambda kv: -kv[1]):
        lines.append('adquit_vector_rules{vector="%s"} %s' % (vec, cnt))
    for cat, cnt in sorted(p["categories"].items(), key=lambda kv: -kv[1]):
        lines.append('adquit_category_rules{category="%s"} %s' % (cat, cnt))
    for dom, hits in p["top_blocked"][:10]:
        lines.append('adquit_top_blocked{domain="%s"} %s' % (dom, hits))
    return Response("\n".join(lines) + "\n", mimetype="text/plain")

# ──────────────────────────────────────────────
#  Command line interface (the `adquit` binary wraps these)
# ──────────────────────────────────────────────
def _api_get(path, params=None, timeout=6):
    url = "http://127.0.0.1:%s%s" % (CFG.get("web_port", 8080), path)
    params = dict(params or {})
    params.setdefault("token", CFG.get("api_token", ""))
    try:
        res = requests.get(url, params=params, timeout=timeout)
        if res.status_code == 200:
            return res.json()
        return {"_error": "http %s" % res.status_code}
    except Exception as exc:
        return {"_error": str(exc)[:100]}


def _api_raw(path, timeout=8):
    """Plain-text GET against the live service (no token needed for /adquit.txt)."""
    url = "http://127.0.0.1:%s%s" % (CFG.get("web_port", 8080), path)
    try:
        res = requests.get(url, timeout=timeout)
        if res.status_code == 200 and res.text.lstrip().startswith("!"):
            return res.text
    except Exception:
        pass
    return None


GREEN, RED, YEL, DIM, BOLD, RESET = ("\033[32m", "\033[31m", "\033[33m", "\033[2m",
                                     "\033[1m", "\033[0m")
if not sys.stdout.isatty():
    GREEN = RED = YEL = DIM = BOLD = RESET = ""


def tick(ok):
    return "%s✔%s" % (GREEN, RESET) if ok else "%s✘%s" % (RED, RESET)


def cmd_test(domains=None, live=True):
    """Engine self-test: seed rules must block, trusted sites must pass."""
    if not BLOCKED and not load_gravity_cache():
        rebuild_master_blocklist(persist=False)
    must_block = ["doubleclick.net", "pagead2.googlesyndication.com", "adservice.google.com",
                  "googleadservices.com", "an.facebook.com", "adsystem.com",
                  "config.unityads.unity3d.com", "securepubads.g.doubleclick.net",
                  "s0.2mdn.net", "adnxs.com"] + list(domains or [])
    must_pass = ["github.com", "google.com", "youtube.com", "microsoft.com", "apple.com",
                 "example.com", "openai.com", "reddit.com", "wikipedia.org", "cloudflare.com"]
    failed_block, failed_pass = [], []
    for d in must_block:
        if classify(d)["action"] != "block":
            failed_block.append(d)
    for d in must_pass:
        if classify(d)["action"] != "allow":
            failed_pass.append("%s (%s)" % (d, classify(d)["reason"]))
    print("\n%sNetBlock Fortress %s self-test%s" % (BOLD, VERSION, RESET))
    print("  rules armed: %s exact + %s wildcard zones\n"
          % ("{:,}".format(len(BLOCKED)), "{:,}".format(len(WILDCARDS))))
    print("  %s blocking verified on %s/%s ad hosts"
          % (tick(not failed_block), len(must_block) - len(failed_block), len(must_block)))
    if failed_block:
        print("    %snot blocked: %s%s" % (DIM, ", ".join(failed_block), RESET))
    print("  %s no false positives on %s/%s popular domains"
          % (tick(not failed_pass), len(must_pass) - len(failed_pass), len(must_pass)))
    if failed_pass:
        print("    %swrongly blocked: %s%s" % (YEL, ", ".join(failed_pass), RESET))
    ok_dns = True
    if live:
        probe = DNSRecord.question("doubleclick.net", "A")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(probe.pack(), ("127.0.0.1", int(CFG.get("dns_port", 53))))
            data, _ = s.recvfrom(4096)
            s.close()
            ans = DNSRecord.parse(data)
            answers = [str(r.rdata) for r in ans.rr if r.rtype == QTYPE.A]
            nxd = ans.header.rcode == RCODE.NXDOMAIN
            sink = {"0.0.0.0", "::", (CFG.get("sinkhole_ip") or "127.0.0.1")}
            ok_dns = bool(nxd or not answers or all(a in sink for a in answers))
            print("  %s live resolver on :%s answered %s (doubleclick.net)"
                  % (tick(ok_dns), CFG.get("dns_port", 53),
                     "NXDOMAIN" if nxd else (answers or "empty answer")))
        except Exception as exc:
            ok_dns = False
            print("  %s live resolver check skipped: %s" % (tick(False), exc))
    return 0 if (not failed_block and not failed_pass and ok_dns) else 1


def cmd_doctor():
    print("\n%sNetBlock Fortress %s doctor%s  (home: %s)\n" % (BOLD, VERSION, RESET, BASE_DIR))
    problems = 0
    checks = []
    checks.append(("python >= 3.8", sys.version_info >= (3, 8), sys.version.split()[0]))
    for mod in ("flask", "requests", "dnslib"):
        try:
            __import__(mod)
            checks.append(("module %s" % mod, True, "installed"))
        except Exception as exc:
            checks.append(("module %s" % mod, False, str(exc)[:40]))
    port = int(CFG.get("dns_port", 53))
    free = True
    who = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
    except OSError as exc:
        free = False
        who = "busy (%s)" % exc.__class__.__name__
    finally:
        s.close()
    if port == 53:
        listening = ""
        try:
            out = subprocess.run(["ss", "-ulpn", "sport = :53"], capture_output=True,
                                 text=True, timeout=5).stdout
            listening = " ".join(l.strip() for l in out.splitlines()[1:3])[:120]
        except Exception:
            pass
        checks.append(("udp/%s available" % port, free, listening or who or "free"))
        if not free and "systemd-resolved" in (listening or ""):
            print("%s  hint%s systemd-resolved owns :53 - run: "
                  "sudo adquit doctor --fix-resolved" % (YEL, RESET))
    else:
        checks.append(("udp/%s available" % port, True, "non-privileged port"))
    health = _api_get("/api/health")
    running = health.get("ok") is True
    checks.append(("fortress service running", running,
                   health.get("version", "not answering") if running else health.get("_error", "offline")))
    if running:
        checks.append(("rules compiled", health.get("rules", 0) > 0,
                       "%s exact / %s wildcards" % (health.get("rules"), health.get("wildcards"))))
        if health.get("dns_bind_error"):
            checks.append(("DNS bind", False, health["dns_bind_error"][:60]))
    feeds = [l for l in CFG.get("enabled_lists", []) if (LIST_DIR / ("%s.txt" % l)).exists()]
    checks.append(("feeds downloaded", len(feeds) > 0,
                   "%s/%s present" % (len(feeds), len(CFG.get("enabled_lists", [])))))
    bad = [l for l, st in LIST_STATUS.items() if st.get("state") == "error" and st.get("enabled")]
    checks.append(("feed errors", not bad, "%s failing: %s" % (len(bad), ", ".join(bad[:5])) if bad else "none"))
    checks.append(("writable data dir", os.access(DATA_DIR, os.W_OK), str(DATA_DIR)))
    default_pw = CFG.get("password_hash") == hashlib.sha256(b"admin123").hexdigest()
    checks.append(("default password changed", not default_pw,
                   "CHANGE IT: adquit passwd <new>" if default_pw else "ok"))
    web_free = True
    w = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    w.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        w.bind(("127.0.0.1", int(CFG.get("web_port", 8080))))
    except OSError:
        web_free = False
    finally:
        w.close()
    checks.append(("tcp/%s" % CFG.get("web_port"), web_free or running,
                   "in use by fortress" if (not web_free and running) else ("free" if web_free else "in use"))
                  )
    if os.geteuid() == 0:
        try:
            rc = open("/etc/resolv.conf").read()
            names = [l.split()[1] for l in rc.splitlines() if l.startswith("nameserver")]
            checks.append(("this host uses itself for DNS", "127.0.0.1" in names or "::1" in names,
                           "nameservers: %s" % ", ".join(names) or "none"))
        except Exception:
            pass
    for label, ok, detail in checks:
        if not ok:
            problems += 1
        print("  %s %-28s %s%s%s" % (tick(ok), label, DIM, detail, RESET))
    print("\n  %s%d issue(s)%s\n" % (YEL if problems else GREEN, problems, RESET))
    return 1 if problems else 0


def _notify_service():
    """Tell a running fortress to pick up rule/config changes made from the CLI."""
    res = _api_get("/api/reload")
    if res.get("ok"):
        print("[+] live service reloaded (%s rules, %s wildcard zones)"
              % ("{:,}".format(res.get("rules", 0)), "{:,}".format(res.get("wildcards", 0))))
    else:
        print("[i] no live service to notify - changes apply on the next start")

def cmd_stats(as_json=False):
    live = _api_get("/api/stats")
    if live.get("_error") and SNAPSHOT_FILE.exists():
        try:
            live = json.loads(SNAPSHOT_FILE.read_text())
            live["_note"] = "service offline - last snapshot"
        except Exception:
            pass
    if as_json:
        print(json.dumps(live, indent=2))
        return 0
    if live.get("_error"):
        print("%sFortress is not running%s (%s)" % (RED, RESET, live["_error"]))
        print("start it with: sudo adquit start")
        return 1
    macro = sum(v for vid, v in (live.get("vectors") or {}).items()
                if vid in MACRO_VECTORS)
    micro = sum(v for vid, v in (live.get("vectors") or {}).items() if vid in MICRO_VECTORS)
    print("\n%s  NetBlock Fortress %s - %s%s" % (BOLD, VERSION, live.get("mode", "?"), RESET))
    print("  queries %s | blocked %s (%s%%) | clients %s | uptime %s"
          % ("{:,}".format(live.get("queries", 0)), "{:,}".format(live.get("blocked", 0)),
             live.get("block_rate", 0), live.get("clients", 0),
             human_duration(live.get("uptime_seconds", 0))))
    print("  rules %s + %s wildcards from %s/%s feeds"
          % ("{:,}".format(live.get("rules", 0)), "{:,}".format(live.get("wildcards", 0)),
             live.get("feeds_enabled", 0), live.get("feeds_total", 0)))
    print("  macro ad rules %s | micro ad rules %s | cache hits %s"
          % ("{:,}".format(macro), "{:,}".format(micro), "{:,}".format(live.get("cache_hits", 0))))
    print("  bandwidth saved %s | time saved %s" % (live.get("bandwidth_saved", "-"),
                                                    live.get("time_saved", "-")))
    top = live.get("top_blocked") or []
    if top:
        print("\n%s  most blocked%s" % (BOLD, RESET))
        for row in top[:10]:
            print("    %-46s %s" % (row["domain"], "{:,}".format(row["hits"])))
    print("")
    return 0


def cmd_stats_watch():
    while True:
        os.system("clear")
        cmd_stats()
        time.sleep(2)


def cli(argv):
    """Tiny arg parser so the engine is usable without the adquit wrapper."""
    if not argv:
        return None
    cmd = argv[0]
    rest = argv[1:]
    if cmd in ("--version", "-V", "version"):
        print("NetBlock Fortress %s (%s)" % (VERSION, CODENAME))
        return 0
    if cmd in ("--help", "-h", "help"):
        print(__doc__)
        print("commands:\n  --stats | --json | --watch | --test [domain] | --doctor\n"
              "  --update-lists | --rebuild | --verify-lists | --mode <name>\n"
              "  --block <domain...> | --allow <domain...> | --unblock <domain>\n"
              "  --set-auth <user> <pass> | --set <key> <value> | --get <key>\n"
              "  --top | --health | --version | --export ublock [file] | --intel <domain>")
        return 0
    if cmd in ("--stats", "stats"):
        return cmd_stats()
    if cmd in ("--json", "json"):
        return cmd_stats(as_json=True)
    if cmd in ("--watch",):
        return cmd_stats_watch()
    if cmd in ("--test", "test"):
        return cmd_test([d for d in rest if not d.startswith("-")],
                        live="--no-live" not in rest)
    if cmd in ("--doctor", "doctor"):
        return cmd_doctor()
    if cmd in ("--health",):
        print(json.dumps(_api_get("/api/health"), indent=2))
        return 0
    if cmd in ("--export", "export"):
        what = rest[0] if rest and not rest[0].startswith("-") else "ublock"
        if what not in ("ublock", "adblock", "list"):
            print("[!] unknown export '%s' (available: ublock)" % what)
            return 2
        path = None
        for a in rest[1:]:
            if not a.startswith("-"):
                path = a
        all_rules = "--all" in rest
        text = None
        live = _api_raw("/adquit.txt" + ("?all=1" if all_rules else ""))   # service state wins
        if live:
            text = live
        else:
            text = build_ublock_subscription(all_rules=all_rules)
        dest = Path(path) if path else (DATA_DIR / "adquit.ublock.txt")
        try:
            dest.write_text(text)
        except Exception as exc:
            print("[!] could not write %s: %s" % (dest, exc))
            return 1
        n = sum(1 for line in text.splitlines() if line and not line.startswith("!"))
        print("[+] wrote %s (%s filter rules) - subscribe to it in uBlock Origin / AdGuard:"
              % (dest, "{:,}".format(n)))
        print("    either open that file, or use the live URL:  http://<fortress-ip>:%s/adquit.txt"
              % CFG.get("web_port", 8080))
        return 0
    if cmd in ("--intel", "intel"):
        targets = [a for a in rest if not a.startswith("-")]
        if not targets:
            print("[!] usage: --intel <domain> [<domain> ...]")
            return 2
        as_json = "--json" in rest
        for d in targets:
            rep = intel_report(d)
            if as_json:
                print(json.dumps(rep, indent=2))
                continue
            col = "BLOCK" if rep["action"] == "block" else "allow"
            print("%s  %s" % (d.center(max(28, len(d))), col))
            print("  verdict      %s  (layer: %s, %s)" % (rep["reason"], rep["layer"] or "engine", rep["vector"]))
            print("  zone         %s%s" % (rep["zone"], "   [trusted zone]" if rep["trusted_zone"] else ""))
            r = rep.get("rdap") or {}
            if r.get("error"):
                print("  registration unavailable (%s)" % r["error"])
            else:
                print("  registrar    %s" % r.get("registrar", "?"))
                print("  created      %s%s" % (r.get("created", "?")[:10],
                                               "" if r.get("age_days") is None else "  (%s days old)" % r["age_days"]))
                if r.get("nameservers"):
                    print("  ns           %s" % " ".join(x for x in r["nameservers"] if x))
            for h in rep.get("hints", []):
                print("  note         %s" % h)
            print()
        return 0
    if cmd in ("--update-lists", "--pull", "update-lists"):
        force = "--force" in rest
        print("[*] refreshing feeds (force=%s)..." % force)
        out = refresh_all(force=force)
        print("[+] %s" % json.dumps(out))
        return 0
    if cmd in ("--rebuild", "rebuild"):
        n = rebuild_master_blocklist()
        flush_caches()
        print("[+] gravity compiled: %s exact + %s wildcard rules"
              % ("{:,}".format(n), "{:,}".format(len(WILDCARDS))))
        return 0
    if cmd in ("--verify-lists", "verify-lists"):
        rows = verify_lists()
        ok = [r for r in rows if r["status"] == "ok"]
        for r in rows:
            mark = tick(r["status"] == "ok")
            print("  %s %-24s %-10s %s" % (mark, r["lid"], r["status"], r["url"][:64]))
        print("\n[+] %s/%s feeds reachable" % (len(ok), len(rows)))
        return 0 if len(ok) >= len(rows) * 0.8 else 1
    if cmd in ("--mode", "mode"):
        if not rest:
            print("current: %s | available: %s" % (CFG.get("block_mode"), ", ".join(MODES)))
            return 0
        if rest[0] not in MODES:
            print("[!] unknown mode. available: %s" % ", ".join(MODES))
            return 1
        apply_mode(rest[0])
        missing = [l for l in CFG.get("enabled_lists", [])
                   if not (LIST_DIR / ("%s.txt" % l)).exists()]
        print("[+] mode %s armed (%s feeds, %s not yet downloaded)"
              % (rest[0], len(CFG.get("enabled_lists", [])), len(missing)))
        if missing:
            ping = _api_get("/api/refresh")
            if ping.get("ok"):
                print("[*] the running fortress is pulling the missing feeds now "
                      "(watch: adquit logs)")
            else:
                print("[*] run 'adquit gravity' to download them")
        return 0
    if cmd in ("--block", "block"):
        if not rest:
            print("[!] usage: --block domain.tld [more...]")
            return 1
        path = CUSTOM_BLOCK
        lines = ([l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
                 if path.exists() else [])
        added = []
        for raw in rest:
            d = norm_domain(raw)
            if d and d not in lines:
                lines.append(d)
                added.append(d)
        atomic_write(path, "\n".join(lines) + "\n")
        load_custom_lists()
        rebuild_master_blocklist()
        flush_caches()
        print("[+] blocked: %s (%s rules live)" % (", ".join(added) or "nothing new",
                                                   "{:,}".format(len(BLOCKED))))
        _notify_service()
        return 0
    if cmd in ("--allow", "allow"):
        if not rest:
            print("[!] usage: --allow domain.tld [more...]")
            return 1
        done = [save_whitelist_entry(d) for d in rest]
        rebuild_master_blocklist()
        flush_caches()
        print("[+] allowed: %s" % ", ".join(x for x in done if x))
        _notify_service()
        return 0
    if cmd in ("--unblock",):
        if not rest:
            print("[!] usage: --unblock domain.tld")
            return 1
        removed = [remove_block_entry(d) for d in rest]
        print("[+] removed %s custom rules" % sum(1 for r in removed if r))
        _notify_service()
        return 0
    if cmd in ("--set-auth",):
        if len(rest) < 2:
            print("[!] usage: --set-auth <username> <password>")
            return 1
        CFG["admin_username"] = rest[0].strip()
        CFG["password_hash"] = hashlib.sha256(rest[1].encode()).hexdigest()
        save_config()
        print("[+] dashboard login is now %s" % rest[0])
        return 0
    if cmd in ("--passwd",):
        pw = rest[0] if rest else None
        if not pw:
            import getpass
            pw = getpass.getpass("new dashboard password: ")
        if len(pw) < 8:
            print("[!] password must be at least 8 characters")
            return 1
        CFG["password_hash"] = hashlib.sha256(pw.encode()).hexdigest()
        save_config()
        print("[+] password updated")
        return 0
    if cmd in ("--set",):
        if len(rest) < 2:
            print("[!] usage: --set <key> <value>")
            return 1
        key = rest[0]
        if key not in DEFAULT_CONFIG:
            print("[!] unknown key. keys: %s" % ", ".join(sorted(DEFAULT_CONFIG)))
            return 1
        val = rest[1]
        default = DEFAULT_CONFIG[key]
        if isinstance(default, bool):
            val = val.lower() in ("1", "true", "on", "yes")
        elif isinstance(default, int):
            val = int(val)
        elif isinstance(default, list):
            val = [x.strip() for x in val.split(",") if x.strip()]
        CFG[key] = val
        save_config()
        if key in VECTOR_SWITCH.values() or key in ("block_mode", "enabled_lists"):
            rebuild_master_blocklist()
            flush_caches()
        print("[+] %s = %s" % (key, val))
        return 0
    if cmd in ("--get",):
        for key in (rest or sorted(DEFAULT_CONFIG)):
            print("%s = %s" % (key, json.dumps(CFG.get(key))))
        return 0
    if cmd in ("--top",):
        n = int(rest[0]) if rest and rest[0].isdigit() else 15
        live = _api_get("/api/stats")
        rows = live.get("top_blocked") or sorted(TOP_GLOBAL.items(), key=lambda kv: -kv[1])[:n]
        for row in rows[:n]:
            if isinstance(row, dict):
                print("%-48s %s" % (row["domain"], row["hits"]))
            else:
                print("%-48s %s" % (row[0], row[1]))
        return 0
    if cmd in ("--rules",):
        for d in rest:
            v = classify(d)
            print("%-40s %-6s %-12s %s" % (d, v["action"].upper(), v["cat"], v["reason"]))
        return 0
    if cmd in ("--serve", "run", "--daemon", "-d"):
        return None          # fall through to the real server bootstrap
    print("[!] unknown command: %s (try --help)" % cmd)
    return 2


# ──────────────────────────────────────────────
#  Server startup
# ──────────────────────────────────────────────
def start_engine_threads():
    threading.Thread(target=dns_udp_worker, daemon=True, name="dns-udp").start()
    time.sleep(0.15)
    threading.Thread(target=dns_tcp_worker, daemon=True, name="dns-tcp").start()
    threading.Thread(target=gravity_boot_worker, daemon=True, name="gravity").start()
    threading.Thread(target=housekeeping_worker, daemon=True, name="housekeeping").start()
    threading.Thread(target=start_sinkhole_server, daemon=True, name="sinkhole").start()


SERVE_FLAGS = ("--serve", "--daemon", "-d", "run")


def main():
    argv = sys.argv[1:]
    if argv and argv[0].startswith("-") and argv[0] not in SERVE_FLAGS:
        sys.exit(cli(argv) or 0)
    _boot_t0 = time.time()
    cache_ok = bool(BLOCKED) or load_gravity_cache()
    custom_blocked, _custom_allowed = load_custom_lists()
    if cache_ok and not apply_custom_overrides(custom_blocked):
        cache_ok = False
    if not cache_ok:
        LOG.info("building gravity from %s enabled feeds (no usable cache yet)",
                 len(CFG.get("enabled_lists", [])))
        rebuild_master_blocklist()
    _sync_legacy_views(custom_blocked)
    _write_banners()
    start_engine_threads()
    port = int(CFG.get("web_port", 8080))
    LOG.info("dashboard on http://0.0.0.0:%s (user: %s) - rules: %s, ready in %.1fs", port,
             CFG.get("admin_username"), "{:,}".format(len(BLOCKED) + len(WILDCARDS)),
             time.time() - _boot_t0)
    try:
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True,
                use_reloader=False)
    except OSError as exc:
        LOG.error("dashboard could not bind port %s: %s", port, exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
