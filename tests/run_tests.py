#!/usr/bin/env python3
"""
NetBlock Fortress - offline test suite.

No pytest, no network: `python3 tests/run_tests.py` is all you need.
The suite builds a throwaway ADQUIT_HOME, drops the sample feeds from
tests/fixtures into it as custom lists, imports app.py and asserts that the
micro/macro engine blocks what it must and never touches what it must not.
"""

import importlib.util
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FIXTURES = HERE / "fixtures"

HOME = Path(tempfile.mkdtemp(prefix="adquit-tests-"))
(HOME / "data" / "lists").mkdir(parents=True, exist_ok=True)

FIXTURE_MAP = {
    "fx_hosts": "hosts_style.txt",
    "fx_adblock": "adblock_style.txt",
    "fx_wildcard": "wildcard_style.txt",
    "fx_urls": "mixed_urls.txt",
    "fx_plain": "one_per_line.txt",
}
FIXTURE_IDS = list(FIXTURE_MAP)
for fid, fname in FIXTURE_MAP.items():
    shutil.copy(FIXTURES / fname, HOME / "data" / "lists" / (fid + ".txt"))

custom = {fid: {"name": fid, "cat": "ads", "vec": "banner", "url": "file://local"}
          for fid in FIXTURE_IDS}
(HOME / "data" / "config.json").write_text(json.dumps({
    "enabled_lists": FIXTURE_IDS,
    "custom_lists": custom,
    "block_mode": "strict",
    "pattern_engine": True,
    "pattern_action": "enforce",
    "wildcard_engine": True,
    "micro_ads": True,
    "macro_ads": True,
    "invideo_ads": True,
    "ctv_ads": True,
    "dns_port": 5399,
    "web_port": 18099,
    "sinkhole_mode": "zeroip",
    "log_enabled": False,
    "rate_limit_rps": 500,
}))

os.environ["ADQUIT_HOME"] = str(HOME)
os.environ["ADQUIT_NO_PIP"] = "1"
sys.path.insert(0, str(REPO))

_spec = importlib.util.spec_from_file_location("nb_app", str(REPO / "app.py"))
nb = importlib.util.module_from_spec(_spec)
sys.modules["nb_app"] = nb
_spec.loader.exec_module(nb)

# no test may ever reach the network
def _no_network(*a, **k):
    raise AssertionError("network access attempted during tests")


nb.requests.get = _no_network
nb.requests.post = _no_network


def verdict(domain):
    return nb.classify(domain)


class TestFeedParser(unittest.TestCase):
    def test_hosts_format(self):
        text = (FIXTURES / "hosts_style.txt").read_bytes()
        exact, wild, unb = nb.parse_source_bytes(text)
        self.assertIn("ads.example-ads.com", exact)
        self.assertTrue(all("#" not in d for d in exact))
        self.assertIn("track.one-more-tracker.com", exact)
        self.assertIn("tracker-second.example.net", exact)     # second host on one line
        self.assertNotIn("localhost", exact)
        self.assertNotIn("192.168.1.1", exact)
        self.assertFalse(any(".." in d for d in exact))

    def test_adblock_format(self):
        exact, wild, unb = nb.parse_source_bytes((FIXTURES / "adblock_style.txt").read_bytes())
        self.assertIn("ads.adblock-one.com", exact)
        self.assertIn("track.adblock-two.com", exact)          # $third-party option stripped
        self.assertIn("popup.adblock-three.com", exact)
        self.assertIn("direct-url-ad.com", exact)             # |http://... style
        self.assertIn("unbreak.example.com", unb)             # @@ exception
        self.assertNotIn(".example.com##.ad-banner", "".join(exact))   # cosmetic rule ignored
        self.assertTrue(all("##" not in d for d in exact))

    def test_wildcard_format(self):
        exact, wild, unb = nb.parse_source_bytes((FIXTURES / "wildcard_style.txt").read_bytes())
        self.assertIn("ads.wildcard-prefix.com", wild | exact)
        self.assertIn("doubleclick-parent.com", wild | exact)

    def test_urls_and_idna(self):
        exact, wild, unb = nb.parse_source_bytes((FIXTURES / "mixed_urls.txt").read_bytes())
        self.assertIn("url-only-ads.com", exact)
        self.assertIn("other-ads.io", exact)
        self.assertIn("ads.mixed-case.com", exact)            # lower-cased
        self.assertIn("xn--pple-43d.com", exact)              # punycode kept
        self.assertNotIn("garbage-line", exact)


class TestEngineLayers(unittest.TestCase):
    def test_seed_blocks_instantly(self):
        for dom in ("doubleclick.net", "pagead2.googlesyndication.com", "googleadservices.com",
                    "adsystem.com", "unityads.unity3d.com", "s.youtube.com"):
            self.assertEqual(verdict(dom)["action"], "block", dom)

    def test_subdomain_inheritance(self):
        self.assertEqual(verdict("x.y.doubleclick.net")["action"], "block")

    def test_feed_exact_and_parent(self):
        self.assertEqual(verdict("ads.example-ads.com")["action"], "block")
        self.assertEqual(verdict("deep.ads.example-ads.com")["action"], "block")

    def test_unbreak_exception_beats_ad_feed(self):
        # unbreak.example.com is an @@ exception; it must stay reachable
        self.assertEqual(verdict("unbreak.example.com")["action"], "allow")

    def test_macro_keyword_patterns(self):
        for dom in ("ads.exoclick.com", "cdn.taboola.com", "sync.outbrain.com",
                    "match.adsrvr.org", "ib.adnxs.com"):
            self.assertEqual(verdict(dom)["action"], "block", dom)

    def test_micro_sdk_and_pixel_patterns(self):
        self.assertEqual(verdict("config.unityads.unity3d.com")["action"], "block")
        self.assertEqual(verdict("securepubads.g.doubleclick.net")["action"], "block")
        self.assertEqual(verdict("log.hotjar.com")["action"], "block")
        self.assertEqual(verdict("api.mixpanel.com")["action"], "block")
        self.assertEqual(verdict("fp.fingerprintjs.com")["action"], "block")

    def test_youtube_ad_edges(self):
        self.assertEqual(verdict("r1---sn-4g5edn7s.googlevideo.com")["action"], "block")
        self.assertEqual(verdict("staticads.youtube.com")["action"], "block")

    def test_trusted_zones_never_pattern_blocked(self):
        for dom in ("stats.github.com", "analytics.reddit.com", "ads.facebook.com",
                    "telemetry.microsoft.com", "log.amazon.com"):
            self.assertEqual(verdict(dom)["action"], "allow", dom)

    def test_advertiser_dashboards_stay_up(self):
        self.assertEqual(verdict("ads.tiktok.com")["action"], "allow")
        self.assertEqual(verdict("business.facebook.com")["action"], "allow")

    def test_public_services_clean(self):
        for dom in ("github.com", "google.com", "wikipedia.org", "openai.com", "example.com",
                    "news.ycombinator.com", "archive.org"):
            self.assertEqual(verdict(dom)["action"], "allow", dom)

    def test_dga_detection(self):
        self.assertTrue(nb.is_dga("xk3v9zq7plmt2drw.com"))
        self.assertFalse(nb.is_dga("google.com"))
        self.assertFalse(nb.is_dga("mozilla.org"))

    def test_homograph_detection(self):
        self.assertTrue(nb.is_homograph("xn--pple-43d.com"))
        self.assertFalse(nb.is_homograph("apple.com"))

    def test_label_tier_only_in_strict(self):
        # a publisher's own "ads." subdomain: caught in strict, only shadowed in balanced
        nb.CFG["block_mode"] = "strict"
        nb.flush_caches()
        self.assertEqual(verdict("ads.small-publisher-site.net")["action"], "block")
        nb.CFG["block_mode"] = "balanced"
        nb.flush_caches()
        self.assertEqual(verdict("ads.small-publisher-site.net")["action"], "allow")
        nb.CFG["block_mode"] = "strict"
        nb.flush_caches()

    def test_nuclear_mode_adds_heuristics(self):
        nb.CFG["block_mode"] = "strict"
        nb.flush_caches()
        self.assertEqual(verdict("totally-legit-site.click")["action"], "allow")
        nb.CFG["block_mode"] = "nuclear"
        nb.CFG["typosquat_protection"] = True
        nb.flush_caches()
        self.assertEqual(verdict("totally-legit-site.click")["action"], "block")
        self.assertEqual(verdict("paypa1.com")["action"], "block")
        nb.CFG["block_mode"] = "strict"
        nb.CFG["typosquat_protection"] = False
        nb.flush_caches()

    def test_vector_switch_disables_micro(self):
        self.assertEqual(verdict("config.unityads.unity3d.com")["action"], "block")
        nb.CFG["micro_ads"] = False
        nb.rebuild_master_blocklist(persist=False)
        nb.flush_caches()
        # seed entry for unity is a "sdk" vector -> gated off by the micro switch
        self.assertEqual(verdict("config.unityads.unity3d.com")["action"], "allow")
        # safety feeds ignore ad switches, so malware-ish entries would stay
        nb.CFG["micro_ads"] = True
        nb.rebuild_master_blocklist(persist=False)
        nb.flush_caches()

    def test_whitelist_wins_over_everything(self):
        nb.save_whitelist_entry("doubleclick.net")
        nb.rebuild_master_blocklist(persist=False)
        nb.flush_caches()
        self.assertEqual(verdict("doubleclick.net")["action"], "allow")
        self.assertEqual(verdict("anything.doubleclick.net")["action"], "allow")
        (HOME / "data" / "custom_whitelist.txt").write_text("")
        nb.load_custom_lists()
        nb.flush_caches()

    def test_single_label_and_local_names(self):
        self.assertEqual(verdict("printer")["action"], "allow")
        self.assertEqual(verdict("")["action"], "allow")


class TestDNSResponses(unittest.TestCase):
    def _ask(self, name, qtype="A"):
        from dnslib import DNSRecord
        req = DNSRecord.question(name, qtype)
        out = []
        nb.handle_dns_request(req.pack(), ("10.0.0.5", 53000), lambda p, a: out.append(p))
        self.assertTrue(out, "no reply for %s/%s" % (name, qtype))
        return DNSRecord.parse(out[0])

    def test_blocked_a_is_zeroip(self):
        from dnslib import RCODE
        reply = self._ask("doubleclick.net", "A")
        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(reply.rr[0].rdata), "0.0.0.0")

    def test_blocked_aaaa_is_ipv6_unspecified(self):
        reply = self._ask("doubleclick.net", "AAAA")
        self.assertEqual(str(reply.rr[0].rdata), "::")

    def test_nxdomain_mode(self):
        from dnslib import RCODE
        nb.CFG["sinkhole_mode"] = "nxdomain"
        reply = self._ask("doubleclick.net", "A")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        nb.CFG["sinkhole_mode"] = "zeroip"

    def test_amplification_refused(self):
        from dnslib import RCODE
        reply = self._ask("doubleclick.net", "ANY")
        self.assertEqual(reply.header.rcode, RCODE.REFUSED)

    def test_local_zone_nxdomain(self):
        from dnslib import RCODE
        reply = self._ask("printer.local", "A")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)

    def test_stats_and_log_wiring(self):
        before = nb.TOTAL_QUERIES
        self._ask("pagead2.googlesyndication.com", "A")
        self._ask("pagead2.googlesyndication.com", "A")
        self.assertGreaterEqual(nb.TOTAL_QUERIES - before, 2)
        self.assertIn("10.0.0.5", nb.CLIENT_ACTIVITY)
        self.assertGreaterEqual(nb.CLIENT_ACTIVITY["10.0.0.5"]["blocked"], 2)
        self.assertEqual(nb.TOP_GLOBAL["pagead2.googlesyndication.com"], 2)

    def test_decision_cache_hit(self):
        nb.flush_caches()
        hits0 = nb.CACHE_HITS
        nb.classify("taboola.com")
        nb.classify("taboola.com")
        self.assertGreater(nb.CACHE_HITS, hits0)

    def test_rate_limiter(self):
        nb.CLIENT_RATES.clear()
        nb.CFG["rate_limiting"] = True
        nb.CFG["rate_limit_rps"] = 3
        results = [nb.rate_limit_check("10.9.9.9") for _ in range(6)]
        self.assertEqual(results[:3], [True, True, True])
        self.assertFalse(all(results[3:]))
        nb.CFG["rate_limit_rps"] = 500
        nb.CLIENT_RATES.clear()


class TestModesAndConfig(unittest.TestCase):
    def test_profiles(self):
        self.assertIn("off", nb.MODES)
        self.assertIn("nuclear", nb.MODES)
        nb.apply_mode("off")
        self.assertEqual(len(nb.CFG["enabled_lists"]), 0)
        nb.apply_mode("strict")
        self.assertGreater(len(nb.CFG["enabled_lists"]), 30)
        nb.apply_mode("family")
        self.assertIn("sb_porn", nb.CFG["enabled_lists"])
        nb.apply_mode("nuclear")
        self.assertIn("hagezi_ultimate", nb.CFG["enabled_lists"])
        self.assertEqual(nb.CFG["typosquat_protection"], True)
        nb.apply_mode("strict")

    def test_registry_integrity(self):
        self.assertGreaterEqual(len(nb.ALL_LISTS), 100)
        for lid, info in nb.ALL_LISTS.items():
            self.assertIn(info["cat"], nb.CAT, lid)
            self.assertIn(info["vec"], nb.VECTORS, lid)
            self.assertTrue(info["url"].startswith("https://"), lid)
        for vec in nb.VECTORS:
            self.assertIn(vec, nb.VECTOR_SWITCH)
        self.assertGreaterEqual(len(nb.DEFAULT_ENABLED), 50)
        self.assertTrue(set(nb.DEFAULT_ENABLED).issubset(set(nb.ALL_LISTS)))

    def test_legacy_id_migration(self):
        cfg = {"enabled_lists": ["adguard", "oisd", "hagezi_ulti", "nonexistent"]}
        nb.migrate_list_ids(cfg)
        self.assertIn("adguard_dns", cfg["enabled_lists"])
        self.assertIn("oisd_big", cfg["enabled_lists"])
        self.assertIn("hagezi_ultimate", cfg["enabled_lists"])
        self.assertNotIn("nonexistent", cfg["enabled_lists"])

    def test_config_roundtrip_and_schema(self):
        nb.CFG["macro_ads"] = False
        nb.save_config()
        saved = json.loads((HOME / "data" / "config.json").read_text())
        self.assertIs(saved["macro_ads"], False)
        nb.CFG["macro_ads"] = True
        nb.save_config()
        # every default key survives migration
        merged = nb._migrate_config({"block_mode": "strict"})
        for key in nb.DEFAULT_CONFIG:
            self.assertIn(key, merged)

    def test_cli_block_and_allow(self):
        code = nb.cli(["--block", "annoying-ads.biz"])
        self.assertEqual(code, 0)
        self.assertIn("annoying-ads.biz", (HOME / "data" / "custom_blocked.txt").read_text())
        nb.flush_caches()
        self.assertEqual(verdict("annoying-ads.biz")["action"], "block")
        nb.cli(["--allow", "annoying-ads.biz"])
        nb.rebuild_master_blocklist(persist=False)
        nb.flush_caches()
        self.assertEqual(verdict("annoying-ads.biz")["action"], "allow")
        nb.cli(["--unblock", "annoying-ads.biz"])

    def test_api_payload_shape(self):
        payload = nb.stats_payload()
        for key in ("version", "queries", "blocked", "rules", "macro_rules", "micro_rules",
                    "vectors", "feeds_enabled", "block_rate", "bandwidth_saved"):
            self.assertIn(key, payload)
        self.assertGreaterEqual(payload["rules"], 200)


class TestHelpers(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(nb.registrable("a.b.c.github.com"), "github.com")
        self.assertEqual(nb.registrable("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(nb.registrable("example"), "example")

    def test_norm_domain(self):
        self.assertEqual(nb.norm_domain("HTTPS://Ads.Example.COM/path?x=1"), "ads.example.com")
        self.assertIsNone(nb.norm_domain("not a domain"))
        self.assertIsNone(nb.norm_domain("10.0.0.1"))
        self.assertEqual(nb.norm_domain("*.track.example.net".lstrip("*.")), "track.example.net")

    def test_private_ip(self):
        self.assertTrue(nb.is_private_ip("192.168.1.10"))
        self.assertTrue(nb.is_private_ip("127.0.0.1"))
        self.assertFalse(nb.is_private_ip("8.8.8.8"))

    def test_human_formatting(self):
        self.assertEqual(nb.human_bytes(2048), "2.0 KB")
        self.assertIn("m", nb.human_duration(125))

    def test_trusted_zone_suffixes(self):
        self.assertTrue(nb.is_trusted("www.whitehouse.gov"))
        self.assertTrue(nb.is_trusted("cs.stanford.edu"))
        self.assertFalse(nb.is_trusted("evil-ad-network.com"))


class TestWebSurface(unittest.TestCase):
    """Every dashboard page must render (this is where v18 users hit freezes)."""

    @classmethod
    def setUpClass(cls):
        cls.client = nb.app.test_client()

    def login(self):
        with nb.app.test_request_context():
            pass
        self.client.post("/login", data={"username": "admin", "password": "admin123"},
                         follow_redirects=False)

    def test_pages_render(self):
        self.login()
        for path in ("/", "/coverage", "/blocklists", "/modes", "/logs", "/custom",
                     "/settings", "/security", "/lab?domain=doubleclick.net", "/lab",
                     "/api/list_status", "/metrics", "/health"):
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200, "%s -> %s" % (path, res.status_code))

    def test_unauth_api_rejected(self):
        res = nb.app.test_client().get("/api/stats")
        self.assertIn(res.status_code, (401, 302))

    def test_token_api_ok(self):
        token = nb.CFG["api_token"]
        res = self.client.get("/api/stats?token=" + token)
        self.assertEqual(res.status_code, 200)
        self.assertIn("rules", json.loads(res.data))

    def test_wrong_password_rejected(self):
        client = nb.app.test_client()
        res = client.post("/login", data={"username": "admin", "password": "wrong"},
                          follow_redirects=True)
        self.assertIn(b"Invalid username or password", res.data)
        res = client.post("/login", data={"username": "root", "password": "admin123"},
                          follow_redirects=True)
        self.assertIn(b"Invalid username or password", res.data)

    def test_coverage_toggle_roundtrip(self):
        self.login()
        before = nb.CFG["ctv_ads"]
        self.client.post("/coverage/toggle", data={"key": "ctv_ads"})
        self.assertEqual(nb.CFG["ctv_ads"], not before)
        self.client.post("/coverage/toggle", data={"key": "ctv_ads"})
        self.assertEqual(nb.CFG["ctv_ads"], before)

    def test_feed_add_and_mode_switch(self):
        self.login()
        res = self.client.post("/blocklists/add_feed",
                               data={"url": "https://example.org/feed.txt", "name": "Test",
                                     "cat": "ads"}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(any("example.org" in v["url"] for v in nb.CFG["custom_lists"].values()))
        res = self.client.post("/modes/set", data={"mode": "balanced"}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertEqual(nb.CFG["block_mode"], "balanced")
        nb.apply_mode("strict")

    def test_api_block_allow(self):
        token = nb.CFG["api_token"]
        res = self.client.post("/api/block?token=" + token, data={"domain": "spam-ads.pw"})
        self.assertEqual(res.status_code, 200)
        nb.flush_caches()
        self.assertEqual(verdict("spam-ads.pw")["action"], "block")
        res = self.client.post("/api/allow?token=" + token, data={"domain": "spam-ads.pw"})
        self.assertEqual(res.status_code, 200)
        nb.rebuild_master_blocklist(persist=False)
        nb.flush_caches()
        self.assertEqual(verdict("spam-ads.pw")["action"], "allow")


class TestSinkholeHTTP(unittest.TestCase):
    def test_empty_creative_served_for_blocked_host(self):
        import threading
        from http.server import BaseHTTPRequestHandler
        nb.CFG["sinkhole_mode"] = "fortress"
        nb.CFG["sinkhole_port"] = 18077
        nb.CFG["sinkhole_splash"] = True
        # build the server exactly as the app does, then talk to it
        t = threading.Thread(target=nb.start_sinkhole_server, daemon=True)
        t.start()
        import time as _t
        _t.sleep(0.7)
        try:
            s = socket.create_connection(("127.0.0.1", 18077), timeout=4)
            s.sendall(b"GET /pixel.gif HTTP/1.1\r\nHost: doubleclick.net\r\n"
                      b"Accept: image/*\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            self.assertIn(b"200", data.split(b"\r\n")[0])
            self.assertIn(b"image/gif", data)
            self.assertIn(b"GIF89a", data)
        finally:
            nb.CFG["sinkhole_mode"] = "zeroip"


class TestYouTubeAdPayload(unittest.TestCase):
    """Every host a real 'YouTube pre-roll told us about' payload points at, plus the
    hosts that payload's *player* needs to keep working.  Regression cover for v19.1:
    these were the ad endpoints the strict profile still let through."""

    MUST_BLOCK = [
        # ad serving / verification / reporting
        "pagead2.googlesyndication.com", "pagead.googlesyndication.com",
        "ade.googlesyndication.com", "googleadservices.com", "www.googleadservices.com",
        "ad.doubleclick.net", "static.doubleclick.net", "pubads.g.doubleclick.net",
        "securepubads.g.doubleclick.net", "googleads.g.doubleclick.net",
        "static.googleadsserving.cn", "pagead.google.com", "pagead.l.google.com",
        "adservice.google.com", "adservice.google.ae", "dai.google.com",
        # player telemetry / measurement
        "s.youtube.com", "video-stats.l.google.com", "video-stats.youtube.com",
        "app-measurement.com", "firebaselogging.googleapis.com",
        "crashlyticsreports-pa.googleapis.com", "pulse.video", "doubleverify.com",
        "adsafeprotected.com", "innovid.com", "imasdk.googleapis.com",
        "staticads.youtube.com", "youtubeadsdk.com",
        # ad-UX endpoints (the "My Ad Center" / transparency panels report here)
        "myadcenter.google.com", "adstransparency.google.com",
    ]
    MUST_ALLOW = [
        "www.youtube.com", "m.youtube.com", "music.youtube.com", "tv.youtube.com",
        "i.ytimg.com", "yt3.ggpht.com", "yt3.googleusercontent.com",
        "manifest.googlevideo.com", "www.google.com", "accounts.google.com",
        "play.google.com", "gstatic.com", "ads.google.com",       # campaign manager
        "adssettings.google.com",                                  # ad opt-out controls
        "dart.dev",                                                # shares a label, not ours
    ]

    def test_ad_payload_hosts_are_sinkholed(self):
        gaps = [d for d in self.MUST_BLOCK if verdict(d)["action"] != "block"]
        self.assertEqual([], gaps, "these ad endpoints are still reachable: %s" % gaps)

    def test_player_and_public_services_stay_up(self):
        broken = [d for d in self.MUST_ALLOW
                  if verdict(d)["action"] == "block"]
        self.assertEqual([], broken, "the engine broke: %s" % broken)

    def test_hard_ad_label_override_is_scoped_to_the_estate(self):
        # Google owns both the ad tech and the trusted zones, so an ad label under a
        # google zone must die anyway - that is the layer-5b override, and it is
        # deliberately limited to the named labels of that estate.
        v = verdict("pagead.google.co.uk")
        self.assertEqual("block", v["action"])
        self.assertIn("trusted zone", v["reason"])
        # an ad-*sounding* label that is not on the hard list stays reachable
        self.assertEqual("allow", verdict("myads.google.com")["action"])
        # a host that merely shares a name with an ad technology stays reachable too
        self.assertEqual("allow", verdict("dart.dev")["action"])
        self.assertEqual("allow", verdict("adsense.garden")["action"])


class TestSubscriptionExport(unittest.TestCase):
    """`adquit export ublock` + http://fortress:8080/adquit.txt - the path-level half
    of the job a resolver cannot do (ads that ride on youtube.com / google.com)."""

    def test_subscription_builds(self):
        text = nb.build_ublock_subscription()
        lines = [l for l in text.splitlines() if l and not l.startswith("!")]
        self.assertGreater(len(lines), 150, "subscription too thin: %s rules" % len(lines))
        self.assertTrue(text.startswith("! Title:"), text[:40])
        for needle in ("||youtube.com/api/stats/ads$important",
                       "||youtube.com/get_midroll_info$important",
                       "||youtube.com/ptracking$important",
                       "||google.com/ads/$third-party",
                       "youtube.com##ytd-ad-slot-renderer"):
            self.assertIn(needle, text)

    def test_subscription_mirrors_engine_and_respects_exemptions(self):
        text = nb.build_ublock_subscription()
        self.assertIn("||doubleclick.net^", text)
        for must_not in ("||youtube.com^", "||gstatic.com^", "||ads.google.com^"):
            self.assertNotIn(must_not, text, "subscription would break: %s" % must_not)

    @classmethod
    def setUpClass(cls):
        cls.client = nb.app.test_client()

    def test_route_serves_it_without_a_token(self):
        # a browser extension cannot log in, so this one route is deliberately public
        res = self.client.get("/adquit.txt")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/plain", res.headers.get("Content-Type", ""))
        body = res.get_data(as_text=True)
        self.assertTrue(body.startswith("! Title:"))
        self.assertIn("||youtube.com/api/stats/ads$important", body)
        self.assertIn("Cache-Control", res.headers)
        res2 = self.client.get("/adquit.txt?all=1")
        self.assertEqual(res2.status_code, 200)
        count = lambda txt: sum(1 for line in txt.splitlines() if line.startswith("||"))
        self.assertGreaterEqual(count(res2.get_data(as_text=True)), count(body),
                                "the ?all=1 variant must never carry fewer rules")


class TestDependencyGate(unittest.TestCase):
    """`--version` / `--doctor` must answer even on a box where flask/requests/dnslib
    are gone (wiped venv, bare `python3 app.py`), and starting the service must
    explain the problem instead of raising a ModuleNotFoundError traceback."""

    HARNESS = r"""
import sys
BLOCK = {"flask", "requests", "dnslib", "werkzeug", "jinja2"}


class Blocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCK:
            raise ImportError("No module named %r" % (fullname,))
        return None


sys.meta_path.insert(0, Blocker())
sys.argv = ["app.py"] + sys.argv[1:]
src = open(APP, errors="replace").read()
g = {"__name__": "__main__", "__file__": APP}
try:
    exec(compile(src, APP, "exec"), g)
except SystemExit:
    raise
except BaseException as exc:               # a broken import escaping the gate
    sys.stderr.write("UNWANTED EXCEPTION: %r\n" % (exc,))
    sys.exit(99)
"""

    def setUp(self):
        import subprocess
        self.subprocess = subprocess
        self.harness = HOME / "gate_harness.py"
        self.harness.write_text("APP = %r" % str(REPO / "app.py") + chr(10) + self.HARNESS)
        self.env = dict(os.environ, ADQUIT_HOME=str(HOME), ADQUIT_NO_PIP="1")

    def run_gate(self, *args):
        return self.subprocess.run([sys.executable, str(self.harness)] + list(args),
                                   capture_output=True, text=True, timeout=120, env=self.env)

    def test_version_answers_without_deps(self):
        res = self.run_gate("--version")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("19.0", res.stdout)
        self.assertIn("without its Python deps", res.stdout)
        self.assertNotIn("Traceback", res.stderr)

    def test_doctor_diagnoses_without_deps(self):
        res = self.run_gate("--doctor")
        self.assertEqual(res.returncode, 1, res.stderr)
        for needle in ("offline doctor", "flask", "MISSING", "install.sh"):
            self.assertIn(needle, res.stdout, res.stdout[:600])
        self.assertNotIn("Traceback", res.stderr)

    def test_serving_refuses_with_instructions(self):
        res = self.run_gate("--serve")
        self.assertEqual(res.returncode, 3, res.stderr)
        self.assertIn("needs the Python package(s)", res.stderr)
        self.assertIn("pip install", res.stderr)
        self.assertNotIn("Traceback", res.stderr)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2, exit=False, argv=[sys.argv[0]])
    finally:
        shutil.rmtree(HOME, ignore_errors=True)
