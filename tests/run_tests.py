#!/usr/bin/env python3
"""
NetBlock Fortress - offline test suite.

No pytest, no network: `python3 tests/run_tests.py` is all you need.
The suite builds a throwaway ADQUIT_HOME, drops the sample feeds from
tests/fixtures into it as custom lists, imports app.py and asserts that the
micro/macro engine blocks what it must and never touches what it must not.
"""

import ast
import importlib.util
import json
import os
import re
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

    def test_password_change_forgets_the_saved_initial_password(self):
        """The installer keeps the password it generated in a root-only file so `adquit passwd
        --show` can hand it back - and that file is only allowed to exist while it is still the
        password in use. A plaintext secret nobody can revoke is worse than no plaintext secret,
        so both password-setting verbs delete it, and no other verb may.
        """
        f = HOME / "data" / ".dashboard-initial-password"
        old = (nb.CFG["password_hash"], nb.CFG["admin_username"], nb.CFG["web_port"])
        try:
            f.write_text("generated-by-installer\n")
            self.assertEqual(nb.cli(["--passwd", "a-brand-new-secret"]), 0)
            self.assertFalse(f.exists(), "the plaintext outlived the password it described")
            self.assertNotEqual(old[0], nb.CFG["password_hash"])

            f.write_text("generated-by-installer\n")
            self.assertEqual(nb.cli(["--set-auth", "operator", "another-secret"]), 0)
            self.assertFalse(f.exists(), "--set-auth changed the login but left the old secret")
            self.assertEqual(nb.CFG["admin_username"], "operator")

            # the install password is still current here: an unrelated key change must not cost
            # the operator their only way back in
            f.write_text("still-the-current-one\n")
            self.assertEqual(nb.cli(["--set", "web_port", "8123"]), 0)
            self.assertTrue(f.exists(), "an unrelated config change deleted the only way back in")
            self.assertEqual(f.read_text().strip(), "still-the-current-one")
        finally:
            nb.CFG["password_hash"], nb.CFG["admin_username"], nb.CFG["web_port"] = old
            nb.save_config()
            try:
                f.unlink()
            except OSError:
                pass

    def test_login_verbs_reach_the_running_service(self):
        """Saving a new login to disk is only half the job: the running process compares every
        login against the CFG it read at start. Without the reload these two verbs printed
        "[+] password updated" while the *old* password still worked and the new one did not -
        indistinguishable from "my password was not changed". Both must reload, and say which
        of the two situations they are in.
        """
        import contextlib
        import io
        real = nb._reload_live_config
        old = (nb.CFG["password_hash"], nb.CFG["admin_username"])
        try:
            seen = []
            nb._reload_live_config = lambda: (seen.append("reload"), True)[1]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(nb.cli(["--passwd", "a-brand-new-secret"]), 0)
                self.assertEqual(nb.cli(["--set-auth", "operator", "another-secret"]), 0)
            self.assertEqual(len(seen), 2, "a login verb saved without telling the running box")
            self.assertEqual(buf.getvalue().count("live service reloaded it"), 2, buf.getvalue())

            # and when nothing is listening, it must not claim otherwise
            seen = []
            nb._reload_live_config = lambda: (seen.append("reload"), False)[1]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(nb.cli(["--passwd", "yet-another-secret"]), 0)
            self.assertEqual(len(seen), 1)
            self.assertIn("applies on the next start", buf.getvalue(), buf.getvalue())
        finally:
            nb._reload_live_config = real
            nb.CFG["password_hash"], nb.CFG["admin_username"] = old
            nb.save_config()

    def test_placeholder_passwords_are_refused(self):
        """The examples this project prints become real passwords, typed by people following the
        instructions - so they are refused, and `adquit doctor` flags them where they are already in
        use. `install.sh` even falls back to one of them when its generator cannot run."""
        old = nb.CFG["password_hash"]
        try:
            for pw in nb.PLACEHOLDER_PASSWORDS:
                self.assertGreaterEqual(len(pw), 8, "%s is not even long enough to reach the check" % pw)
                self.assertEqual(nb.cli(["--passwd", pw]), 1, "%s should not be accepted" % pw)
                self.assertEqual(nb.CFG["password_hash"], old, "%s was written anyway" % pw)
            self.assertEqual(nb.cli(["--set-auth", "admin", "change-me-please"]), 1)
            self.assertEqual(nb.CFG["admin_username"], old and nb.CFG["admin_username"])
            self.assertEqual(nb.cli(["--passwd", "a-choice-of-mine"]), 0)
            self.assertNotEqual(nb.CFG["password_hash"], old)
        finally:
            nb.CFG["password_hash"] = old
            nb.save_config()

    def test_doctor_flags_placeholders_not_just_the_default(self):
        import inspect
        src = inspect.getsource(nb.cmd_doctor)
        self.assertIn("PLACEHOLDER_PASSWORDS", src,
                      "the shipped default is checked but the documented examples are not")

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


class TestDomainIntel(unittest.TestCase):
    """`adquit intel` with RDAP stubbed, so the success path is covered even where the
    network is not (the CI-only TypeError this test now catches was invisible offline)."""

    class Resp:
        status_code = 200

        @staticmethod
        def json():
            return {
                "events": [{"eventAction": "registration", "eventDate": "2026-09-25T00:00:00Z"},
                           {"eventAction": "expiration", "eventDate": "2027-09-25T00:00:00Z"}],
                "entities": [{"roles": ["registrar"],
                              "vcardArray": ["vcard", [["fn", {}, "text", "Sneaky Registrar LLC"]]]}],
                "status": ["client transfer prohibited"],
                "nameservers": [{"ldhName": "ns1.scam-ads.net"}, {"ldhName": "ns2.scam-ads.net"}],
            }

    def setUp(self):
        self._real_get = nb.requests.get

    def tearDown(self):
        nb.requests.get = self._real_get

    def test_rdap_facts_are_parsed_and_cached(self):
        nb.requests.get = lambda *a, **k: self.Resp()
        rep = nb.intel_report("brand-new-scam.biz")
        self.assertEqual("brand-new-scam.biz", rep["zone"])
        self.assertEqual("Sneaky Registrar LLC", rep["rdap"]["registrar"])
        self.assertIn("client transfer prohibited", rep["rdap"]["status"])
        self.assertEqual(["ns1.scam-ads.net", "ns2.scam-ads.net"], rep["rdap"]["nameservers"])
        self.assertIsNotNone(rep["rdap"].get("age_days"))
        self.assertTrue(any("freshly" in h or "days old" in h for h in rep["hints"]), rep["hints"])
        # a brand-new scam domain is on no list yet - that is the whole point of intel:
        self.assertEqual("allow", rep["action"])
        self.assertTrue(any("adquit block brand-new-scam.biz" in h for h in rep["hints"]), rep["hints"])
        # cached on the second call (no HTTP) - a TTLCache.set() arity bug shows up here
        nb.requests.get = lambda *a, **k: self.fail("RDAP was queried twice for one zone")
        again = nb.intel_report("brand-new-scam.biz")
        self.assertEqual("Sneaky Registrar LLC", again["rdap"]["registrar"])

    def test_rdap_failure_is_not_fatal(self):
        def boom(*a, **k):
            raise OSError("no route to host")
        nb.requests.get = boom
        rep = nb.intel_report("totally-unknown-zone-xyz.net")
        self.assertIn("error", rep["rdap"])
        self.assertTrue(any("adquit block" in h for h in rep["hints"]))


class TestBootFastPath(unittest.TestCase):
    """A box with 5M rules must not re-read every feed on every start.

    Real-world symptom: `adquit update` rebuilt 5.1M rules, then `systemctl start`
    spent tens of seconds rebuilding them *again* before the dashboard could bind -
    long enough that the 15-second health probe declared a perfectly healthy service
    dead, stopped it, and restarted the load from zero. Boot must trust a fresh
    cache, fold in the operator's own lines without a rebuild, and say how long it took.
    """

    TABLES = ("BLOCKED", "WILDCARDS", "UNBREAK", "GRAVITY_CUSTOM", "CUSTOM_WHITELIST_SET")

    def setUp(self):
        self.saved = {n: getattr(nb, n) for n in self.TABLES}
        self.saved_counts = (dict(nb.VECTOR_COUNTS), dict(nb.CAT_COUNTS))
        for p in (nb.GRAVITY_CACHE, nb.META_DIR / "gravity.custom"):
            p.unlink(missing_ok=True)
        nb.CUSTOM_BLOCK.unlink(missing_ok=True)
        nb.BLOCKED = {"doubleclick.net": ("ads", "banner", "fx_plain"),
                      "track.example": ("trackers", "pixel", "fx_plain")}
        nb.WILDCARDS = {"network.example": ("ads", "banner", "fx_wildcard")}
        nb.UNBREAK = set()
        nb.VECTOR_COUNTS.clear(); nb.CAT_COUNTS.clear()
        nb.VECTOR_COUNTS.update({"banner": 1, "pixel": 1})
        nb.CAT_COUNTS.update({"ads": 1, "trackers": 1})

    def tearDown(self):
        for n, v in self.saved.items():
            setattr(nb, n, v)
        nb.VECTOR_COUNTS.clear(); nb.CAT_COUNTS.clear()
        nb.VECTOR_COUNTS.update(self.saved_counts[0]); nb.CAT_COUNTS.update(self.saved_counts[1])
        for p in (nb.GRAVITY_CACHE, nb.META_DIR / "gravity.custom"):
            p.unlink(missing_ok=True)
        nb.CUSTOM_BLOCK.unlink(missing_ok=True)

    def test_cache_round_trip_carries_the_tallies(self):
        nb.save_gravity_cache(custom=set())
        nb.BLOCKED, nb.WILDCARDS = {}, {}
        nb.VECTOR_COUNTS.clear(); nb.CAT_COUNTS.clear()
        self.assertTrue(nb.load_gravity_cache(), "cache should load from a clean state")
        self.assertEqual(len(nb.BLOCKED), 2)
        # restored without scanning every rule: the counts came from the cache itself
        self.assertEqual(nb.VECTOR_COUNTS.get("pixel"), 1)
        self.assertEqual(nb.CAT_COUNTS.get("trackers"), 1)

    def test_custom_lines_are_folded_in_without_a_rebuild(self):
        nb.save_gravity_cache(custom={"old.example"})
        nb.CUSTOM_BLOCK.write_text("old.example\nadded-while-down.net\n")
        self.assertTrue(nb.load_gravity_cache())
        blocked_now, _ = nb.load_custom_lists()
        self.assertTrue(nb.apply_custom_overrides(blocked_now),
                        "a 2-line custom file must not need a full rebuild")
        self.assertIn("added-while-down.net", nb.BLOCKED)
        self.assertEqual(nb.BLOCKED["added-while-down.net"][0], "custom")
        self.assertNotIn("old.example", nb.BLOCKED, "removed while down must stay removed")
        nb._sync_legacy_views(nb.load_custom_lists()[0])
        self.assertIn("added-while-down.net", nb.CUSTOM_BLOCKED,
                      "the dashboard's custom tally must follow the fold-in")
        # a multi-label entry also gets its wildcard, exactly as the rebuild would
        nb.CUSTOM_BLOCK.write_text("sub.zone.example\n")
        self.assertTrue(nb.apply_custom_overrides(nb.load_custom_lists()[0]))
        self.assertIn("sub.zone.example", nb.WILDCARDS)

    def test_cache_that_cannot_be_verified_forces_a_rebuild(self):
        nb.save_gravity_cache(custom={"a.example"})
        (nb.META_DIR / "gravity.custom").unlink()      # cache from an older build
        self.assertTrue(nb.load_gravity_cache())
        self.assertFalse(nb.apply_custom_overrides(set()),
                         "no custom tally -> the caller must rebuild, not guess")

    def test_boot_does_not_rebuild_a_warm_cache(self):
        src = (REPO / "app.py").read_text()
        self.assertIn("cache_ok and not apply_custom_overrides(custom_blocked)", src,
                      "boot lost its fast path")
        self.assertNotIn("rebuild_master_blocklist(persist=False)\n    _sync_legacy_views", src,
                        "boot rebuilds unconditionally again")
        self.assertIn("ready in %.1fs", src, "boot must report how long it took")
        self.assertIn("no usable cache yet", src, "a cold build must say so while it works")

    def test_legacy_views_are_deferred_but_live(self):
        nb._sync_legacy_views()
        self.assertIsInstance(nb.BLOCKED_DOMAINS, nb._LazyView)
        self.assertIsNone(nb.BLOCKED_DOMAINS._obj, "must not be built at boot")
        self.assertEqual(len(nb.BLOCKED_DOMAINS), 3)     # 2 exact + 1 wildcard zone
        self.assertIsNotNone(nb.BLOCKED_DOMAINS._obj, "materialises on first use")
        nb._sync_legacy_views()
        nb.BLOCKED["fresh.example"] = ("ads", "banner", "test")
        self.assertIn("fresh.example", nb.BLOCKED_DOMAINS, "the view must follow the tables")
        self.assertEqual(nb.DOMAIN_CATEGORIES["doubleclick.net"], "ads")

    def test_source_has_no_invalid_escape_sequences(self):
        """`"\:"` in a CSS selector was fine until Python 3.12 made it a SyntaxWarning and
        it becomes a SyntaxError later - a single backslash can brick every start."""
        import warnings
        src = (REPO / "app.py").read_text()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compile(src, "app.py", "exec")
        bad = [str(w.message) for w in caught
               if issubclass(w.category, (SyntaxWarning, DeprecationWarning))]
        self.assertEqual(bad, [], "invalid escape sequence(s): %s" % bad[:3])
        self.assertIn(r"[data-testid\:cellInnerDiv]", src,
                      "the uBlock CSS rule must keep its escaped colon")

    def test_module_globals_are_declared(self):
        """A function that assigns a module name without `global` writes a local instead -
        which is how the custom tally silently stayed None and every boot rebuilt 5M
        rules. Same class of bug, once is enough."""
        import ast

        def stores(node):
            """Names this function binds directly - ignoring comprehension/lambda/nested
            scopes, where a name is legitimately local."""
            out = set()

            def visit(n):
                if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
                                  ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
                    return
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    out.add(n.id)
                for _field, child in ast.iter_fields(n):
                    if isinstance(child, list):
                        for c in child:
                            if isinstance(c, ast.AST):
                                visit(c)
                    elif isinstance(child, ast.AST):
                        visit(child)
            visit(node)
            return out

        tree = ast.parse((REPO / "app.py").read_text())
        mod_names = set()
        for stmt in tree.body:
            if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for tgt in targets:
                    mod_names |= {t.id for t in ast.walk(tgt) if isinstance(t, ast.Name)}
        offenders = []
        for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            declared = {g for stmt in ast.walk(fn) if isinstance(stmt, ast.Global)
                        for g in stmt.names}
            args = list(fn.args.args) + list(fn.args.kwonlyargs) + list(fn.args.posonlyargs)
            params = {a.arg for a in args}
            for extra in (fn.args.vararg, fn.args.kwarg):
                if extra:
                    params.add(extra.arg)
            leaked = (stores(fn) & mod_names) - declared - params
            if leaked:
                offenders.append("%s(): %s" % (fn.name, sorted(leaked)))
        self.assertEqual(offenders, [], "module globals assigned without `global`: %s"
                         % offenders[:5])


class TestLanSelfHosting(unittest.TestCase):
    """`adquit site add media.lan --port 8096` must be answered by the fortress itself.

    The failure mode this exists to prevent: a user hosts a site, points every device
    at the fortress for DNS, and the resolver answers NXDOMAIN for the whole `.lan`
    suffix (its anti-leak guard) - so the site is unreachable *because of* the blocker.
    Published names therefore resolve before the engine runs, and names under a LAN
    zone are forwarded to the router, never to a public resolver.
    """

    def setUp(self):
        self.cfg = dict(nb.CFG)
        nb.CFG.update({"local_records": {}, "lan_zones": {}, "answer_fortress_names": True,
                       "sinkhole_ip": "192.168.1.50"})

    def tearDown(self):
        nb.CFG.clear()
        nb.CFG.update(self.cfg)

    # --- lookup helpers -----------------------------------------------------
    def test_record_lookup_forms(self):
        nb.CFG["local_records"] = {"media.lan": {"port": 8096}, "nas.lan": "192.168.1.40",
                                   "@app.lan": {"port": 9000}}
        self.assertEqual(nb.local_record_for("media.lan")["port"], 8096)
        self.assertEqual(nb.local_record_for("nas.lan"), {"ip": "192.168.1.40"},
                         "a bare string is a valid shorthand for an address")
        self.assertEqual(nb.local_record_for("app.lan")["port"], 9000,
                         "@ in a zone file must resolve as the bare host too")
        self.assertIsNone(nb.local_record_for("whoever.lan"))
        nb.CFG["local_records"] = "nonsense"
        self.assertIsNone(nb.local_record_for("media.lan"), "a corrupt value must not raise")

    def test_published_name_defaults_to_this_box(self):
        nb.CFG["local_records"] = {"media.lan": {"port": 8096}}
        self.assertEqual(nb.local_record_ip(nb.local_record_for("media.lan")), "192.168.1.50")
        nb.CFG["local_records"]["nas.lan"] = {"ip": "192.168.1.40"}
        self.assertEqual(nb.local_record_ip(nb.local_record_for("nas.lan")), "192.168.1.40")

    def test_zone_lookup_prefers_the_longest_suffix(self):
        nb.CFG["lan_zones"] = {"lan": "192.168.1.1", "home.lan": "192.168.1.1"}
        self.assertEqual(nb.lan_zone_for("nas.home.lan")[0], "home.lan")
        self.assertEqual(nb.lan_zone_for("printer.lan")[0], "lan")
        self.assertIsNone(nb.lan_zone_for("example.com"))
        nb.CFG["lan_zones"] = []
        self.assertIsNone(nb.lan_zone_for("printer.lan"))

    def test_aaaa_stays_empty_unless_configured(self):
        from dnslib import DNSRecord, QTYPE
        q = DNSRecord.question("media.lan", "A")
        q.qtype = QTYPE.A
        self.assertEqual(len(nb.build_local_reply(q, q.q, "192.168.1.50").rr), 1)
        q6 = DNSRecord.question("media.lan", "AAAA")
        self.assertEqual(len(nb.build_local_reply(q6, q6.q, "192.168.1.50").rr), 0,
                         "no IPv6 configured must NOT mean 'dial ::'")
        self.assertEqual(len(nb.build_local_reply(q6, q6.q, "192.168.1.50", ip6="fe80::1").rr), 1)

    # --- the resolver path --------------------------------------------------
    def _ask(self, name, qtype="A"):
        from dnslib import DNSRecord
        req = DNSRecord.question(name, qtype)
        out = {}

        def send(data, addr):
            out["packet"] = data
            out["addr"] = addr
        nb.handle_dns_request(req.pack(), ("10.0.0.5", 5123), send)
        self.assertIn("packet", out, "no reply for %s" % name)
        rep = DNSRecord.parse(out["packet"])
        return req.header.id, rep

    def test_published_name_is_answered_locally(self):
        nb.CFG["local_records"] = {"media.lan": {"port": 8096}}
        rid, rep = self._ask("media.lan")
        self.assertEqual(rep.header.id, rid, "the question id must come back intact")
        self.assertEqual([str(a.rdata) for a in rep.rr], ["192.168.1.50"])
        self.assertEqual(rep.header.rcode, 0)

    def test_fortress_own_names_resolve_for_plain_unicast_clients(self):
        _rid, rep = self._ask("adquit.lan")
        self.assertEqual([str(a.rdata) for a in rep.rr], ["192.168.1.50"],
                         "the URL `adquit lan` prints has to actually resolve")

    def test_unmanaged_lan_name_never_reaches_a_public_resolver(self):
        def no_ever(*a, **k):
            raise AssertionError("LAN name leaked to the public upstream")
        up, nb.resolve_upstream = nb.resolve_upstream, no_ever
        try:
            _rid, rep = self._ask("printer.lan")
        finally:
            nb.resolve_upstream = up
        self.assertEqual(rep.header.rcode, nb.RCODE.NXDOMAIN)

    def test_zone_names_are_forwarded_to_the_router_not_the_engine(self):
        from dnslib import A, DNSRecord, QTYPE, RR
        inner = DNSRecord.question("printer.lan", "A").reply()
        inner.add_answer(RR("printer.lan", QTYPE.A, rdata=A("192.168.1.77"), ttl=30))
        seen = []
        up, ln, nb.resolve_upstream = nb.resolve_upstream, nb.resolve_lan_name, None
        nb.resolve_upstream = lambda *a, **k: self.fail("public upstream consulted for a LAN zone")
        nb.resolve_lan_name = lambda n, t, s: (seen.append((n, t, s)) or inner)
        try:
            nb.CFG["lan_zones"] = {"lan": "192.168.1.1"}
            rid, rep = self._ask("printer.lan")
        finally:
            nb.resolve_upstream, nb.resolve_lan_name = up, ln
        self.assertEqual(seen, [("printer.lan", "A", "192.168.1.1")])
        self.assertEqual([str(a.rdata) for a in rep.rr], ["192.168.1.77"])
        self.assertEqual(rep.header.id, rid, "reply must carry our question, not the router's")

    def test_zone_with_a_dead_router_answers_something(self):
        # a black hole: no answer, no exception, and no leak to the public resolver
        nb.CFG["lan_zones"] = {"lan": "127.0.0.1:1"}
        up, nb.resolve_upstream = nb.resolve_upstream, (
            lambda *a, **k: self.fail("public upstream consulted for a LAN zone"))
        try:
            _rid, rep = self._ask("printer.lan")
        finally:
            nb.resolve_upstream = up
        self.assertIn(rep.header.rcode, (nb.RCODE.NXDOMAIN, nb.RCODE.SERVFAIL))

    def test_config_set_accepts_a_json_object(self):
        cfg_path = nb.CONFIG_FILE
        before = cfg_path.read_text() if cfg_path.exists() else None
        try:
            rc = nb.cli(["--set", "local_records", '{"media.lan": {"port": 8096}}'])
            self.assertEqual(rc, 0)
            self.assertEqual(nb.CFG["local_records"], {"media.lan": {"port": 8096}})
            rc = nb.cli(["--set", "local_records", "not json"])
            self.assertEqual(rc, 1, "garbage must be refused, not stored")
        finally:
            nb.CFG["local_records"] = {}
            if before is not None:
                cfg_path.write_text(before)
            else:
                cfg_path.unlink(missing_ok=True)


class TestProxyAware(unittest.TestCase):
    """Behind a reverse proxy on the same box, `request.remote_addr` must still be the
    device that asked - and a device must not be able to claim to be someone else."""

    def _env(self, peer, script_name=None, **headers):
        env = {"REMOTE_ADDR": peer, "wsgi.url_scheme": "http", "SERVER_NAME": "adquit.lan",
               "SERVER_PORT": "80", "REQUEST_METHOD": "GET", "PATH_INFO": "/api/health"}
        if script_name is not None:
            env["SCRIPT_NAME"] = script_name
        for k, v in headers.items():
            env["HTTP_" + k.upper().replace("-", "_")] = v
        seen = {}

        def wsgi(e, sr):
            seen["env"] = e
            return [b"ok"]
        mw = nb.ProxyAware(wsgi)
        mw(env, lambda *a: None)
        return seen["env"]

    def test_loopback_proxy_may_name_the_real_client(self):
        env = self._env("127.0.0.1", **{"X-Forwarded-For": "203.0.113.7, 10.0.0.1",
                                        "X-Forwarded-Proto": "https"})
        self.assertEqual(env["REMOTE_ADDR"], "203.0.113.7")
        self.assertEqual(env["wsgi.url_scheme"], "https")

    def test_a_lan_client_cannot_impersonate_one(self):
        env = self._env("192.168.1.80", **{"X-Forwarded-For": "8.8.8.8"})
        self.assertEqual(env["REMOTE_ADDR"], "192.168.1.80", "spoofed header must be ignored")

    def test_forwarded_prefix_becomes_script_name(self):
        env = self._env("::1", **{"X-Forwarded-Prefix": "/adquit/"})
        self.assertEqual(env["SCRIPT_NAME"], "/adquit")
        env = self._env("::1", script_name="/already", **{"X-Forwarded-Prefix": "/x"})
        self.assertEqual(env["SCRIPT_NAME"], "/already", "an existing mount wins")

    def test_off_switch_is_respected(self):
        cfg = dict(nb.CFG)
        try:
            nb.CFG["trust_proxy"] = False
            env = self._env("127.0.0.1", **{"X-Forwarded-For": "203.0.113.7"})
            self.assertEqual(env["REMOTE_ADDR"], "127.0.0.1")
        finally:
            nb.CFG.clear(); nb.CFG.update(cfg)


class TestStartPage(unittest.TestCase):
    """`adquit site add` should be enough to get a tile on a LAN start page.

    The registry the resolver reads is the registry the page reads, so there is no second
    place to keep in sync - and the page is unauthenticated on purpose (it links to things
    every device on this network may already open), which is only safe if it leaks nothing
    but names, and escapes them.
    """

    def setUp(self):
        self.cfg = dict(nb.CFG)
        nb.CFG.update({"portal_enabled": True, "portal_port": 8082,
                       "portal_title": "Home on the NAS", "portal_note": "",
                       "local_records": {}, "lan_zones": {}, "answer_fortress_names": True,
                       "sinkhole_mode": "zeroip", "sinkhole_ip": "192.0.2.50"})

    def tearDown(self):
        nb.CFG.clear()
        nb.CFG.update(self.cfg)

    def test_names_are_answered_only_while_the_page_is_on(self):
        self.assertIn("home.lan", nb.portal_names())
        self.assertIn("home.local", nb.portal_names())
        self.assertIn("home.lan", nb.fortress_names())
        nb.CFG["portal_enabled"] = False
        self.assertEqual(nb.portal_names(), [])
        self.assertNotIn("home.lan", nb.fortress_names())

    def test_tile_links_follow_how_the_site_is_served(self):
        nb.CFG["local_records"] = {
            "media.lan": {"port": 8096},                      # proxied -> the name, no port
            "nas.lan": {"ip": "192.0.2.9", "proxy": False},    # another box, DNS only
            "old.lan": {"ip": "192.0.2.9", "port": 8081, "proxy": False},  # other box, real port
        }
        by = {e["name"]: e for e in nb.portal_entries()}
        self.assertEqual(by["media.lan"]["url"], "http://media.lan/")
        self.assertEqual(by["nas.lan"]["url"], "http://192.0.2.9/")
        self.assertEqual(by["old.lan"]["url"], "http://192.0.2.9:8081/")
        self.assertEqual(nb.portal_entries()[-1]["kind"], "fortress",
                         "the dashboard is the last tile, not a site you publish")

    def test_free_text_is_escaped_and_nothing_secret_shows_up(self):
        nb.CFG["local_records"] = {"x.lan": {"port": 1, "note": "<script>alert(1)</script>"}}
        html = nb.render_portal_html()
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Home on the NAS", html)
        for secret in ("api_token", "password_hash"):
            self.assertNotIn(secret, html)

    def test_the_empty_page_tells_you_the_command(self):
        html = nb.render_portal_html()
        self.assertIn("Nothing published yet", html)
        self.assertIn("adquit site add", html)

    def test_the_listener_serves_the_page_and_json(self):
        import json
        import urllib.error
        import urllib.request
        nb.CFG["local_records"] = {"media.lan": {"port": 8096}}
        # an ephemeral port: whatever else this box happens to be running must not decide
        import socket as _sock
        probe = _sock.socket()
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
        probe.close()
        httpd = nb.start_portal_server(port=free)
        self.assertIsNotNone(httpd, "the portal listener must come up")
        base = "http://127.0.0.1:%s" % httpd.server_address[1]
        try:
            with urllib.request.urlopen(base + "/", timeout=5) as r:
                body = r.read().decode()
                self.assertEqual(r.headers.get("X-Adquit"), "portal")
            self.assertIn("http://media.lan/", body)
            with urllib.request.urlopen(base + "/portal.json", timeout=5) as r:
                data = json.loads(r.read().decode())
            self.assertEqual([e["name"] for e in data["entries"]][:1], ["media.lan"])
            # an unknown path lands on the page, and nothing is writable here
            req = urllib.request.Request(base + "/whatever", data=b"hi", method="POST")
            try:
                urllib.request.urlopen(req, timeout=5)
                self.fail("POST must be refused")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 405)
            with urllib.request.urlopen(base + "/photos", timeout=5) as r:
                self.assertEqual(r.status, 200)     # followed the 302 to /
                self.assertIn("<!doctype html>", r.read().decode())
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_disabled_and_busy_ports_do_not_break_the_boot(self):
        nb.CFG["portal_enabled"] = False
        self.assertIsNone(nb.start_portal_server())
        nb.CFG["portal_enabled"] = True
        nb.CFG["portal_port"] = 0
        self.assertIsNone(nb.start_portal_server())
        nb.CFG["portal_port"] = 1
        self.assertIsNone(nb.start_portal_server(), "no privilege: log it, do not raise")


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
        self.assertIn(nb.VERSION, res.stdout)
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


def _mentions(name, text):
    """Whole-word only: `CFG` must not match inside `CFGX`, or a key inside a comment about it."""
    return re.search(r"\b%s\b" % re.escape(name), text) is not None


def _kept(line, marker):
    """An exception that has to be earned: the marker sits on the definition's own line."""
    return marker in line


class TestHygiene(unittest.TestCase):
    """Nothing in app.py may be unreachable, and every exposed key must be reachable by hand.

    A five-thousand-line engine accumulates spare parts: a constant defined and never read, a
    compatibility shim nobody calls any more, a key in DEFAULT_CONFIG nothing consults. Each one
    is a second, wrong opinion about how the engine works, paid for by the next reader - so v19.3
    deleted `CORE_SEED_DOMAINS`, `ENGINE_STATS`, `SYNC_PATH_HOSTS`, `CUSTOM_PROTECTED`,
    `SAFE_SEARCH_TARGETS` (the live table is `SAFE_SEARCH_HOSTS`) and the `audit_threat` shim,
    and these tests are what keeps them from creeping back. They read the source instead of
    running it, so they cost milliseconds and fail with the line to delete. An exception has to
    be earned: `# hygiene: keep` on the definition's own line, with a reason.
    """

    KEEP = "# hygiene: keep"
    SURFACE = ("bin/adquit", "install.sh", "uninstall.sh", "README.md", "CHANGELOG.md",
               "Dockerfile", "Makefile", "docker-compose.yml", ".github/workflows/ci.yml",
               ".github/workflows/release.yml", "tests/run_tests.py", "tests/test_cli.sh",
               "tests/doc_contract.sh")

    def _surface(self, exclude=None):
        """Everything allowed to reach into the engine: the CLI, the installers, the docs, the
        tests. A name used only by a test is used - `tests/` is how an operator's shell and this
        suite drive the module, and the CLI reaches config keys by string (`--set`, `--get`).

        `exclude` matters on the shell side: bin/adquit is in this list, so without it a
        function defined nowhere-else would look 'used by the docs' by its own definition.
        """
        parts = []
        for rel in self.SURFACE:
            if rel == exclude:
                continue
            path = REPO / rel
            if path.exists():
                parts.append(path.read_text(encoding="utf-8", errors="ignore"))
        return "\n".join(parts)

    def _sources(self):
        src = (REPO / "app.py").read_text(encoding="utf-8")
        return src, self._surface(exclude="app.py")

    @staticmethod
    def _module_items(tree):
        """(name, first, last, must_keep) for every module-level definition and constant."""
        items = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                items.append((node.name, node.lineno, node.end_lineno, bool(node.decorator_list)))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        items.append((target.id, node.lineno, node.end_lineno, False))
        return items

    def test_no_unreachable_module_level_names(self):
        src, others = self._sources()
        lines = src.splitlines()
        tree = ast.parse(src)
        items = self._module_items(tree)

        inside = [False] * (len(lines) + 1)
        for _, first, last, _dec in items:
            for i in range(first - 1, min(last, len(lines))):
                inside[i] = True
        outside = "\n".join("" if inside[i] else line for i, line in enumerate(lines))

        by_name = {}
        for name, first, last, dec in items:
            by_name.setdefault(name, (first, last, dec))

        live = set()
        for name, first, last, dec in items:
            if _kept(lines[first - 1], self.KEEP):
                continue
            if dec:
                live.add(name)          # reached through a URL, not through a name
            elif _mentions(name, outside) or _mentions(name, others):
                live.add(name)
        for _ in range(20):             # a name is live if a live body reaches it
            grew = False
            for name, first, last, dec in items:
                if name in live or _kept(lines[first - 1], self.KEEP):
                    continue
                for lname in list(live):
                    lfirst, llast, _ = by_name[lname]
                    if _mentions(name, "\n".join(lines[lfirst - 1:llast])):
                        live.add(name)
                        grew = True
                        break
            if not grew:
                break

        dead = ["%s (line %d)" % (name, first)
                for name, first, last, dec in items
                if name not in live and not _kept(lines[first - 1], self.KEEP)]
        self.assertFalse(
            dead,
            "unreachable in app.py: %s - delete it, or write why it must stay on its own line "
            "(%s)" % ("; ".join(dead), self.KEEP))

    SHELL_SOURCES = ("bin/adquit", "install.sh", "uninstall.sh", "tests/doc_contract.sh")

    def test_no_unreachable_cli_functions(self):
        """The same rule on the shell side, because the CLI is where an orphan hides best.

        bin/adquit dispatches from one long case block, so a function whose verb was renamed or
        dropped keeps looking 'used' to a reader forever. Shell has no compiler, so the check is
        here: every top-level `name() {` must be reachable from module level (the dispatcher, a
        trap, a subshell in the file) or from another reachable function, or be named by the
        tests, the docs or the other scripts. `# hygiene: keep` on the definition excuses one.
        """
        for rel in self.SHELL_SOURCES:
            external = self._surface(exclude=rel)
            path = REPO / rel
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
            spans = {}
            for match in re.finditer(r"^([a-z_][a-z0-9_]*)\s*\(\)\s*\{", text, re.M):
                name = match.group(1)
                if name in spans:
                    continue
                first = text[:match.start()].count("\n") + 1
                end = len(lines)
                for i in range(first, len(lines)):
                    if lines[i] == "}":
                        end = i + 1
                        break
                spans[name] = (first, end)
            if not spans:
                continue

            inside = [False] * (len(lines) + 2)
            for first, end in spans.values():
                for i in range(first - 1, end):
                    inside[i] = True
            outside = "\n".join("" if inside[i] else line for i, line in enumerate(lines))
            body_of = {n: "\n".join(lines[a - 1:b]) for n, (a, b) in spans.items()}
            kept = {n for n, (a, _b) in spans.items() if _kept(lines[a - 1], self.KEEP)}

            live = {n for n in spans
                    if _mentions(n, outside) or _mentions(n, external) or n in kept}
            for _ in range(20):
                grew = False
                for n in spans:
                    if n in live or n in kept:
                        continue
                    if any(src in live and _mentions(n, body_of[src]) for src in spans):
                        live.add(n)
                        grew = True
                if not grew:
                    break
            dead = sorted(n for n in spans if n not in live)
            self.assertFalse(
                dead,
                "%s defines functions nothing calls: %s - delete them, or put '%s' and a "
                "reason on the definition's own line" % (rel, ", ".join(dead), self.KEEP))

    def test_readme_counts_the_suite_honestly(self):
        """The suite's size is a claim the README makes; a stale number means nobody reads it."""
        collected = unittest.TestLoader().loadTestsFromModule(
            sys.modules[__name__]).countTestCases()
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        claims = re.findall(r"(\d+)[- ](?:test offline suite|engine/)", readme)
        self.assertTrue(claims, "README no longer states the suite size - say it again, or delete this test")
        wrong = [c for c in claims if int(c) != collected]
        self.assertFalse(
            wrong,
            "README advertises %s tests; this file collects %d - update the prose (or the prose "
            "was describing a different suite all along)" % (", ".join(wrong), collected))

    def test_no_unused_imports(self):
        src, _others = self._sources()
        lines = src.splitlines()
        tree = ast.parse(src)
        bound = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound.append((alias.asname or alias.name.split(".")[0], node.lineno))
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name != "*":
                        bound.append((alias.asname or alias.name, node.lineno))
        import_lines = {ln for _n, ln in bound}
        rest = "\n".join("" if (i + 1) in import_lines else line for i, line in enumerate(lines))
        # `app.py` is imported by the suite as `nb`, so a name re-exported for callers is used
        unused = sorted({name for name, ln in bound
                         if not _kept(lines[ln - 1], "# hygiene: keep") and not _mentions(name, rest)})
        self.assertFalse(unused, "imported and never used: %s" % ", ".join(unused))

    def test_every_default_config_key_is_read(self):
        """A key nobody reads is a promise the engine does not keep."""
        src, others = self._sources()
        tree = ast.parse(src)
        keys = []
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "DEFAULT_CONFIG" for t in node.targets):
                for k in node.value.keys:
                    if isinstance(k, ast.Str):
                        keys.append(k.s)
                break
        self.assertTrue(keys, "DEFAULT_CONFIG not found - the test has to know where the keys live")
        body = src + "\n" + others
        unread = [k for k in keys if len(re.findall(r'["\']%s["\']' % re.escape(k), body)) < 2]
        self.assertFalse(
            unread,
            "config keys nothing reads (remove them, or wire them up): %s" % ", ".join(unread))



    def test_every_config_writing_cli_verb_reaches_the_service(self):
        """A verb that saves and does not notify is the password bug in waiting.

        `--passwd` wrote config.json, said "[+] password updated", and the running dashboard kept
        comparing logins against the hash it read at start - so the operator's new password did not
        work, the old one still did, and nothing on screen was technically a lie. `--block` never
        had that problem because it calls `_notify_service()`. Rather than trust the next verb to
        remember, every gate in `cli()` that touches CFG or save_config() must also reach the
        service (or restart it) before it returns.
        """
        src = (REPO / "app.py").read_text(errors="replace")
        cli = src[src.index("def cli(argv):"):]
        gates = re.split(r"\n    if cmd in \((.*?)\):", cli)
        checked = []
        for i in range(1, len(gates), 2):
            verb = gates[i].strip(' "\'' ).strip(",").strip('"').strip("'")
            body = gates[i + 1].split("\n    if cmd in (")[0]
            if verb in ("--serve", "--daemon"):
                continue
            writes = ("save_config()" in body or "atomic_write(" in body
                      or re.search(r"CFG\[[^\]]+\] *[^=]*=", body))
            if not writes:
                continue
            checked.append(verb)
            reaches = ("_notify_service" in body or "_reload_live_config" in body
                       or "_live_suffix" in body or "/api/reload" in body)
            self.assertTrue(
                reaches,
                "%s changes config but never tells the running service; add _notify_service() "
                "(rules) or _live_suffix() (config only, no recompilation)" % verb)
        # a floor is not enough: if the parse drifted and these two stopped being seen, the guard
        # would pass while the login bug walked back in
        self.assertTrue(all(v in checked for v in ("--passwd", "--set-auth")),
                        "the login verbs are not among the gates this checked: %s" % checked)
        self.assertGreaterEqual(len(checked), 3,
                                "only %s gates parsed - the test stopped seeing the CLI" % checked)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2, exit=False, argv=[sys.argv[0]])
    finally:
        shutil.rmtree(HOME, ignore_errors=True)
