import unittest

from adblock_rules import (
    domain_rule_matches,
    domain_suffixes,
    find_matching_rule,
    normalize_domain,
    parse_blocklist_line,
    parse_blocklist_text,
)


class DomainNormalizationTests(unittest.TestCase):
    def test_idn_and_root_dot_are_normalized(self):
        self.assertEqual(normalize_domain("BÜCHER.example."), "xn--bcher-kva.example")

    def test_rejects_invalid_or_non_domain_inputs(self):
        for value in (
            "", "localhost", "example.com/path", "example.com:443", "*.com",
            "0.0.0.0", "-bad.example", "bad-.example", "a..example", "*.example.com*",
        ):
            with self.subTest(value=value):
                self.assertIsNone(normalize_domain(value))

    def test_local_suffixes_are_skipped_for_feeds_but_allowed_for_explicit_rules(self):
        self.assertIsNone(normalize_domain("printer.local"))
        self.assertEqual(normalize_domain("printer.local", allow_local=True), "printer.local")

    def test_suffixes_are_boundary_aware_and_include_service_names(self):
        self.assertEqual(
            domain_suffixes("_dmarc.mail.example.com."),
            ("_dmarc.mail.example.com", "mail.example.com", "example.com"),
        )
        self.assertFalse(domain_rule_matches("notexample.com", "example.com"))
        self.assertTrue(domain_rule_matches("ads.example.com", "example.com"))

    def test_wildcard_rule_only_matches_subdomains(self):
        self.assertFalse(domain_rule_matches("example.com", "*.example.com"))
        self.assertTrue(domain_rule_matches("ads.example.com", "*.example.com"))
        self.assertEqual(find_matching_rule("a.ads.example.com", {"*.example.com"}), "*.example.com")


class BlocklistParsingTests(unittest.TestCase):
    def test_hosts_lists_only_accept_sinkhole_mappings(self):
        text = """
# comment
0.0.0.0 ads.example.com tracker.example.net localhost
127.0.0.1 metrics.example.org # generated
::1 pixel.example.io
192.0.2.1 should-not-be-blocked.example
0.0.0.0 203.0.113.10
"""
        self.assertEqual(
            parse_blocklist_text(text),
            {"ads.example.com", "tracker.example.net", "metrics.example.org", "pixel.example.io"},
        )

    def test_plain_domains_and_wildcard_domains(self):
        self.assertEqual(
            parse_blocklist_text("ads.example.com\n*.tracker.example.com\n# ignored\n"),
            {"ads.example.com", "*.tracker.example.com"},
        )

    def test_adblock_plus_host_rules_are_supported_but_paths_and_exceptions_are_not(self):
        text = """
||ads.example.com^
||sub.example.net^$script,third-party
||*.tracking.example.org^
||path.example.com/banner.js^
@@||allow.example.com^
example.com##.ad-banner
||conditional.example.com^$domain=publisher.example
"""
        self.assertEqual(
            parse_blocklist_text(text),
            {"ads.example.com", "sub.example.net", "*.tracking.example.org"},
        )

    def test_dnsmasq_only_accepts_blocking_address_rules(self):
        text = """
address=/ads.example.com/0.0.0.0
address=/nxdomain.example/
address=/mapped.example/192.0.2.1
server=/forwarded.example/192.0.2.53
server=/BÜCHER.example/
"""
        self.assertEqual(
            parse_blocklist_text(text),
            {"ads.example.com", "nxdomain.example"},
        )

    def test_malware_ip_feeds_and_url_filters_do_not_become_fake_domains(self):
        lines = [
            "203.0.113.4",
            "198.51.100.0/24",
            "https://example.com/ads.js",
            "/tracking-pixel/",
            "@@||allow.example.com^",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(parse_blocklist_line(line), set())


if __name__ == "__main__":
    unittest.main()
