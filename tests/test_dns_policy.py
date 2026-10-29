import os
import tempfile
import unittest
from unittest.mock import patch

# Importing the service for policy tests must not bind DNS ports or use the
# production data directory.
_TEST_HOME = tempfile.TemporaryDirectory(prefix="netblock-test-")
os.environ["NETBLOCK_HOME"] = _TEST_HOME.name
os.environ["NETBLOCK_DISABLE_SERVERS"] = "1"

from dnslib import CNAME, QTYPE, RR, A, DNSHeader, DNSRecord

import app as fortress


class FakeSocket:
    def __init__(self):
        self.packets = []

    def sendto(self, packet, address):
        self.packets.append((packet, address))


class FakeHTTPResponse:
    def __init__(self, body):
        self.body = body
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=65536):
        yield self.body


class FakeTCPSocket:
    def __init__(self):
        self.data = b""

    def sendall(self, data):
        self.data += data


class FakeUpstreamSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address

    def send(self, packet):
        request = DNSRecord.parse(packet)
        response = request.reply()
        response.add_answer(RR(
            rname=request.questions[0].qname,
            rtype=QTYPE.A,
            rclass=1,
            ttl=30,
            rdata=A("203.0.113.25"),
        ))
        self.response = response.pack()

    def recv(self, size):
        return self.response


class DNSPolicyTests(unittest.TestCase):
    def setUp(self):
        self.old = {
            "categories": fortress.DOMAIN_CATEGORIES,
            "sources": fortress.DOMAIN_SOURCES,
            "custom_blocked": fortress.CUSTOM_BLOCKED,
            "custom_whitelist": fortress.CUSTOM_WHITELIST,
            "rate_limiting": fortress.CFG.get("rate_limiting"),
            "dga_protection": fortress.CFG.get("dga_protection"),
            "cname_uncloaking": fortress.CFG.get("cname_uncloaking"),
            "rebinding_protection": fortress.CFG.get("rebinding_protection"),
            "query_logging": fortress.CFG.get("query_logging"),
        }
        fortress.DOMAIN_CATEGORIES = {"ads.example": "ads"}
        fortress.DOMAIN_SOURCES = {"ads.example": "test feed"}
        fortress.CUSTOM_BLOCKED = set()
        fortress.CUSTOM_WHITELIST = set()
        fortress.CFG.update({
            "rate_limiting": False,
            "dga_protection": False,
            "cname_uncloaking": True,
            "rebinding_protection": False,
            "query_logging": False,
        })

    def tearDown(self):
        fortress.DOMAIN_CATEGORIES = self.old["categories"]
        fortress.DOMAIN_SOURCES = self.old["sources"]
        fortress.CUSTOM_BLOCKED = self.old["custom_blocked"]
        fortress.CUSTOM_WHITELIST = self.old["custom_whitelist"]
        for key in ("rate_limiting", "dga_protection", "cname_uncloaking", "rebinding_protection", "query_logging"):
            fortress.CFG[key] = self.old[key]

    def test_upstream_resolver_builds_a_numeric_dns_question(self):
        with patch.object(fortress.socket, "socket", return_value=FakeUpstreamSocket()):
            response = fortress.resolve_upstream("clean.example", QTYPE.A, 1)
        self.assertIsNotNone(response)
        self.assertEqual(str(response.rr[0].rdata), "203.0.113.25")

    def test_feed_refresh_keeps_last_good_cache_on_empty_source_then_replaces_atomically(self):
        list_id = "adguard"
        cache_path = fortress.LIST_DIR / f"{list_id}.txt"
        existed = cache_path.exists()
        old_bytes = cache_path.read_bytes() if existed else None
        old_status = dict(fortress.LIST_STATUS[list_id])
        try:
            cache_path.write_text("0.0.0.0 cached.example\n", encoding="utf-8")
            with patch("requests.get", return_value=FakeHTTPResponse(b"<!doctype html>")):
                self.assertEqual(fortress.download_and_parse_list(list_id), 0)
            self.assertEqual(cache_path.read_text(encoding="utf-8"), "0.0.0.0 cached.example\n")
            self.assertEqual(fortress.LIST_STATUS[list_id]["state"], "stale")
            self.assertEqual(fortress.LIST_STATUS[list_id]["count"], 1)

            with patch("requests.get", return_value=FakeHTTPResponse(b"||new-ad.example^\n")):
                self.assertEqual(fortress.download_and_parse_list(list_id), 1)
            self.assertEqual(cache_path.read_text(encoding="utf-8"), "||new-ad.example^\n")
            self.assertEqual(fortress.LIST_STATUS[list_id]["state"], "active")
        finally:
            if existed:
                cache_path.write_bytes(old_bytes)
            else:
                cache_path.unlink(missing_ok=True)
            fortress.LIST_STATUS[list_id].clear()
            fortress.LIST_STATUS[list_id].update(old_status)
            fortress.save_list_status()

    def test_suffix_matching_is_boundary_safe_and_whitelist_wins(self):
        self.assertEqual(fortress.audit_threat("img.ads.example.")[0], "blocked")
        self.assertEqual(fortress.audit_threat("notads.example")[0], "allowed")

        fortress.CUSTOM_WHITELIST = {"ads.example"}
        self.assertEqual(fortress.audit_threat("img.ads.example")[0], "whitelisted")

    def test_client_activity_and_rate_limit_tracking_are_bounded(self):
        old_max_clients = fortress.MAX_TRACKED_CLIENTS
        old_activity = list(fortress.CLIENT_ACTIVITY.items())
        old_rates = list(fortress.CLIENT_RATES.items())
        try:
            fortress.MAX_TRACKED_CLIENTS = 2
            with fortress.CLIENT_ACTIVITY_LOCK:
                fortress.CLIENT_ACTIVITY.clear()
            with fortress.RATE_LIMIT_LOCK:
                fortress.CLIENT_RATES.clear()
            fortress.CFG["rate_limiting"] = True

            for index in range(3):
                client_ip = f"192.0.2.{index + 1}"
                fortress.update_client_activity(client_ip, total=1)
                self.assertTrue(fortress.rate_limit_check(client_ip))

            self.assertEqual(list(fortress.CLIENT_ACTIVITY), ["192.0.2.2", "192.0.2.3"])
            self.assertEqual(list(fortress.CLIENT_RATES), ["192.0.2.2", "192.0.2.3"])
        finally:
            fortress.MAX_TRACKED_CLIENTS = old_max_clients
            with fortress.CLIENT_ACTIVITY_LOCK:
                fortress.CLIENT_ACTIVITY.clear()
                fortress.CLIENT_ACTIVITY.update(old_activity)
            with fortress.RATE_LIMIT_LOCK:
                fortress.CLIENT_RATES.clear()
                fortress.CLIENT_RATES.update(old_rates)

    def test_video_cdn_is_protected_even_if_a_feed_contains_it(self):
        fortress.DOMAIN_CATEGORIES["googlevideo.com"] = "ads"
        fortress.DOMAIN_SOURCES["googlevideo.com"] = "unsafe test feed"
        verdict, _, _, rule, source = fortress.audit_threat("r4---sn-4g5edn7s.googlevideo.com")
        self.assertEqual(verdict, "allowed")
        self.assertEqual(rule, "googlevideo.com")
        self.assertEqual(source, "protected media guard")

    def test_blocked_query_returns_sinkhole_and_records_rule_source(self):
        query = DNSRecord.question("img.ads.example", "A")
        query.header.id = 0xBEEF
        udp = FakeSocket()
        with patch.object(fortress, "resolve_upstream") as upstream:
            fortress.handle_dns_request(query.pack(), ("192.0.2.50", 54321), udp)
        upstream.assert_not_called()

        response = DNSRecord.parse(udp.packets[-1][0])
        self.assertEqual(response.header.id, 0xBEEF)
        self.assertEqual(str(response.rr[0].rdata), "0.0.0.0")
        event = fortress.QUERY_LOGS[0]
        self.assertEqual(event["matched_rule"], "ads.example")
        self.assertEqual(event["source"], "test feed")

    def test_cname_is_checked_from_one_upstream_answer_and_client_id_is_restored(self):
        query = DNSRecord.question("cloaked.example", "A")
        query.header.id = 0x1234
        upstream_reply = DNSRecord(
            DNSHeader(id=0x9876, qr=1, aa=1, ra=1),
            q=query.questions[0],
        )
        upstream_reply.add_answer(RR(
            rname=query.questions[0].qname,
            rtype=QTYPE.CNAME,
            rclass=1,
            ttl=60,
            rdata=CNAME("ads.example."),
        ))
        udp = FakeSocket()

        with patch.object(fortress, "resolve_upstream", return_value=upstream_reply) as upstream:
            fortress.handle_dns_request(query.pack(), ("192.0.2.51", 54322), udp)

        upstream.assert_called_once()
        response = DNSRecord.parse(udp.packets[-1][0])
        self.assertEqual(response.header.id, 0x1234)
        self.assertEqual(str(response.rr[0].rdata), "0.0.0.0")
        self.assertIn("CNAME target blocked", fortress.QUERY_LOGS[0]["reason"])

    def test_tcp_dns_reply_uses_two_byte_length_prefix(self):
        query = DNSRecord.question("clean.example", "A")
        query.header.id = 0x3456
        upstream_reply = DNSRecord(DNSHeader(id=0x7777, qr=1, aa=1, ra=1), q=query.questions[0])
        upstream_reply.add_answer(RR(
            rname=query.questions[0].qname,
            rtype=QTYPE.A,
            rclass=1,
            ttl=60,
            rdata=A("203.0.113.21"),
        ))
        tcp = FakeTCPSocket()

        with patch.object(fortress, "resolve_upstream", return_value=upstream_reply):
            fortress.handle_dns_request(query.pack(), ("192.0.2.53", 54324), tcp, tcp=True)

        response_length = int.from_bytes(tcp.data[:2], "big")
        self.assertEqual(response_length, len(tcp.data) - 2)
        response = DNSRecord.parse(tcp.data[2:])
        self.assertEqual(response.header.id, 0x3456)
        self.assertEqual(str(response.rr[0].rdata), "203.0.113.21")

    def test_allowed_upstream_reply_uses_original_client_transaction_id(self):
        query = DNSRecord.question("clean.example", "A")
        query.header.id = 0x4567
        upstream_reply = DNSRecord(DNSHeader(id=0x7777, qr=1, aa=1, ra=1), q=query.questions[0])
        upstream_reply.add_answer(RR(
            rname=query.questions[0].qname,
            rtype=QTYPE.A,
            rclass=1,
            ttl=60,
            rdata=A("203.0.113.20"),
        ))
        udp = FakeSocket()

        with patch.object(fortress, "resolve_upstream", return_value=upstream_reply):
            fortress.handle_dns_request(query.pack(), ("192.0.2.52", 54323), udp)

        response = DNSRecord.parse(udp.packets[-1][0])
        self.assertEqual(response.header.id, 0x4567)
        self.assertEqual(response.questions[0].qname, query.questions[0].qname)
        self.assertEqual(str(response.rr[0].rdata), "203.0.113.20")


if __name__ == "__main__":
    unittest.main()
