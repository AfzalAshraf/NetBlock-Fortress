"""Domain-level parsing and matching for DNS blocklists.

DNS can only act on hostnames, not URLs, paths, cosmetic rules, or request types.
This module therefore deliberately accepts only unambiguous host rules from the
common hosts, plain-domain, dnsmasq, and Adblock Plus list formats.
"""

import re
from ipaddress import ip_address
from typing import Iterable, Optional, Set, Tuple

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_ABP_RULE_RE = re.compile(
    r"^\|\|(\*\.)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(\^|\||\$|$)",
    re.IGNORECASE,
)
_LOCAL_NAMES = ("localhost", ".localhost", ".local", ".lan", ".internal", ".home.arpa")
_SINKHOLE_ADDRESSES = {"0.0.0.0", "::", "127.0.0.1", "::1"}


def normalize_domain(value: str, allow_local: bool = False, allow_wildcard: bool = True) -> Optional[str]:
    """Return a canonical ASCII domain (or ``*.domain`` pattern), else ``None``.

    Rejects IP literals, URL fragments, paths, ports, wildcards other than a
    leading ``*.`` and malformed labels. IDNs are converted to ASCII.
    """
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 256:
        return None

    wildcard = value.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            return None
        value = value[2:]
    if not value or "*" in value or "/" in value or "\\" in value or ":" in value:
        return None

    try:
        canonical = value.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return None

    if len(canonical) > 253 or "." not in canonical:
        return None
    labels = canonical.split(".")
    if any(not label or len(label) > 63 or not _LABEL_RE.fullmatch(label) for label in labels):
        return None
    try:
        ip_address(canonical)
        return None
    except ValueError:
        pass

    if not allow_local and (
        canonical == "localhost" or any(canonical.endswith(suffix) for suffix in _LOCAL_NAMES[1:])
    ):
        return None

    return "*." + canonical if wildcard else canonical


def normalize_query_name(value: str) -> str:
    """Normalize a DNS QNAME while preserving service labels such as ``_dmarc``."""
    if not isinstance(value, str):
        return ""
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or "/" in value or "\\" in value:
        return ""

    labels = []
    for label in value.split("."):
        if not label:
            return ""
        if label.startswith("_"):
            service_label = label[1:]
            if not service_label or len(label) > 63 or not re.fullmatch(r"[a-z0-9_-]+", service_label):
                return ""
            labels.append(label)
            continue
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            return ""
        if len(ascii_label) > 63 or not _LABEL_RE.fullmatch(ascii_label):
            return ""
        labels.append(ascii_label)

    canonical = ".".join(labels)
    return canonical if len(canonical) <= 253 else ""


def domain_suffixes(query_name: str) -> Tuple[str, ...]:
    """Return QNAME suffixes from most-specific to least-specific (excluding TLD)."""
    normalized = normalize_query_name(query_name)
    if not normalized:
        return ()
    labels = normalized.split(".")
    return tuple(".".join(labels[index:]) for index in range(max(0, len(labels) - 1)))


def domain_rule_matches(query_name: str, rule: str) -> bool:
    """Test a normalized root rule or ``*.subtree`` rule against a QNAME."""
    query = normalize_query_name(query_name)
    pattern = normalize_domain(rule, allow_local=True)
    if not query or not pattern:
        return False
    if pattern.startswith("*."):
        root = pattern[2:]
        return query != root and query.endswith("." + root)
    return query == pattern or query.endswith("." + pattern)


def _is_sinkhole_address(value: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return address.is_unspecified or address.is_loopback


def _parse_dnsmasq_address(line: str) -> Set[str]:
    """Accept dnsmasq address overrides only when they sinkhole or NXDOMAIN."""
    directive = line.strip().split(None, 1)[0] if line.strip() else ""
    prefix = "address=/"
    if not directive.lower().startswith(prefix):
        return set()

    specification = directive[len(prefix):]
    if "/" not in specification:
        return set()
    fields = specification.split("/")
    if fields[-1] == "":
        fields.pop()  # address=/example.com/ means NXDOMAIN in dnsmasq.
    if not fields or any(not field for field in fields):
        return set()

    # One or more trailing IPs are optional address overrides. Do not convert
    # a legitimate mapping to a different address into a DNS block.
    while fields:
        try:
            address = ip_address(fields[-1])
        except ValueError:
            break
        fields.pop()
        if not (address.is_unspecified or address.is_loopback):
            return set()
    if not fields or any(_looks_like_ip(field) for field in fields):
        return set()

    domains = [normalize_domain(field) for field in fields]
    if any(domain is None for domain in domains):
        return set()
    return set(domains)


def _looks_like_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def _parse_abp_domain_rule(line: str) -> Optional[str]:
    # Cosmetic filters, exceptions (allow rules), and path/URL filters cannot be
    # represented by DNS. Do not turn them into broader whole-domain blocks.
    if line.startswith("@@") or "##" in line or "#@#" in line or "#$#" in line:
        return None
    match = _ABP_RULE_RE.match(line)
    if not match:
        return None

    wildcard, host, boundary = match.groups()
    remainder = line[match.end():]
    if boundary == "^" and remainder and not remainder.startswith("$"):
        return None
    if boundary == "|" and remainder:
        return None
    if boundary == "$" and remainder and not re.match(r"^[a-zA-Z0-9_,=-]+$", remainder):
        return None
    if boundary == "^" and remainder.startswith("$"):
        options = remainder[1:].lower()
        # These options make the rule conditional on a site/URL or perform an
        # action other than blocking the hostname.
        if any(option in options for option in ("domain=", "denyallow=", "redirect=", "removeparam", "badfilter")):
            return None

    pattern = ("*." if wildcard else "") + host
    return normalize_domain(pattern)


def parse_blocklist_line(raw_line: str) -> Set[str]:
    """Parse one supported hosts/domain/dnsmasq/ABP line into domain rules."""
    line = raw_line.strip().lstrip("\ufeff")
    if not line or line.startswith(("#", "!", ";", "//")):
        return set()

    # ABP / AdGuard hostname-anchored network filters. URL-path, regex,
    # cosmetic, and exception rules are intentionally ignored.
    if line.startswith("@@") or line.startswith("||"):
        rule = _parse_abp_domain_rule(line)
        return {rule} if rule else set()

    # dnsmasq `address=` rules can block or map to a real IP; `server=` rules
    # forward queries and must not be mistaken for blocks.
    if line.lower().startswith("address=/"):
        return _parse_dnsmasq_address(line)

    fields = line.split()
    if not fields:
        return set()

    # Hosts files: only accept mappings to a sinkhole address. Other mappings
    # (including malware-feed IPs and CIDRs) are not domain block rules.
    if fields[0] in _SINKHOLE_ADDRESSES or _is_sinkhole_address(fields[0]):
        if not _is_sinkhole_address(fields[0]):
            return set()
        domains = set()
        for host in fields[1:]:
            if host.startswith(("#", "!")):
                break
            rule = normalize_domain(host, allow_wildcard=False)
            if rule:
                domains.add(rule)
        return domains

    # Plain domain feeds, including an optional inline comment.
    candidate = fields[0]
    if len(fields) > 1 and not fields[1].startswith(("#", "!", ";")):
        return set()
    rule = normalize_domain(candidate)
    return {rule} if rule else set()


def parse_blocklist_text(text: str) -> Set[str]:
    """Parse a complete text blocklist and return its supported DNS rules."""
    if isinstance(text, bytes):
        text = text.decode("utf-8-sig", errors="replace")
    if not isinstance(text, str):
        return set()
    domains = set()
    for line in text.splitlines():
        domains.update(parse_blocklist_line(line))
    return domains


def find_matching_rule(query_name: str, rules: Iterable[str]) -> Optional[str]:
    """Return the most-specific matching root/wildcard rule in ``rules``."""
    normalized = normalize_query_name(query_name)
    if not normalized:
        return None
    for suffix in domain_suffixes(normalized):
        if suffix in rules:
            return suffix
        wildcard = "*." + suffix
        if suffix != normalized and wildcard in rules:
            return wildcard
    return None
