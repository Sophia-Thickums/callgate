"""callgate.rules — what a tool call is allowed to reach.

Design law: every rule must be able to say "I cannot judge this", and a rule that
cannot fail is not a rule. Where a rule would need to guess, it returns UNKNOWN and
the gate reports it rather than waving it through.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse
import ipaddress

ALLOW = "allow"
DENY = "deny"
UNKNOWN = "unknown"


@dataclass
class Verdict:
    action: str            # allow | deny | unknown
    rule: str
    reason: str
    detail: dict = field(default_factory=dict)

    def as_dict(self):
        return {"action": self.action, "rule": self.rule, "reason": self.reason, "detail": self.detail}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host in ("localhost", "localhost.localdomain")


# Credential-ish material a legitimate tool call almost never needs to SEND OUT.
_SECRET_PATTERNS = [
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{12,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("generic assignment of a long secret", re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9._\-]{12,}")),
]

# Tools whose normal job is to move bytes off the machine.
_NETWORK_TOOLS = ("http", "fetch", "request", "curl", "wget", "post", "upload", "send", "webhook", "url")


def _looks_like_network(tool: str, args: dict) -> bool:
    t = (tool or "").lower()
    if any(k in t for k in _NETWORK_TOOLS):
        return True
    for v in args.values():
        if isinstance(v, str) and re.match(r"^https?://", v.strip()):
            return True
    return False


def _all_strings(obj) -> list[tuple[str, str]]:
    """Flatten to (path, value) for every string in a nested structure."""
    out = []
    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(o, (list, tuple)):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
        elif isinstance(o, str):
            out.append((path or "value", o))
    walk(obj, "")
    return out


# --------------------------------------------------------------------------- #
# rules — each returns a Verdict, and UNKNOWN is a first-class answer
# --------------------------------------------------------------------------- #

def rule_egress_secret(tool: str, args: dict) -> Verdict:
    """A call that would move credential-shaped data off this machine."""
    if not _looks_like_network(tool, args):
        return Verdict(ALLOW, "egress_secret", "not a network call")
    for path, value in _all_strings(args):
        for name, pat in _SECRET_PATTERNS:
            if pat.search(value):
                return Verdict(
                    DENY, "egress_secret",
                    f"outbound call carries {name} in argument '{path}'",
                    {"argument": path, "material": name},
                )
    return Verdict(ALLOW, "egress_secret", "outbound call, no credential-shaped argument")


def rule_private_network(tool: str, args: dict) -> Verdict:
    """Which host is this call actually aimed at? Judge the host, not the tool name."""
    host = None
    for _, value in _all_strings(args):
        m = re.match(r"^https?://([^/:\s]+)", value.strip())
        if m:
            host = m.group(1)
            break
    if host is None:
        if _looks_like_network(tool, args):
            return Verdict(UNKNOWN, "private_network",
                           "call looks outbound but no explicit host could be resolved")
        return Verdict(ALLOW, "private_network", "no host in call")
    if _is_private_host(host):
        return Verdict(ALLOW, "private_network", f"host {host} is local")
    return Verdict(UNKNOWN, "private_network",
                   f"call reaches external host {host}",
                   {"host": host})


def rule_secret_read(tool: str, args: dict) -> Verdict:
    """A call reaching into a known secret store. Legitimate, but worth naming."""
    for path, value in _all_strings(args):
        low = value.lower()
        if any(p in low for p in ("/.ssh/", "/.aws/", "credentials.json", ".env",
                                   "id_rsa", "auth.json", ".netrc", "keyring")):
            return Verdict(DENY, "secret_read",
                           f"call reads a credential store: '{path}'",
                           {"argument": path})
    return Verdict(ALLOW, "secret_read", "no credential store referenced")


RULES: list[Callable[[str, dict], Verdict]] = [
    rule_secret_read,      # reading secrets is what we catch first
    rule_egress_secret,    # moving them out is what we catch hardest
    rule_private_network,  # where it points
]


def evaluate(tool: str, args: dict) -> Verdict:
    """First DENY wins. Otherwise UNKNOWN outranks ALLOW. ALLOW only if all allow."""
    verdicts = [r(tool, args) for r in RULES]
    for v in verdicts:
        if v.action == DENY:
            return v
    for v in verdicts:
        if v.action == UNKNOWN:
            return v
    return verdicts[-1]
