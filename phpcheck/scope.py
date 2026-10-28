"""The scope lock, the confirmation terminal and safe text.

remote and fleet touch other hosts. They run only against hosts the user has
placed in --scope, after the user has typed the confirmation on the
controlling terminal (or passed --yes together with --scope for scripted
runs). Anything outside the scope is refused, not warned about.

safe_text() is applied to every string that comes from a target (response
headers, command output, error lines) before it reaches the terminal or a
report, so a hostile banner cannot drive the operator's terminal.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import unicodedata
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

LABEL_PATTERN = re.compile(r"^(xn--)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

# The controlling terminal. The confirmation is read from here and nowhere
# else: not stdin, not an environment variable, not a file.
TTY_PATH = "/dev/tty"

CONFIRM_WORD = "yes"


def is_valid_name(name: str) -> bool:
    """True when name is a properly formed FQDN with at least two labels.
    Supports standard ASCII domains and Punycode (xn-- prefixed) IDN domains.
    """
    if not name or len(name) > 253:
        return False
    if "." not in name:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not LABEL_PATTERN.match(label):
            return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    if not re.match(r"^[a-zA-Z]{2,}$", tld) and not tld.startswith("xn--"):
        return False
    return True


def is_valid_host(name: str) -> bool:
    """True for an FQDN or a single-label host name such as an ssh alias (web-01)."""
    if not name or len(name) > 253:
        return False
    return all(LABEL_PATTERN.match(label) for label in name.split("."))


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class Scope:
    """The hosts, networks and domains the user has placed in scope.

    Entries come from --scope, either a file (one entry per line, blank lines
    and # comments ignored) or a comma-separated list. Four forms:

        app.example.com     exactly that host (a single-label ssh alias such as web-01 is allowed)
        *.example.com       every name under example.com, at any depth, not the apex
        203.0.113.7         that address
        203.0.113.0/24      every address in that network

    A target is covered when its host name matches a host or domain entry,
    or when every address it resolves to falls inside a network entry.
    Anything else is out of scope and nothing is sent to it.
    """

    def __init__(self, entries: Sequence[str]):
        self.entries: List[str] = []
        self.hosts = set()
        self.domains = set()
        self.networks = []
        for raw in entries:
            kind, value = self._parse_entry(raw)
            if kind == "host":
                self.hosts.add(value)
                self.entries.append(value)
            elif kind == "domain":
                self.domains.add(value)
                self.entries.append("*.%s" % value)
            else:
                self.networks.append(value)
                shown = str(value.network_address) if value.num_addresses == 1 else str(value)
                self.entries.append(shown)
        if not self.entries:
            raise ValueError("scope is empty: list at least one host, network or domain")

    @classmethod
    def from_option(cls, spec: str) -> "Scope":
        """Build a scope from the --scope value: a file path or a comma-separated list."""
        spec = (spec or "").strip()
        if not spec:
            raise ValueError("scope is empty")
        if os.path.isfile(spec):
            with open(spec, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            raw = []
            for line in lines:
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
            if not raw:
                raise ValueError("scope file has no entries: %s" % spec)
            return cls(raw)
        return cls([part for part in spec.split(",") if part.strip()])

    @staticmethod
    def _parse_entry(raw: str) -> Tuple[str, object]:
        text = raw.strip().lower()
        if not text:
            raise ValueError("empty scope entry")
        try:
            return "network", ipaddress.ip_network(text, strict=False)
        except ValueError:
            pass
        if text.startswith(("http://", "https://", "ssh://")):
            text = urlsplit(text).hostname or ""
        if "/" in text:
            text = text.split("/")[0]
        kind = "host"
        if text.startswith("*."):
            kind = "domain"
            text = text[2:]
        if "@" in text:
            text = text.rsplit("@", 1)[-1]
        if ":" in text and not _is_ip(text):
            text = text.split(":")[0]
        text = text.rstrip(".")
        if kind == "domain" and not is_valid_name(text):
            raise ValueError("not a host, network or domain: %s" % raw.strip())
        if kind == "host" and not is_valid_host(text):
            raise ValueError("not a host, network or domain: %s" % raw.strip())
        return kind, text

    def covers(self, hostname: str, ips: Sequence[str] = ()) -> bool:
        """True when the name is listed, or every resolved address is inside a listed network."""
        name = (hostname or "").strip().lower().rstrip(".")
        if name and name in self.hosts:
            return True
        for domain in self.domains:
            if name.endswith(".%s" % domain):
                return True
        addrs = []
        for ip in ips:
            try:
                addrs.append(ipaddress.ip_address(ip))
            except ValueError:
                return False
        if not addrs:
            return False
        for addr in addrs:
            if not any(addr.version == net.version and addr in net for net in self.networks):
                return False
        return True

    def describe(self) -> str:
        return ", ".join(self.entries)


def resolve_host(hostname: str) -> List[str]:
    """Every address the host resolves to, in resolver order, without duplicates.
    An address literal resolves to itself. Returns [] when resolution fails."""
    if _is_ip(hostname):
        return [hostname]
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    seen: List[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


def target_hostname(target: str) -> str:
    """The host inside a remote target (URL or bare host) or a fleet host
    (ssh alias, user@host or ssh://user@host:port), lower-cased, without a port."""
    t = (target or "").strip()
    if "://" in t:
        return (urlsplit(t).hostname or "").lower().rstrip(".")
    t = t.rsplit("@", 1)[-1]
    if t.startswith("[") and "]" in t:
        return t[1:t.index("]")].lower()
    if _is_ip(t):
        return t.lower()
    if ":" in t:
        t = t.split(":", 1)[0]
    return t.split("/", 1)[0].lower().rstrip(".")


def _open_tty() -> int:
    """A raw read-write descriptor on the controlling terminal.

    Opened with os.open rather than open(path, "r+"): the latter builds a
    BufferedRandom, which demands a seekable stream, and a terminal is not
    one, so it raises io.UnsupportedOperation (an OSError) on every real
    terminal and the gate would never open. O_NOCTTY is a no-op for
    /dev/tty and documents that the call never acquires a terminal.
    """
    return os.open(TTY_PATH, os.O_RDWR | getattr(os, "O_NOCTTY", 0))


def tty_available() -> bool:
    """True when a controlling terminal can be opened for the confirmation prompt."""
    try:
        fd = _open_tty()
    except OSError:
        return False
    os.close(fd)
    return True


def read_tty_line(prompt: str) -> Optional[str]:
    """Write prompt to the controlling terminal and read one line back from it.

    Returns the stripped line, or None when there is no terminal or it hit
    end of file. Nothing else can answer: stdin is not read, and no
    environment variable or configuration file is consulted.
    """
    try:
        fd = _open_tty()
    except OSError:
        return None
    try:
        if prompt:
            os.write(fd, prompt.encode("utf-8", "replace"))
        with open(fd, "r", encoding="utf-8", errors="replace", closefd=False) as reader:
            line = reader.readline()
    except OSError:
        return None
    finally:
        os.close(fd)
    if not line:
        return None
    return line.strip()


# Characters that must not reach a terminal or a report as they are:
#   Cc  C0 and C1 control characters, including ESC, BEL, CR, LF, DEL
#   Cf  format characters: bidirectional overrides, zero-width joiners, soft hyphen
#   Cs  lone surrogates
#   Zl  line separator, Zp  paragraph separator
_UNSAFE_CATEGORIES = ("Cc", "Cf", "Cs", "Zl", "Zp")
_BLANK = ("\t", "\n", "\r", "\x0b", "\x0c", " ", " ")


def safe_text(text: object, limit: Optional[int] = None) -> str:
    """Text taken from a target, made safe to print on one line.

    Tabs, newlines and other line breaks become single spaces. Every other
    control, format or separator character is shown in escaped form
    (\\x1b, \\u202e) so that it is visible in the evidence but inert. Runs of
    spaces are collapsed. With limit, longer text is cut and marked.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    out: List[str] = []
    for ch in text:
        if ch in _BLANK:
            out.append(" ")
        elif unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            code = ord(ch)
            out.append("\\x%02x" % code if code < 0x100 else "\\u%04x" % code)
        else:
            out.append(ch)
    cleaned = re.sub(r" {2,}", " ", "".join(out)).strip()
    if limit is not None and limit > 0 and len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip() + " [cut]"
    return cleaned
