"""Reading PHP settings from probe output, phpinfo output and FPM pool files,
and summarising which mitigations are in place."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# Settings that matter for CVE-2026-109618 and CVE-2026-109619.
SETTINGS_KEYS = (
    "memory_limit",
    "post_max_size",
    "upload_max_filesize",
    "max_file_uploads",
    "file_uploads",
    "max_input_vars",
    "max_input_nesting_level",
    "max_multipart_body_parts",
    "session.upload_progress.enabled",
    "fatal_error_backtraces",
)

BOOLEAN_KEYS = ("file_uploads", "session.upload_progress.enabled", "fatal_error_backtraces")

NOT_PRESENT = "(not present)"

# The PHP snippet run with `php -r`. It only reads constants and ini values.
PROBE_PHP = (
    "$k=array(" + ",".join("'%s'" % k for k in SETTINGS_KEYS) + ");"
    "echo 'php.version=',PHP_VERSION,\"\\n\";"
    "echo 'php.sapi=',php_sapi_name(),\"\\n\";"
    "echo 'php.ini_loaded=',(function_exists('php_ini_loaded_file')?(string)php_ini_loaded_file():''),\"\\n\";"
    "foreach($k as $n){$v=ini_get($n);echo 'ini.',$n,'=',($v===false?'" + NOT_PRESENT + "':$v),\"\\n\";}"
)


def normalise_bool(value: str) -> str:
    v = value.strip().lower()
    if v in ("1", "on", "yes", "true"):
        return "On"
    if v in ("0", "off", "no", "false", "", "no value"):
        return "Off"
    return value.strip()


def _clean(key: str, value: str) -> str:
    value = value.strip()
    if key in BOOLEAN_KEYS and value != NOT_PRESENT:
        return normalise_bool(value)
    return value


@dataclass
class ProbeData:
    version: Optional[str] = None
    sapi: Optional[str] = None
    ini_loaded: Optional[str] = None
    settings: Dict[str, str] = field(default_factory=dict)


def parse_probe(text: str) -> ProbeData:
    """Parse the key=value lines printed by PROBE_PHP. Other lines are ignored."""
    data = ProbeData()
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key == "php.version":
            data.version = value.strip()
        elif key == "php.sapi":
            data.sapi = value.strip()
        elif key == "php.ini_loaded":
            data.ini_loaded = value.strip() or None
        elif key.startswith("ini.") and key[4:] in SETTINGS_KEYS:
            data.settings[key[4:]] = _clean(key[4:], value)
    return data


_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ROW_RE = re.compile(r'<td class="e">(.*?)</td><td class="v">(.*?)</td>', re.I)
_HTML_VERSION_RE = re.compile(r"PHP Version\s*(?:</td><td class=\"v\">)?\s*([0-9][^<\s]*)", re.I)


def parse_phpinfo(text: str) -> ProbeData:
    """Parse `php -i` output, text or HTML, for the version, SAPI and settings."""
    data = ProbeData()
    for line in text.splitlines():
        if "<td" in line:
            m = _HTML_ROW_RE.search(line)
            if m:
                key = html.unescape(_TAG_RE.sub("", m.group(1))).strip()
                value = html.unescape(_TAG_RE.sub("", m.group(2))).strip()
                _take(data, key, value)
                continue
        if "PHP Version" in line and "<" in line:
            m = _HTML_VERSION_RE.search(line)
            if m and not data.version:
                data.version = m.group(1)
            continue
        if "=>" in line:
            parts = [p.strip() for p in line.split("=>")]
            if len(parts) >= 2:
                _take(data, parts[0], parts[1])
    return data


def _take(data: ProbeData, key: str, value: str) -> None:
    if key == "PHP Version" and not data.version:
        data.version = value
    elif key == "Server API" and not data.sapi:
        data.sapi = value
    elif key == "Loaded Configuration File" and not data.ini_loaded:
        data.ini_loaded = None if value in ("(none)", "") else value
    elif key in SETTINGS_KEYS and key not in data.settings:
        data.settings[key] = _clean(key, value)


_SAPI_NAMES = {
    "fpm/fastcgi": "fpm",
    "fpm-fcgi": "fpm",
    "cgi/fastcgi": "cgi",
    "cgi-fcgi": "cgi",
    "command line interface": "cli",
    "cli": "cli",
    "apache 2.0 handler": "apache2handler",
    "apache2handler": "apache2handler",
    "litespeed v8.1": "lsapi",
    "litespeed": "lsapi",
    "frankenphp": "frankenphp",
}


def sapi_kind(sapi: Optional[str], default: str) -> str:
    if not sapi:
        return default
    s = sapi.strip().lower()
    if s in _SAPI_NAMES:
        return _SAPI_NAMES[s]
    if s.startswith("litespeed"):
        return "lsapi"
    return default


@dataclass
class Pool:
    path: str
    name: str
    pm: Optional[str] = None
    max_requests: Optional[str] = None
    max_children: Optional[str] = None
    overrides: Dict[str, str] = field(default_factory=dict)

    @property
    def recycles(self) -> bool:
        try:
            return int(self.max_requests or "0") > 0
        except ValueError:
            return False


_OVERRIDE_RE = re.compile(r"^php_(?:admin_)?(?:value|flag)\[([^\]]+)\]$")


def parse_pool_file(path: str, text: str) -> List[Pool]:
    """Parse an FPM pool or php-fpm.conf file. [global] is not a pool."""
    pools: List[Pool] = []
    current: Optional[Pool] = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if name.lower() == "global":
                current = None
            else:
                current = Pool(path=path, name=name)
                pools.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.split(";")[0].strip().strip('"')
        if key == "pm":
            current.pm = value
        elif key == "pm.max_requests":
            current.max_requests = value
        elif key == "pm.max_children":
            current.max_children = value
        else:
            m = _OVERRIDE_RE.match(key)
            if m and m.group(1) in SETTINGS_KEYS:
                current.overrides[m.group(1)] = _clean(m.group(1), value)
    return pools


def merge_pools(pools: Sequence[Pool]) -> List[Pool]:
    """FPM allows a pool to be declared across several files; later files win."""
    merged: Dict[Tuple[str, str], Pool] = {}
    order: List[Tuple[str, str]] = []
    for p in pools:
        base = p.path.rsplit("/", 1)[0]
        k = (base, p.name)
        if k not in merged:
            merged[k] = Pool(path=p.path, name=p.name)
            order.append(k)
        m = merged[k]
        m.pm = p.pm or m.pm
        m.max_requests = p.max_requests or m.max_requests
        m.max_children = p.max_children or m.max_children
        m.overrides.update(p.overrides)
    return [merged[k] for k in order]


def assess_settings(settings: Dict[str, str], branch: Optional[str],
                    pools: Sequence[Pool] = (), patched: bool = False) -> Tuple[List[str], List[str]]:
    """Return (in_place, gaps). Neither list replaces patching.

    The memory_limit=-1 interim setting is only suggested for unpatched
    installs; once patched a finite memory_limit is the normal choice."""
    in_place: List[str] = []
    gaps: List[str] = []

    mem = settings.get("memory_limit")
    if mem is not None and mem != NOT_PRESENT:
        if mem.strip() == "-1":
            in_place.append("memory_limit=-1 (interim setting from GHSA-w8hw-w9fx-j79w, partial)")
        elif not patched:
            gaps.append("memory_limit=%s is finite; GHSA-w8hw-w9fx-j79w interim setting is -1 (partial, pair with a cgroup limit)" % mem)

    fu = settings.get("file_uploads")
    if fu == "On":
        gaps.append("file_uploads=On (disable where uploads are unused)")
    elif fu == "Off":
        in_place.append("file_uploads=Off")

    up = settings.get("session.upload_progress.enabled")
    if up == "On":
        gaps.append("session.upload_progress.enabled=On (set 0, GHSA-6wmf-4rv5-p3rp)")
    elif up == "Off":
        in_place.append("session.upload_progress.enabled=Off")

    if branch == "8.5" or (branch and tuple(int(x) for x in branch.split(".")) > (8, 5)):
        fb = settings.get("fatal_error_backtraces")
        if fb == "On":
            gaps.append("fatal_error_backtraces=On (set 0 on 8.5, GHSA-6wmf-4rv5-p3rp)")
        elif fb == "Off":
            in_place.append("fatal_error_backtraces=Off")

    for pool in pools:
        label = "pool %s" % pool.name
        if pool.recycles:
            in_place.append("%s: pm.max_requests=%s" % (label, pool.max_requests))
        else:
            gaps.append("%s: pm.max_requests=%s (workers never recycled)" % (
                label, pool.max_requests if pool.max_requests else "unset, default 0"))
        for k, v in sorted(pool.overrides.items()):
            text = "%s sets %s=%s" % (label, k, v)
            if (k == "memory_limit" and v == "-1") or (k in BOOLEAN_KEYS and v == "Off"):
                in_place.append(text)
            elif k in BOOLEAN_KEYS and v == "On":
                gaps.append(text)
    return in_place, gaps


def short_settings(settings: Dict[str, str]) -> str:
    parts = []
    for k in SETTINGS_KEYS:
        if k in settings and settings[k] != NOT_PRESENT:
            parts.append("%s=%s" % (k, settings[k] if settings[k] != "" else '""'))
    return " ".join(parts)
