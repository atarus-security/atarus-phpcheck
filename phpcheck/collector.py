"""The read-only inventory script and the parser for its output.

The same POSIX sh script is used by `local` (run with sh -s), `fleet` (piped
over ssh) and the best-effort part of `image` (piped into the container).
It only lists files, runs `-v`, `-r <probe>` or `-i` on PHP binaries it finds,
greps a handful of lines out of FPM pool files and reads the version string
embedded in Apache PHP modules. It changes nothing on the host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .model import Result, build_result
from .settings import (
    PROBE_PHP,
    SETTINGS_KEYS,
    Pool,
    merge_pools,
    parse_phpinfo,
    parse_pool_file,
    parse_probe,
    sapi_kind,
)

_INFO_GREP = "|".join(
    ["PHP Version", "Server API", "Loaded Configuration File"] + [k.replace(".", "\\.") for k in SETTINGS_KEYS]
)
_POOL_GREP = (
    r"^[[:space:]]*(\[|pm[[:space:]]*=|pm\.max_requests|pm\.max_children|php_(admin_)?(value|flag)\[("
    + "|".join(k.replace(".", "\\.") for k in SETTINGS_KEYS)
    + r")\])"
)

_SCRIPT_TEMPLATE = r"""
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
LC_ALL=C
export PATH LC_ALL
echo "@@PHPCHECK 1"
echo "@@HOST $(hostname 2>/dev/null || uname -n 2>/dev/null)"
PROBE=$(cat <<'PHPCHECK_PROBE_EOF'
@PROBE@
PHPCHECK_PROBE_EOF
)
if command -v timeout >/dev/null 2>&1; then T="timeout 20"; else T=""; fi
resolve() {
  r=$(readlink -f "$1" 2>/dev/null)
  [ -n "$r" ] || r=$(realpath "$1" 2>/dev/null)
  [ -n "$r" ] || r=$1
  printf '%s\n' "$r"
}
SEEN=" "
seen() {
  case "$SEEN" in *" $1 "*) return 0 ;; esac
  SEEN="$SEEN$1 "
  return 1
}
emit_bin() {
  real=$(resolve "$1")
  seen "$real" && return 0
  name=$(basename "$real")
  case "$name" in
    *-config*|*ize*|*.dpkg*|*.rpm*|*.bak|*dbg*) return 0 ;;
    *fpm*) kind=fpm ;;
    *cgi*) kind=cgi ;;
    lsphp*) kind=lsapi ;;
    *) kind=cli ;;
  esac
  echo "@@BIN $kind $real"
  echo "@@V"
  $T "$real" -v </dev/null 2>&1 | head -n 8
  echo "@@INFO"
  if [ "$kind" = cli ]; then
    $T "$real" -r "$PROBE" </dev/null 2>&1 | head -n 60
  else
    $T "$real" -i </dev/null 2>&1 | grep -aE '@INFO_GREP@' | head -n 80
  fi
  echo "@@END"
}
for d in $(printf '%s' "$PATH" | tr ':' ' ') /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
    /opt/homebrew/bin /opt/homebrew/sbin /opt/homebrew/opt/php*/bin /opt/homebrew/opt/php*/sbin \
    /usr/local/opt/php*/bin /usr/local/opt/php*/sbin /opt/remi/php*/root/usr/bin /opt/remi/php*/root/usr/sbin \
    /opt/cpanel/ea-php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/sbin /opt/plesk/php/*/bin /opt/plesk/php/*/sbin \
    /usr/local/php*/bin /usr/local/php*/sbin /usr/local/lsws/lsphp*/bin /opt/bitnami/php/bin /opt/bitnami/php/sbin; do
  [ -d "$d" ] || continue
  for f in "$d"/php "$d"/php[0-9]* "$d"/php-fpm* "$d"/php-cgi* "$d"/lsphp*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    emit_bin "$f"
  done
done
for m in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
    /usr/local/apache2/modules/libphp*.so /usr/libexec/apache2/libphp*.so /opt/homebrew/opt/php*/lib/httpd/modules/libphp*.so \
    /usr/local/opt/php*/lib/httpd/modules/libphp*.so /usr/local/lib/libphp*.so /usr/lib/libphp*.so; do
  [ -f "$m" ] || continue
  real=$(resolve "$m")
  seen "$real" && continue
  echo "@@MODULE $real"
  grep -a -o 'X-Powered-By: PHP/[0-9A-Za-z.~+-]*' "$real" 2>/dev/null | head -n 1
  echo "@@END"
done
for ini in /etc/php/*/apache2/php.ini; do
  [ -f "$ini" ] || continue
  ver=$(echo "$ini" | cut -d/ -f4)
  cli=/usr/bin/php$ver
  [ -x "$cli" ] || continue
  echo "@@SAPIINI apache2 $ver $ini"
  echo "@@INFO"
  PHP_INI_SCAN_DIR="$(dirname "$ini")/conf.d" $T "$cli" -c "$ini" -r "$PROBE" </dev/null 2>&1 | head -n 60
  echo "@@END"
done
for c in /etc/apache2/mods-enabled/php*.load /etc/httpd/conf.modules.d/*php*.conf; do
  [ -f "$c" ] && echo "@@APACHE_CONF $c"
done
for p in /etc/php/*/fpm/php-fpm.conf /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.conf /etc/php-fpm.d/*.conf \
    /etc/opt/remi/php*/php-fpm.conf /etc/opt/remi/php*/php-fpm.d/*.conf /opt/remi/php*/root/etc/php-fpm.d/*.conf \
    /usr/local/etc/php-fpm.conf /usr/local/etc/php-fpm.d/*.conf /usr/local/etc/php/*/php-fpm.d/*.conf \
    /opt/homebrew/etc/php/*/php-fpm.conf /opt/homebrew/etc/php/*/php-fpm.d/*.conf \
    /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf /opt/plesk/php/*/etc/php-fpm.d/*.conf /opt/bitnami/php/etc/php-fpm.d/*.conf; do
  [ -f "$p" ] && [ -r "$p" ] || continue
  echo "@@POOL $p"
  grep -aE '@POOL_GREP@' "$p" 2>/dev/null | head -n 200
  echo "@@END"
done
echo "@@DONE"
"""

SCRIPT = (
    _SCRIPT_TEMPLATE.replace("@PROBE@", PROBE_PHP)
    .replace("@INFO_GREP@", _INFO_GREP)
    .replace("@POOL_GREP@", _POOL_GREP)
)

_PHP_V_RE = re.compile(r"^PHP (\d\S*) \(", re.M)
_XPB_RE = re.compile(r"X-Powered-By: PHP/(\S+)")
_LIBPHP_RE = re.compile(r"libphp(\d+(?:\.\d+)?)")


def version_from_php_v(text: str) -> Optional[str]:
    m = _PHP_V_RE.search(text or "")
    return m.group(1) if m else None


@dataclass
class _Block:
    tag: str
    args: List[str]
    sections: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class Inventory:
    reported_host: Optional[str] = None
    complete: bool = False
    bins: List[_Block] = field(default_factory=list)
    modules: List[_Block] = field(default_factory=list)
    sapi_inis: List[_Block] = field(default_factory=list)
    apache_confs: List[str] = field(default_factory=list)
    pools: List[Pool] = field(default_factory=list)


def parse_output(text: str) -> Inventory:
    inv = Inventory()
    block: Optional[_Block] = None
    pool_blocks: List[_Block] = []
    section = "body"
    for line in text.splitlines():
        if line.startswith("@@"):
            tag, _, rest = line[2:].partition(" ")
            if tag == "HOST":
                inv.reported_host = rest.strip() or None
            elif tag == "DONE":
                inv.complete = True
            elif tag == "APACHE_CONF":
                inv.apache_confs.append(rest.strip())
            elif tag in ("BIN", "MODULE", "SAPIINI", "POOL"):
                block = _Block(tag, rest.split(" "))
                section = "body"
                {"BIN": inv.bins, "MODULE": inv.modules, "SAPIINI": inv.sapi_inis, "POOL": pool_blocks}[tag].append(block)
            elif tag in ("V", "INFO") and block is not None:
                section = tag
            elif tag == "END":
                block = None
            continue
        if block is not None:
            block.sections.setdefault(section, []).append(line)
    pools: List[Pool] = []
    for pb in pool_blocks:
        pools.extend(parse_pool_file(" ".join(pb.args), "\n".join(pb.sections.get("body", []))))
    inv.pools = merge_pools(pools)
    return inv


def _pools_for(branch: Optional[str], pools: List[Pool]) -> List[Pool]:
    """Pools under a versioned directory (/etc/php/8.2/fpm) belong to that branch;
    pools in unversioned locations are attributed to every FPM install."""
    out = []
    for p in pools:
        m = re.search(r"/(?:php/?)?(\d)\.?(\d)/", p.path) or re.search(r"php(\d)(\d)/", p.path)
        if m and branch and "%s.%s" % (m.group(1), m.group(2)) != branch:
            continue
        out.append(p)
    return out


def results_from_inventory(inv: Inventory, target: str, mode: str) -> List[Result]:
    results: List[Result] = []
    for b in inv.bins:
        kind, path = b.args[0], " ".join(b.args[1:])
        vtext = "\n".join(b.sections.get("V", []))
        info = "\n".join(b.sections.get("INFO", []))
        data = parse_probe(info) if kind == "cli" else parse_phpinfo(info)
        version = version_from_php_v(vtext) or data.version
        sapi = sapi_kind(data.sapi, kind)
        pools = _pools_for(build_result(target, mode, version).branch, inv.pools) if sapi == "fpm" else []
        notes = []
        if not version:
            notes.append("binary did not report a version: %s" % (vtext.strip().splitlines() or ["no output"])[0][:120])
        results.append(build_result(target, mode, version, sapi=sapi, path=path,
                                    settings=data.settings, pools=pools, notes=notes))

    for m in inv.modules:
        path = " ".join(m.args)
        body = "\n".join(m.sections.get("body", []))
        mv = _XPB_RE.search(body)
        version = mv.group(1) if mv else None
        notes = ["version read from the string embedded in the module binary"] if version else []
        settings: Dict[str, str] = {}
        branch = None
        if version:
            branch = build_result(target, mode, version).branch
        else:
            lm = _LIBPHP_RE.search(path.rsplit("/", 1)[-1])
            if lm and "." in lm.group(1):
                version = lm.group(1)
                notes.append("only the branch is known, taken from the module file name")
            branch = lm.group(1) if lm and "." in lm.group(1) else None
        for s in inv.sapi_inis:
            if len(s.args) >= 2 and s.args[1] == branch:
                settings = parse_probe("\n".join(s.sections.get("INFO", []))).settings
                notes.append("settings read with %s via the CLI of the same branch" % " ".join(s.args[2:]))
        enabled = [c for c in inv.apache_confs if branch and branch in c] or inv.apache_confs
        if enabled:
            notes.append("Apache config loading PHP: %s" % ", ".join(enabled))
        if re.search(r"/(apache2?|httpd)/", path):
            sapi = "apache2handler"
        else:
            sapi = "embed"
            notes.append("libphp shared library outside an Apache module directory (embed SAPI)")
        results.append(build_result(target, mode, version, sapi=sapi, path=path,
                                    settings=settings, notes=notes,
                                    confidence="medium" if version else "none"))
    return results
