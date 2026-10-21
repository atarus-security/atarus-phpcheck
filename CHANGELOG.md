# Changelog

All notable changes to this project are listed here. Versions follow semantic versioning.

## 0.1.0 (2026-10-21)

First release.

- Checks for CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp). Fixed releases 8.5.12, 8.4.27, 8.3.36 and 8.2.35, verified against the php-src advisories. PHP 8.1 and older are reported as end-of-life-unfixed.
- Advisory table kept as data in `phpcheck/advisories.py`, one line per CVE.
- `local` mode: read-only inventory of PHP binaries, SAPIs, `libphp` modules, the settings named in the advisories, and FPM pool `pm.max_requests`.
- `remote` mode: passive HEAD and GET checks of `X-Powered-By`, `Server` and PHP session cookies, plus HEAD-only presence checks of common phpinfo paths with a soft-404 baseline. Rate limited.
- `image` mode: `docker run --rm --network none --entrypoint php <image> -v`, the settings probe, and an optional in-container inventory.
- `fleet` mode: the local inventory over `ssh -o BatchMode=yes`, aggregated across hosts.
- Table output by default, `--json`, `--explain`, `--fail-on-unknown`. Exit code 1 when anything is vulnerable or end of life.
- Handles release candidates, `-dev` builds and vendor version suffixes such as `-1~deb12u1`.
- Standard library only. Runs with `python3 -m phpcheck` on Python 3.9 and newer.
