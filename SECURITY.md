# Security policy

## Reporting a problem in atarus-phpcheck

Email info@atarussecurity.com with "atarus-phpcheck" in the subject. Include the version (`python3 -m phpcheck --version`), what you ran, and what happened. Please do not open a public issue for anything that could put users at risk.

We aim to acknowledge reports within three working days and to ship a fix, or explain why we will not, within thirty days.

Things we treat as security problems:

- Any way the tool sends a request or runs a command beyond what the README describes, in particular anything that could trigger CVE-2026-109618 or CVE-2026-109619 on a target.
- Command or option injection through target names, image names, host lists or data returned by a target.
- Output that reports a vulnerable version as fixed.
- Leaking local data (paths, environment, credentials) to a remote target.

## Reporting a problem in PHP

This tool does not handle PHP vulnerabilities. Report those to the PHP project through https://github.com/php/php-src/security.

## Supported versions

Only the latest release receives fixes. Keep the advisory table current by updating to the latest release, or add new CVEs yourself as described in the README.
