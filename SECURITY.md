# Security policy

## Reporting a vulnerability

Please report security issues in atarus-phpcheck privately by email to security@atarussecurity.com, with "atarus-phpcheck" in the subject. Do not open a public GitHub issue for a vulnerability. The same contact and our disclosure terms are published at https://atarussecurity.com/security/ and in https://atarussecurity.com/.well-known/security.txt.

Include:

- the version (`python3 -m phpcheck --version`) or commit you tested
- what you ran, what happened, and a proof of concept if you have one
- the impact you expect

We aim to acknowledge reports within two business days and to agree a fix and disclosure date with you. We are happy to credit reporters who want credit.

## Supported versions

Only the latest release on the default branch receives security fixes. Keep the advisory table current by updating to the latest release, or add new CVEs yourself as described in the README.

## Scope

In scope: the code in this repository and the reports it generates.

Out of scope: the `docker` and `ssh` binaries and the PHP binaries this tool runs, the images and hosts it inspects, and findings that require an attacker who already controls the machine running the tool.

## Using this tool

`local` and `image` only touch this machine: a read-only inventory of the host, or `docker run` of an image that is already present, with no network, a read-only filesystem, no capabilities and a non-root user. `remote` and `fleet` touch other hosts, so they run only against hosts inside a `--scope` you provide, after you type `yes` on the terminal (or pass `--yes` together with `--scope` for scripted runs). Only use them against hosts you own or are authorized in writing to test.

Treat as a security bug and report it: any request or ssh session to a host outside `--scope`, any way to pass the confirmation gate other than typing `yes` on the terminal or the documented `--yes` flag, any `docker run` that pulls an image or runs without the documented hardening flags, any request beyond the ordinary HEAD and GET requests the README describes (in particular anything that could trigger CVE-2026-109618 or CVE-2026-109619 on a target), command or option injection through target names, image names, host lists or data returned by a target, a control character from a target reaching the terminal or a report unescaped, output that reports a vulnerable version as fixed or reads as clean for a check that did not run, leaking local data (paths, environment, credentials) to a target, and any network destination not listed in the README's network table.

## Safe harbour

Good-faith research against your own installation of this tool, within the terms above, will not be reported to law enforcement or pursued legally by us. Testing against hosts you do not own or administer is not covered and is not something this tool should be used for.

## Reporting a problem in PHP

This tool does not handle PHP vulnerabilities. Report those to the PHP project through https://github.com/php/php-src/security.
