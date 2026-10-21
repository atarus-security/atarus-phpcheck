import unittest

from phpcheck.advisories import Advisory
from phpcheck.versions import (EOL, FIXED, UNKNOWN, VULNERABLE, assess, compare,
                               fix_table, parse_version)


class ParseVersion(unittest.TestCase):
    def test_plain(self):
        v = parse_version("8.2.35")
        self.assertEqual((v.major, v.minor, v.patch, v.pre, v.extra), (8, 2, 35, None, ""))

    def test_php_v_banner(self):
        v = parse_version("PHP 8.3.14 (cli) (built: Nov 19 2024 15:14:35) (NTS)")
        self.assertEqual(v.upstream, "8.3.14")

    def test_debian_suffix(self):
        v = parse_version("8.2.28-1~deb12u1")
        self.assertEqual((v.patch, v.extra, v.upstream), (28, "-1~deb12u1", "8.2.28"))
        self.assertTrue(v.is_vendor_build)
        self.assertFalse(v.is_prerelease)

    def test_ubuntu_and_sury_suffixes(self):
        self.assertEqual(parse_version("8.1.2-1ubuntu2.20").extra, "-1ubuntu2.20")
        v = parse_version("8.3.14-1+0~20241119.55+debian12~1.gbp5b2b1a")
        self.assertEqual((v.upstream, v.is_vendor_build), ("8.3.14", True))

    def test_release_candidates(self):
        for raw, pre, num in (("8.5.12RC1", "rc", 1), ("8.4.0rc2", "rc", 2), ("8.5.0alpha3", "alpha", 3),
                              ("8.5.0beta1", "beta", 1), ("8.5.13-dev", "dev", 0)):
            v = parse_version(raw)
            self.assertEqual((v.pre, v.prenum), (pre, num), raw)
            self.assertTrue(v.is_prerelease)

    def test_branch_only(self):
        v = parse_version("7.4")
        self.assertEqual((v.branch, v.patch), ((7, 4), None))

    def test_garbage(self):
        for raw in (None, "", "nginx", "PHP", "1.2.3"):
            self.assertIsNone(parse_version(raw), raw)

    def test_ordering(self):
        self.assertEqual(compare("8.5.12RC1", "8.5.12"), -1)
        self.assertEqual(compare("8.5.12-dev", "8.5.12alpha1"), -1)
        self.assertEqual(compare("8.5.12alpha1", "8.5.12beta1"), -1)
        self.assertEqual(compare("8.5.12beta2", "8.5.12RC1"), -1)
        self.assertEqual(compare("8.5.13-dev", "8.5.12"), 1)
        self.assertEqual(compare("8.2.35", "8.2.35-1~deb12u1"), 0)
        self.assertEqual(compare("8.2.9", "8.2.10"), -1)
        self.assertEqual(compare("8.10.0", "8.9.99"), 1)


class Assess(unittest.TestCase):
    def check(self, raw, status, fixed_in=None):
        a = assess(raw)
        self.assertEqual(a.status, status, raw)
        if fixed_in is not None:
            self.assertEqual(a.fixed_in, fixed_in, raw)
        return a

    def test_every_supported_branch(self):
        table = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
        for branch, patch in table.items():
            fixed = "%s.%d" % (branch, patch)
            self.check("%s.%d" % (branch, patch - 1), VULNERABLE, fixed)
            self.check("%s.0" % branch, VULNERABLE, fixed)
            self.check(fixed, FIXED, fixed)
            self.check("%s.%d" % (branch, patch + 1), FIXED, fixed)

    def test_named_edges(self):
        self.check("8.1.33", EOL, "none (EOL)")
        self.check("8.2.34", VULNERABLE, "8.2.35")
        self.check("8.2.35", FIXED, "8.2.35")
        self.check("8.5.12", FIXED, "8.5.12")
        self.check("7.4", EOL, "none (EOL)")
        self.check("7.4.33", EOL)
        self.check("8.0.30", EOL)
        self.check("5.6.40", EOL)

    def test_affected_list(self):
        self.assertEqual(assess("8.4.26").affected_by, ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertEqual(assess("8.4.27").affected_by, [])
        self.assertEqual(assess("8.1.33").affected_by, ["CVE-2026-109618", "CVE-2026-109619"])

    def test_release_candidates(self):
        a = self.check("8.5.12RC1", VULNERABLE)
        self.assertTrue(any("pre-release" in n for n in a.notes))
        self.check("8.4.27RC1", VULNERABLE)
        self.check("8.5.12-dev", VULNERABLE)
        self.check("8.5.13RC1", FIXED)
        self.check("8.5.13-dev", FIXED)
        self.check("8.1.0RC1", EOL)

    def test_debian_style(self):
        a = self.check("8.2.28-1~deb12u1", VULNERABLE, "8.2.35")
        self.assertTrue(any("vendor" in n for n in a.notes))
        self.check("8.2.35-1~deb12u1", FIXED)
        self.check("8.1.2-1ubuntu2.20", EOL)

    def test_branch_only_supported_is_unknown(self):
        self.check("8.3", UNKNOWN)

    def test_newer_branch_assumed_fixed(self):
        a = self.check("8.6.0", FIXED, "n/a")
        self.assertTrue(any("newer" in n for n in a.notes))
        self.check("9.0.1", FIXED)

    def test_unparseable(self):
        self.check(None, UNKNOWN)
        self.check("not a version", UNKNOWN)


class TableIsData(unittest.TestCase):
    def test_new_advisory_is_one_line(self):
        advs = (
            Advisory("CVE-2026-109618", "GHSA-x", "a", "2026-10-21", {"8.2": "8.2.35", "8.5": "8.5.12"}),
            Advisory("CVE-2099-0001", "GHSA-y", "b", "2099-01-01", {"8.2": "8.2.40", "8.5": "8.5.20"}),
        )
        self.assertEqual(assess("8.2.36", advs).status, VULNERABLE)
        self.assertEqual(assess("8.2.36", advs).affected_by, ["CVE-2099-0001"])
        self.assertEqual(assess("8.2.36", advs).fixed_in, "8.2.40")
        self.assertEqual(assess("8.2.40", advs).status, FIXED)

    def test_advisory_not_affecting_older(self):
        advs = (Advisory("CVE-2099-0002", "GHSA-z", "c", "2099-01-01", {"8.5": "8.5.20"}, affects_older=False),)
        self.assertEqual(assess("8.4.1", advs).status, FIXED)
        self.assertEqual(assess("8.5.19", advs).status, VULNERABLE)

    def test_fix_table(self):
        rows = fix_table()
        self.assertEqual([r[:2] for r in rows],
                         [("8.5", "8.5.12"), ("8.4", "8.4.27"), ("8.3", "8.3.36"), ("8.2", "8.2.35")])


if __name__ == "__main__":
    unittest.main()
