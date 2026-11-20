import re
import unittest

from sync_rules import parse_module, host_regex, render_outputs


def source(*rules):
    return f"#!desc=Rules:{len(rules)} Created:example\n[Rule]\n" + "\n".join(rules)


class ConverterTest(unittest.TestCase):
    def test_domain_mapping_and_stable_output(self):
        module = parse_module(source("DOMAIN-SUFFIX,Example.com,DIRECT", "DOMAIN,one.example.com,DIRECT"), "DIRECT")
        outputs = render_outputs({"DIRECT": module})
        self.assertEqual(outputs["direct-domains.txt"].splitlines()[1:], ["+.example.com", "one.example.com"])

    def test_repairs_known_upstream_malformed_rules(self):
        module = parse_module(source(
            "DOMAIN-SUFFIX,IP-CIDR,192.0.2.1/32,no-resolve,PROXY",
            "DOMAIN-SUFFIX,OMAIN-SUFFIX,bing.net,PROXY",
        ), "PROXY")
        self.assertEqual(module.repaired, 2)
        self.assertEqual(module.domains, {"+.bing.net"})
        self.assertEqual(module.networks, {"IP-CIDR,192.0.2.1/32,no-resolve"})

    def test_hostname_regex_preserves_bounds_and_domain_boundary(self):
        result = host_regex(r"^https?:\/\/(.*\.)?zayy([0-9]{0,3})?\.xyz.*$")
        self.assertNotIn(",", result)
        self.assertTrue(re.fullmatch(result, "cdn.ZAYY123.xyz"))
        self.assertFalse(re.fullmatch(result, "zayy1234.xyz"))
        self.assertFalse(re.fullmatch(result, "zayy1.xyz.example"))

    def test_reports_unrepresentable_filters(self):
        module = parse_module(source(
            "DOMAIN,example.com,PROXY",
            r'URL-REGEX,"^https?:\/\/example\.com\/path.*$",PROXY',
            "USER-AGENT,TikTok*,PROXY",
        ), "PROXY")
        self.assertEqual(module.skipped, {"URL-REGEX": 1, "USER-AGENT": 1})

    def test_fails_before_publishing_on_a_partial_or_changed_module(self):
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            parse_module("#!desc=Rules:2\n[Rule]\nDOMAIN,example.com,DIRECT", "DIRECT")
        with self.assertRaisesRegex(ValueError, "Expected routing target"):
            parse_module(source("DOMAIN,example.com,PROXY"), "DIRECT")


if __name__ == "__main__":
    unittest.main()
