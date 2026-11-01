"""Pruebas unitarias del enumerador (core/enumerator.py)."""

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.enumerator import plan, load_rules, _service_key
from core.scanner import Port

RULES = load_rules(os.path.join(ROOT, "rules.json"))


class ServiceKeyTests(unittest.TestCase):
    def test_http_plain(self):
        p = Port(port=80, proto="tcp", service="http")
        self.assertEqual(_service_key(p, RULES["aliases"], RULES["services"]), "http")

    def test_http_over_tls_becomes_https(self):
        p = Port(port=443, proto="tcp", service="http", tunnel="ssl")
        self.assertEqual(_service_key(p, RULES["aliases"], RULES["services"]), "https")

    def test_alias_microsoft_ds_to_smb(self):
        p = Port(port=445, proto="tcp", service="microsoft-ds")
        self.assertEqual(_service_key(p, RULES["aliases"], RULES["services"]), "smb")

    def test_port_fallback_when_no_service(self):
        p = Port(port=3306, proto="tcp", service="")
        self.assertEqual(_service_key(p, RULES["aliases"], RULES["services"]), "mysql")

    def test_unknown_service_returns_none(self):
        p = Port(port=12345, proto="tcp", service="weirdthing")
        self.assertIsNone(_service_key(p, RULES["aliases"], RULES["services"]))


class PlanTests(unittest.TestCase):
    def test_plan_uses_https_for_tls(self):
        ports = [Port(port=443, proto="tcp", service="http",
                      product="nginx", tunnel="ssl")]
        actions = plan(ports, "10.0.0.1", RULES)
        self.assertTrue(actions)
        self.assertTrue(all(a.service == "https" for a in actions))
        self.assertTrue(any("https://10.0.0.1:443" in a.cmdline for a in actions))

    def test_malformed_rule_is_skipped(self):
        rules = {"aliases": {}, "services": {"http": [{"note": "sin tool ni cmd"}]}}
        ports = [Port(port=80, proto="tcp", service="http")]
        self.assertEqual(plan(ports, "x", rules), [])

    def test_load_rules_rejects_bad_structure(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"no_services": True}, fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                load_rules(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
