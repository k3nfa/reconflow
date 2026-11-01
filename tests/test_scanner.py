"""Pruebas unitarias del escáner (core/scanner.py): parseo XML y errores."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import parse_nmap_xml

GOOD_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="9.6p1"/></port>
<port protocol="tcp" portid="443"><state state="open"/>
  <service name="http" product="nginx" tunnel="ssl"/></port>
<port protocol="tcp" portid="3306"><state state="closed"/>
  <service name="mysql"/></port>
</ports></host>
</nmaprun>"""


class ParseTests(unittest.TestCase):
    def test_open_ports_only(self):
        scan = parse_nmap_xml(GOOD_XML, "10.0.0.1")
        self.assertEqual({p.port for p in scan.ports}, {22, 443})

    def test_version_banner(self):
        scan = parse_nmap_xml(GOOD_XML)
        ssh = next(p for p in scan.ports if p.port == 22)
        self.assertIn("OpenSSH", ssh.banner)
        self.assertIn("9.6p1", ssh.banner)

    def test_tls_detection_via_tunnel(self):
        scan = parse_nmap_xml(GOOD_XML)
        https = next(p for p in scan.ports if p.port == 443)
        self.assertTrue(https.is_tls)

    def test_empty_xml_raises(self):
        with self.assertRaises(RuntimeError):
            parse_nmap_xml("", "x")

    def test_invalid_xml_raises_runtime(self):
        with self.assertRaises(RuntimeError):
            parse_nmap_xml("<not-closed", "x")

    def test_port_without_id_skipped(self):
        xml = ('<nmaprun><host><ports><port protocol="tcp">'
               '<state state="open"/></port></ports></host></nmaprun>')
        scan = parse_nmap_xml(xml, "x")
        self.assertEqual(scan.ports, [])


if __name__ == "__main__":
    unittest.main()
