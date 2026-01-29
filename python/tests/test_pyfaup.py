#!/usr/bin/env python3

from __future__ import annotations

import unittest

from pyfaup import Host, Hostname, Url


class TestPyFaupRR(unittest.TestCase):
    def test_url(self) -> None:
        parsed_url = Url(
            "https://user:pass@sub.example.com:8080/path?query=value#fragment"
        )

        self.assertEqual(
            parsed_url.orig,
            "https://user:pass@sub.example.com:8080/path?query=value#fragment",
        )

        self.assertEqual(parsed_url.scheme, "https")
        self.assertEqual(parsed_url.username, "user")
        self.assertEqual(parsed_url.password, "pass")
        self.assertEqual(parsed_url.host, "sub.example.com")
        self.assertEqual(parsed_url.subdomain, "sub")
        self.assertEqual(parsed_url.domain, "example.com")
        self.assertEqual(parsed_url.suffix, "com")
        self.assertEqual(parsed_url.port, 8080)
        self.assertEqual(parsed_url.path, "/path")
        self.assertEqual(parsed_url.query, "query=value")
        self.assertEqual(parsed_url.fragment, "fragment")

    def test_hostname(self) -> None:
        hn = Hostname("sub.example.com")
        self.assertEqual(hn.subdomain, "sub")
        self.assertEqual(hn.domain, "example.com")
        self.assertEqual(str(hn.suffix), "com")
        if hn.suffix is not None:
            self.assertTrue(hn.suffix.is_known())
        self.assertEqual(str(hn), "sub.example.com")

        with self.assertRaises(ValueError):
            Hostname("192.168.1.1")

    def test_unknown_suffix(self) -> None:
        hn = Hostname("test.custom-tld")
        if hn.suffix is not None:
            self.assertFalse(hn.suffix.is_known())

        hn = Hostname("SSH-2.0-OpenSSH_9.2p1")
        if hn.suffix is not None:
            self.assertFalse(hn.suffix.is_known())
            
        hn = Hostname("laptop.local")
        if hn.suffix is not None:
            self.assertFalse(hn.suffix.is_known())

    def test_host(self) -> None:
        # Test hostname
        host = Host("sub.example.com")
        self.assertTrue(host.is_hostname())
        self.assertFalse(host.is_ip_addr())
        self.assertFalse(host.is_ipv4())
        self.assertFalse(host.is_ipv6())
        self.assertEqual(str(host), "sub.example.com")

        # Test IPv4
        host = Host("192.168.1.1")
        self.assertFalse(host.is_hostname())
        self.assertTrue(host.is_ip_addr())
        self.assertTrue(host.is_ipv4())
        self.assertFalse(host.is_ipv6())
        self.assertEqual(str(host), "192.168.1.1")
        self.assertEqual(host.try_into_ip(), "192.168.1.1")
        with self.assertRaises(ValueError):
            host.try_into_hostname()

        # Test IPv6
        host = Host("::1")
        self.assertFalse(host.is_hostname())
        self.assertTrue(host.is_ip_addr())
        self.assertFalse(host.is_ipv4())
        self.assertTrue(host.is_ipv6())
        self.assertEqual(str(host), "::1")
        self.assertEqual(host.try_into_ip(), "::1")
        with self.assertRaises(ValueError):
            host.try_into_hostname()

        # Test hostname conversion
        host = Host("sub.example.com")
        hn = host.try_into_hostname()
        self.assertEqual(str(hn), "sub.example.com")
        self.assertEqual(hn.subdomain, "sub")
        self.assertEqual(hn.domain, "example.com")
        self.assertEqual(str(hn.suffix), "com")
        with self.assertRaises(ValueError):
            host.try_into_ip()

        # Test invalid host
        with self.assertRaises(ValueError):
            Host("invalid host")


if __name__ == "__main__":
    unittest.main()
