#!/usr/bin/env python3

from __future__ import annotations

import unittest

from pyfaup import Url


class TestPyFaupRR(unittest.TestCase):

    def test_url(self) -> None:
        parsed_url = Url('https://user:pass@sub.example.com:8080/path?query=value#fragment')

        self.assertEqual(parsed_url.scheme, 'https')
        self.assertEqual(parsed_url.username, 'user')
        self.assertEqual(parsed_url.password, 'pass')
        self.assertEqual(parsed_url.host, 'sub.example.com')
        self.assertEqual(parsed_url.subdomain, 'sub')
        self.assertEqual(parsed_url.domain, 'example.com')
        self.assertEqual(parsed_url.suffix, 'com')
        self.assertEqual(parsed_url.port, 8080)
        self.assertEqual(parsed_url.path, '/path')
        self.assertEqual(parsed_url.query, 'query=value')
        self.assertEqual(parsed_url.fragment, 'fragment')
