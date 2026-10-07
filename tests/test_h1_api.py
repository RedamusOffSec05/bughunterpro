#!/usr/bin/env python3
"""Unit tests for h1_api. The HTTP transport is faked, so no network is used."""

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import h1_api
from h1_api import HackerOneClient, HackerOneError, scope_identifiers

BASE = h1_api.API_BASE
HANDLE = "example-program"
FIRST_PAGE = f"{BASE}/hackers/programs/{HANDLE}/structured_scopes?page%5Bsize%5D=100"


class FakeFetch:
    """Returns queued (status, headers, body) tuples and records each request."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        return self.responses.pop(0)


def _ok(payload):
    import json
    return 200, {}, json.dumps(payload)


def _client(fetch, **kwargs):
    sleeps = []
    clock_value = [1000.0]

    def clock():
        return clock_value[0]

    def sleep(seconds):
        sleeps.append(seconds)
        clock_value[0] += seconds

    client = HackerOneClient("user", "tok", fetch=fetch, sleep=sleep, clock=clock, **kwargs)
    return client, sleeps


def _item(identifier, asset_type="URL", eligible=True):
    return {"attributes": {"asset_identifier": identifier, "asset_type": asset_type,
                           "eligible_for_submission": eligible}}


class TestCredentials(unittest.TestCase):
    def test_missing_credentials_raise(self):
        with self.assertRaises(HackerOneError) as ctx:
            HackerOneClient("", "")
        self.assertIn("H1_API_USERNAME", str(ctx.exception))

    def test_from_env_reads_environment(self):
        import os
        from unittest import mock
        env = {"H1_API_USERNAME": "u", "H1_API_TOKEN": "t"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = HackerOneClient.from_env(fetch=FakeFetch([_ok({"data": []})]))
        self.assertIsNotNone(client)

    def test_from_env_without_variables_raises(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(HackerOneError):
            HackerOneClient.from_env()

    def test_basic_auth_header_sent(self):
        fetch = FakeFetch([_ok({"data": []})])
        client, _ = _client(fetch)
        client.get_structured_scopes(HANDLE)
        expected = "Basic " + base64.b64encode(b"user:tok").decode()
        self.assertEqual(fetch.calls[0][1]["Authorization"], expected)


class TestStructuredScopes(unittest.TestCase):
    def test_request_url_and_page_size(self):
        fetch = FakeFetch([_ok({"data": []})])
        client, _ = _client(fetch)
        client.get_structured_scopes(HANDLE)
        self.assertEqual(fetch.calls[0][0], FIRST_PAGE)

    def test_follows_pagination_links(self):
        page_two = f"{BASE}/hackers/programs/{HANDLE}/structured_scopes?page%5Bnumber%5D=2"
        fetch = FakeFetch([
            _ok({"data": [_item("a.example.com")], "links": {"next": page_two}}),
            _ok({"data": [_item("b.example.com")], "links": {}}),
        ])
        client, _ = _client(fetch)
        items = client.get_structured_scopes(HANDLE)
        self.assertEqual([i["attributes"]["asset_identifier"] for i in items],
                         ["a.example.com", "b.example.com"])
        self.assertEqual(fetch.calls[1][0], page_two)

    def test_relative_next_link_is_resolved(self):
        fetch = FakeFetch([
            _ok({"data": [], "links": {"next": "/v1/hackers/programs/x/structured_scopes?page=2"}}),
            _ok({"data": []}),
        ])
        client, _ = _client(fetch)
        client.get_structured_scopes(HANDLE)
        self.assertEqual(fetch.calls[1][0], "https://api.hackerone.com/v1/hackers/programs/x/structured_scopes?page=2")

    def test_refuses_to_send_credentials_to_other_host(self):
        fetch = FakeFetch([
            _ok({"data": [], "links": {"next": "https://attacker.example/steal"}}),
        ])
        client, _ = _client(fetch)
        with self.assertRaises(HackerOneError):
            client.get_structured_scopes(HANDLE)
        self.assertEqual(len(fetch.calls), 1)

    def test_page_limit_is_enforced(self):
        looping = f"{BASE}/hackers/programs/{HANDLE}/structured_scopes?page=next"
        responses = [_ok({"data": [], "links": {"next": looping}})] * 2
        fetch = FakeFetch(responses)
        client, _ = _client(fetch)
        original = h1_api.MAX_PAGES
        h1_api.MAX_PAGES = 1
        try:
            with self.assertRaises(HackerOneError):
                client.get_structured_scopes(HANDLE)
        finally:
            h1_api.MAX_PAGES = original

    def test_invalid_handle_rejected_before_request(self):
        fetch = FakeFetch([])
        client, _ = _client(fetch)
        for bad in ["", "../etc", "a/b", " spaced "]:
            with self.assertRaises(HackerOneError):
                client.get_structured_scopes(bad)
        self.assertEqual(fetch.calls, [])


class TestErrors(unittest.TestCase):
    def test_401_message_does_not_leak_token(self):
        fetch = FakeFetch([(401, {}, "unauthorized body")])
        client, _ = _client(fetch)
        with self.assertRaises(HackerOneError) as ctx:
            client.get_structured_scopes(HANDLE)
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn("tok", str(ctx.exception))

    def test_404_reports_program_not_found(self):
        fetch = FakeFetch([(404, {}, "")])
        client, _ = _client(fetch)
        with self.assertRaises(HackerOneError) as ctx:
            client.get_structured_scopes(HANDLE)
        self.assertIn("program not found", str(ctx.exception))

    def test_429_honours_retry_after_then_succeeds(self):
        fetch = FakeFetch([(429, {"Retry-After": "7"}, ""), _ok({"data": [_item("a.example.com")]})])
        client, sleeps = _client(fetch)
        items = client.get_structured_scopes(HANDLE)
        self.assertEqual(len(items), 1)
        self.assertIn(7, sleeps)

    def test_429_persisting_raises(self):
        fetch = FakeFetch([(429, {}, "")] * (h1_api.MAX_RETRIES + 1))
        client, _ = _client(fetch)
        with self.assertRaises(HackerOneError):
            client.get_structured_scopes(HANDLE)

    def test_invalid_json_raises(self):
        fetch = FakeFetch([(200, {}, "<html>not json</html>")])
        client, _ = _client(fetch)
        with self.assertRaises(HackerOneError):
            client.get_structured_scopes(HANDLE)

    def test_requests_are_spaced_by_min_interval(self):
        page_two = f"{BASE}/hackers/programs/{HANDLE}/structured_scopes?page=2"
        fetch = FakeFetch([_ok({"data": [], "links": {"next": page_two}}), _ok({"data": []})])
        client, sleeps = _client(fetch)
        client.get_structured_scopes(HANDLE)
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], h1_api.MIN_INTERVAL, places=6)


class TestScopeFiltering(unittest.TestCase):
    def test_keeps_eligible_supported_assets(self):
        items = [
            _item("app.example.com", "URL"),
            _item("*.example.com", "WILDCARD"),
            _item("example.com", "DOMAIN"),
        ]
        keep, skipped = scope_identifiers(items)
        self.assertEqual(keep, ["app.example.com", "*.example.com", "example.com"])
        self.assertEqual(skipped, [])

    def test_skips_ineligible_and_unsupported_types(self):
        items = [
            _item("app.example.com", "URL", eligible=False),
            _item("10.0.0.0/8", "CIDR"),
            _item("com.example.android", "ANDROID"),
        ]
        keep, skipped = scope_identifiers(items)
        self.assertEqual(keep, [])
        self.assertEqual(len(skipped), 3)
        self.assertEqual(skipped[0]["reason"], "not eligible for submission")
        self.assertIn("CIDR", skipped[1]["reason"])

    def test_asset_type_is_case_insensitive(self):
        keep, _ = scope_identifiers([_item("app.example.com", "url")])
        self.assertEqual(keep, ["app.example.com"])

    def test_empty_identifier_is_dropped(self):
        keep, _ = scope_identifiers([_item("   ", "URL")])
        self.assertEqual(keep, [])


if __name__ == "__main__":
    unittest.main()
