"""HackerOne Hacker API client for reading a program's structured scope.

Authentication is HTTP Basic: the API token identifier is the username and the
token value is the password. Credentials are read from the environment
(H1_API_USERNAME / H1_API_TOKEN) so they never appear in shell history or
process listings.

Endpoint: GET /v1/hackers/programs/{handle}/structured_scopes (JSON:API,
paginated through links.next). Structured scope reads are limited to 50
requests per minute, so calls are spaced at least MIN_INTERVAL seconds apart.
"""

import base64
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode, urljoin, urlparse

API_BASE = "https://api.hackerone.com/v1"
USERNAME_ENV = "H1_API_USERNAME"
TOKEN_ENV = "H1_API_TOKEN"
USER_AGENT = "BugHunterPro-H1Research/2.0 (authorized bug bounty assessment)"

# Asset types that can be turned into hostnames for probing. Everything else
# (CIDR, API, ANDROID, OTHER, ...) is reported as skipped.
SUPPORTED_ASSET_TYPES = {"URL", "WILDCARD", "DOMAIN"}

PAGE_SIZE = 100
MAX_PAGES = 50
MIN_INTERVAL = 1.2
MAX_RETRIES = 3
MAX_RETRY_AFTER = 120


class HackerOneError(Exception):
    """Raised for missing credentials, API errors, or an unusable response."""


def _urllib_fetch(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", errors="ignore")


def _describe_error(status):
    # Never echo the response body or request headers: they may contain secrets.
    messages = {
        401: "authentication failed (401): check H1_API_USERNAME and H1_API_TOKEN",
        403: "forbidden (403): the token lacks access to this program, or the IP allowlist blocks this host",
        404: "program not found (404): check the program handle",
    }
    return messages.get(status, f"HackerOne API returned HTTP {status}")


def _retry_after(headers):
    try:
        seconds = int(headers.get("Retry-After", 60))
    except (TypeError, ValueError):
        seconds = 60
    return min(max(seconds, 1), MAX_RETRY_AFTER)


class HackerOneClient:
    def __init__(self, username, token, base_url=API_BASE, fetch=_urllib_fetch,
                 sleep=time.sleep, clock=time.monotonic, timeout=30):
        if not username or not token:
            raise HackerOneError(
                f"HackerOne credentials missing: set {USERNAME_ENV} and {TOKEN_ENV}"
            )
        self._base = base_url.rstrip("/")
        self._netloc = urlparse(self._base).netloc
        self._auth = "Basic " + base64.b64encode(f"{username}:{token}".encode()).decode()
        self._fetch = fetch
        self._sleep = sleep
        self._clock = clock
        self._timeout = timeout
        self._last_call = None

    @classmethod
    def from_env(cls, **kwargs):
        return cls(os.environ.get(USERNAME_ENV, ""), os.environ.get(TOKEN_ENV, ""), **kwargs)

    def _throttle(self):
        if self._last_call is not None:
            wait = MIN_INTERVAL - (self._clock() - self._last_call)
            if wait > 0:
                self._sleep(wait)
        self._last_call = self._clock()

    def _get_json(self, url):
        # Refuse to send credentials anywhere except the configured API host.
        if urlparse(url).netloc != self._netloc:
            raise HackerOneError("refusing to send credentials to a non-HackerOne host")

        headers = {"Authorization": self._auth, "Accept": "application/json", "User-Agent": USER_AGENT}
        for attempt in range(MAX_RETRIES + 1):
            self._throttle()
            status, resp_headers, body = self._fetch(url, headers, self._timeout)
            if status == 429:
                if attempt == MAX_RETRIES:
                    break
                self._sleep(_retry_after(resp_headers))
                continue
            if status != 200:
                raise HackerOneError(_describe_error(status))
            try:
                return json.loads(body)
            except json.JSONDecodeError as e:
                raise HackerOneError(f"HackerOne returned invalid JSON: {e}") from e
        raise HackerOneError("HackerOne rate limit (429) persisted after retries")

    def get_structured_scopes(self, handle):
        """Return the raw structured-scope items for a program, across all pages."""
        if not handle or "/" in handle or handle != handle.strip():
            raise HackerOneError(f"invalid program handle: {handle!r}")

        path = f"/hackers/programs/{quote(handle, safe='')}/structured_scopes"
        url = f"{self._base}{path}?{urlencode({'page[size]': PAGE_SIZE})}"
        items = []
        for _ in range(MAX_PAGES):
            payload = self._get_json(url)
            items.extend(payload.get("data") or [])
            next_url = (payload.get("links") or {}).get("next")
            if not next_url:
                return items
            next_url = urljoin(url, next_url)
            if next_url == url:
                break
            url = next_url
        raise HackerOneError(
            f"structured scope for {handle!r} spans more than {MAX_PAGES} pages; refusing a partial scope"
        )


def scope_identifiers(items):
    """Split raw scope items into (identifiers, skipped).

    Only assets marked eligible_for_submission with a supported asset type are
    kept. Ineligible assets are skipped, since they are in scope for research
    but not for submissions, and testing them is not what the program wants.
    """
    keep = []
    skipped = []
    for item in items:
        attrs = item.get("attributes") or {}
        identifier = (attrs.get("asset_identifier") or "").strip()
        asset_type = (attrs.get("asset_type") or "").upper()
        if not attrs.get("eligible_for_submission"):
            skipped.append({"asset": identifier, "reason": "not eligible for submission"})
        elif asset_type not in SUPPORTED_ASSET_TYPES:
            skipped.append({"asset": identifier, "reason": f"unsupported asset type {asset_type or 'unknown'}"})
        elif identifier:
            keep.append(identifier)
    return keep, skipped
