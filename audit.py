#!/usr/bin/env python3
"""Read-only PHP release assessment for an operator-supplied version or URL.

This sends at most one ordinary GET and does not attempt either CVE. A release
range is an inventory signal, not evidence that an installation is exploitable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
VERSION = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(?:[+._~-].*)?\s*$")
POWERED_BY = re.compile(r"(?:^|\s|;)PHP/(\d+\.\d+\.\d+(?:[+._~-][^\s;]*)?)", re.I)
MAX_BODY = 65536


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def assess(version: str | None) -> tuple[str, str]:
    if not version:
        return "unknown", "PHP version was not available from the supplied evidence"
    match = VERSION.fullmatch(version)
    if not match:
        return "unknown", "PHP version could not be parsed"
    major, minor, patch = map(int, match.groups())
    fixed_patch = FIXED.get((major, minor))
    if fixed_patch is None:
        return "unknown", "This PHP branch is outside the four advisory release ranges"
    if patch < fixed_patch:
        return "upstream_affected_range", (
            f"Upstream PHP {major}.{minor} was fixed in {major}.{minor}.{fixed_patch}; "
            "vendor backports and deployment reachability require separate verification"
        )
    return "upstream_fixed_range", (
        f"This version is at or after upstream PHP {major}.{minor}.{fixed_patch}; "
        "confirm the installed package and running workers"
    )


def inspect_url(url: str, timeout: float) -> tuple[str | None, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("URL must be HTTP(S) with a host and without embedded credentials")
    opener = build_opener(NoRedirect())
    request = Request(url, headers={"User-Agent": "php2shell-release-audit/1.0"}, method="GET")
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    with response:
        status = response.status
        header = response.headers.get("X-Powered-By", "")
        header_match = POWERED_BY.search(header)
        version = header_match.group(1) if header_match else None
        source = "X-Powered-By" if version else "none"
        if response.headers.get_content_type() == "application/json":
            body = response.read(MAX_BODY + 1)
            if len(body) <= MAX_BODY:
                try:
                    data = json.loads(body)
                except (UnicodeDecodeError, ValueError):
                    data = None
                if isinstance(data, dict) and isinstance(data.get("php_version"), str):
                    version = data["php_version"]
                    source = "JSON php_version field"
    return version, source, status


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only PHP release assessment; no CVE payloads")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--url", help="Operator-supplied HTTP(S) endpoint; one GET only")
    choice.add_argument("--php-version", help="Installed PHP version obtained from a trusted inventory")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()
    if not 0 < args.timeout <= 30:
        parser.error("--timeout must be between 0 and 30 seconds")

    result: dict[str, object] = {"cves": CVES, "target": args.url or "operator inventory"}
    try:
        if args.url:
            version, source, status = inspect_url(args.url, args.timeout)
            result.update({"http_status": status, "version_source": source})
        else:
            version, source = args.php_version, "operator inventory"
            result["version_source"] = source
        assessment, explanation = assess(version)
        result.update({"php_version": version, "assessment": assessment,
                       "explanation": explanation,
                       "exploitability": "not_tested"})
    except (OSError, URLError, ValueError) as exc:
        result.update({"php_version": None, "assessment": "unknown",
                       "exploitability": "not_tested", "error": str(exc)})
        print(json.dumps(result, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
