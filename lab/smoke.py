#!/usr/bin/env python3
"""Read-only check that the two local PHP lab targets have the expected setup."""

import json
import sys
import time
import urllib.error
import urllib.request


TARGETS = (("vulnerable", 18084, "8.4.26"), ("patched", 18085, "8.4.27"))


def check_target(name: str, port: int, version: str) -> None:
    url = f"http://127.0.0.1:{port}/index.php"
    last_error: Exception | None = None
    for _ in range(15):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                data = json.load(response)
            break
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(1)
    else:
        raise RuntimeError(f"{name} is unavailable at {url}: {last_error}")

    expected = {
        "lab": "php2shell",
        "php_version": version,
        "sapi": "apache2handler",
        "memory_limit": "8M",
        "post_max_size": "32M",
        "upload_progress_enabled": "1",
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise RuntimeError(
                f"{name}: expected {key}={value!r}, got {data.get(key)!r}"
            )
    print(f"{name}: PHP {version}, mod_php, expected lab settings OK ({url})")


def main() -> int:
    try:
        for target in TARGETS:
            check_target(*target)
    except RuntimeError as exc:
        print(f"Lab check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
