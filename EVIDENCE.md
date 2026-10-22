# PHP2Shell proof record

## Claim and boundary

**CVE-2026-109619, demonstrated session-state case.** An unauthenticated
multipart request makes PHP publish request-owned session state before normal
initialization. A fatal allocation failure interrupts cleanup. The same Apache
worker processes another multipart request while that state still refers to
freed memory. The client reclaims and steers the state into a native call; the
observable consequence is a proof file written by the PHP worker. This matches
the PHP project's [stale-global-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

```text
multipart input → session upload-progress state → fatal interruption
               → request memory freed → next request on same worker
               → stale session state consumed → fixed proof command
```

**CVE-2026-109618, independently reproduced as a controlled shutdown crash.**
Its distinct claim is that OOM interrupts an operation while request data is
partially initialized; shutdown then consumes the invalid data. A separate
four-case test now shows OOM in every case, but SIGSEGV only when a fixed
sentinel value is present on the vulnerable build. A debugger places that
crash in `zend_array_destroy()` called by `php_request_shutdown()`. The
[PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [Red Hat technical report](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2026-109618)
support the partial HashTable insertion mechanism. Our runtime evidence shows
the input-dependent shutdown corruption; it does not show RCE for this CVE.

## CVE-2026-109619 test contract

| Item | Recorded condition |
| --- | --- |
| Target | Official PHP Apache images pinned in `compose.yaml` |
| Positive build | PHP 8.4.26, Apache 2.4.68, mod_php prefork |
| Negative build | PHP 8.4.27, Apache 2.4.68, same lab configuration |
| Entry point | Unauthenticated HTTP multipart POST to `/index.php` |
| Relevant settings | `memory_limit=8M`, `post_max_size=32M`, upload progress enabled, one worker |
| Consequence required | New `/out/p1` file with the worker identity |
| Stop condition | Bounded leak and execution retries, then `not_observed` or `inconclusive` |

The result file is removed before each target run. The fixed command is
`id>/out/p1`; it does not depend on application code. The same script and
request shapes are used against the patched control. The PHP versions are
verified from each running HTTP endpoint before execution, while offsets are
read from each container's loaded PHP module. No mock PHP implementation is
used for the end-to-end result.

## CVE-2026-109619 observed run

The latest machine-readable result is in `artifacts/last-run.json`, and the
positive proof is in `artifacts/vulnerable/p1`. A completed local run showed:

- PHP 8.4.26: heap and library disclosures followed by a proof file containing
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.
- PHP 8.4.27: the required heap disclosure was not observed in three attempts;
  no proof file was produced.

These observations establish the CVE-2026-109619 session-chain consequence for
the pinned vulnerable build. They do not establish portability to every PHP
build or effectiveness against arbitrary internet deployments. A failed attempt
on the patched build alone would not refute another path or deployment.

The host-side CLI accepts `--url` only for the two exact loopback lab endpoints.
The result JSON records the attempted CVE-2026-109619 claim and a separate
`not_tested_by_this_command` marker for CVE-2026-109618. The latter describes
that command's scope; the independent experiment is recorded below.

## CVE-2026-109618 independent local experiment

`lab/probe_618.py` starts a fresh pinned Docker container for each case, using
Apache 2.4.68 mod_php with `memory_limit=32M`, `post_max_size=8M`, one worker,
and a randomly assigned loopback port. It sends the same request shape with
one sentinel word changed, first to a harmless zero control and then to a
fixed nonzero marker. The same cases run on PHP 8.4.26 and PHP 8.4.27. The
request never executes application code and the probe does not try to run a
command. The trigger design follows the public Red Hat report; the harness,
preflight, per-case isolation, and outcome checks are local to this repository.

| Build | Variation | OOM | HTTP result | Worker SIGSEGV |
| --- | --- | --- | --- | --- |
| PHP 8.4.26 | Zero control | Yes | 500 | No |
| PHP 8.4.26 | Nonzero sentinel | Yes | Connection closed | Yes |
| PHP 8.4.27 | Zero control | Yes | 500 | No |
| PHP 8.4.27 | Nonzero sentinel | Yes | 500 | No |

The four-case result is in `artifacts/cve-109618-last-run.json`. A separate
debugger run on the vulnerable sentinel case recorded SIGSEGV at
`zend_array_destroy()` → `php_request_shutdown()` after an OOM; the compact
stack is in `artifacts/cve-109618-backtrace.txt`. This differential and stack
support the CVE-2026-109618 shutdown-corruption claim for this exact build.
The incomplete Bucket itself was not dumped in our debugger run; its
initialization ordering is sourced from the Red Hat report. No CVE-2026-109618
RCE consequence was attempted or observed.

## Status

| Claim | Result in this repository | Remaining evidence |
| --- | --- | --- |
| CVE-2026-109619 session-state RCE on pinned PHP 8.4.26 mod_php | Demonstrated | Wider version/deployment matrix untested |
| CVE-2026-109618 shutdown corruption on pinned PHP 8.4.26 mod_php | Controlled crash observed | Direct Bucket-state dump and RCE consequence not demonstrated; wider build matrix untested |

Instruction/reference receipt: the PHP project's two GHSA advisories and the
Wiz analysis were read; the local source, runtime configuration, Docker image
identities, proof artifact, and patched control were inspected. The
`fp-check` validation-fidelity and `poc-builder` procedures informed the claim
separation and control design. This record reports observed behavior rather
than asserting a verdict for untested versions.
