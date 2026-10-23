# woxeshell

> ⚠️ **Authorized use only.** Detection on systems you own or have explicit
> written permission to test. A positive result is an indicator, not proof of RCE.

Detection-only scanner for:

| CVE | Description | Fixed in |
|-----|-------------|----------|
| **CVE-2026-109618** | RCE via OOM corruption during request cleanup | PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| **CVE-2026-109619** | RCE via stale request-owned global state on same worker | same |

## Build

```bash
go build -o woxeshell .
```

## Usage

```bash
./woxeshell -u https://target.example
./woxeshell -l targets.txt -c 20 -o report.jsonl -v
./woxeshell -l targets.txt -x http://127.0.0.1:8080 -k
./woxeshell -u https://api.example -H "Authorization: Bearer TOKEN"
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-u` | — | single target URL |
| `-l` | — | file with target URLs |
| `-o` | — | JSONL report file |
| `-c` | `10` | concurrency |
| `-t` | `20s` | per-request timeout |
| `-max-time` | `0` | global timeout (`0` = unlimited) |
| `-r` | `0` | global rate limit (req/sec) |
| `-ua` | — | custom User-Agent |
| `-k` | off | skip TLS verification |
| `-x` | — | proxy URL |
| `-H` | — | extra header (repeatable) |
| `-v` | off | verbose |
| `-no-color` | off | disable ANSI |
| `-no-banner` | off | suppress banner |
| `-skip-fingerprint` | off | skip PHP fingerprinting |
| `-retries` | `1` | retries per request |

### Output legend

| Tag | Meaning |
|-----|---------|
| `[VULN]` | at least one indicator found |
| `[SAFE]` | PHP detected, no indicators found |
| `[SKIP]` | target does not appear to be PHP |
| `[ERR ]` | request failed |

### Exit codes

- `0` no indicators
- `1` at least one indicator
- `2` usage error

## How it works

### Fingerprinting
Checks `X-Powered-By`, `Server`, and `Set-Cookie` for PHP signatures. If a
version is exposed and already at or above the fixed release for its branch,
the target is skipped as patched.

### CVE-2026-109619
Two requests over the **same keep-alive connection**:

1. Request A primes the worker with marker **A** (baseline echo checked).
2. Request B sends marker **B** on the same connection.
3. If response B also contains **A**, stale request-owned global state leaked
   across requests → indicator.

### CVE-2026-109618
Behavioral heuristics only:

1. Baseline small request must succeed.
2. A 32 MiB benign body exercises the cleanup path.
3. Follow-up request checks worker health.
4. A change in the `Server` header, connection reset, unresponsive worker, or
   a 5xx response with `fatal` / `memory` / `allocate` / `oom` signatures is
   reported as an indicator.

No exploit payload is delivered.

## Output

Text on stderr/stdout, plus optional JSONL (`-o`):

```json
{"target":"https://x","vulnerable":true,"php":true,"version":"8.4.26","cves":["CVE-2026-109619"],"evidence":["..."]}
```

## Mitigations

- Patch to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or vendor backports).
- If patching is not possible: disable `session.upload_progress`, restart
  workers, review `memory_limit`, `post_max_size`, and `fatal_error_backtraces`.
- Check third-party images, appliances, and embedded PHP runtimes separately.

## Limitations

- Detection is heuristic. False positives are possible, especially for 109618.
- `mod_php` may behave differently from PHP-FPM under keep-alive.

## License

MIT — see [LICENSE](LICENSE).