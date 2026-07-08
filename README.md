# Scan Integrity Report

Python CLI that pulls [Snyk API & Web](https://snyk.io/product/api-web-testing/) scan data and prints a release-readiness report: scan metadata, endpoint coverage, authentication state, response anomalies, and findings by severity.

Use it to verify a DAST scan before approving a release—manually or in CI.

## Quick start

```bash
pip install requests
export SAW_API_KEY="eyJhbG..."   # from https://plus.probely.app/ → Profile → API Keys

python3 scan-integrity-report.py --scan-id <scan_id>
```

Optional: set `API_BASE_URL` at the top of `scan-integrity-report.py` (default: `https://api.us.probely.com`).

**Requirements:** Python 3.9+, `requests`, Snyk API & Web API key.

## Usage

Provide `--scan-id` for a specific scan, or `--target-id` for the latest scan on a target.

```bash
python3 scan-integrity-report.py --scan-id <scan_id>
python3 scan-integrity-report.py --target-id <target_id>

python3 scan-integrity-report.py --scan-id <scan_id> --format json          # CI / automation
python3 scan-integrity-report.py --scan-id <scan_id> --show-requests        # parsed requests, 10 at a time (interactive)
python3 scan-integrity-report.py --scan-id <scan_id> --show-requests --all-requests  # all request details, no prompts
python3 scan-integrity-report.py --scan-id <scan_id> --endpoint-id <ep_id>   # single endpoint only
```

| Option | Description |
|--------|-------------|
| `--scan-id` | Scan to report on |
| `--target-id` | Target to report on (latest scan) |
| `--format` | `text` (default) or `json` |
| `--show-requests` | Include parsed HTTP requests per endpoint |
| `--all-requests` | With `--show-requests` in text mode, show all endpoint details without prompting between batches (auto-enabled when stdout/stdin are not a TTY) |
| `--endpoint-id` | Skip full report; show one endpoint |

## What the report includes

- **Scan metadata** — target name, URL, status, profile, runtime, who triggered it and how
- **Coverage** — accepted vs rejected endpoints, auth/unauth breakdown, status codes, sizes
- **Anomalies** — non-2xx and unauthenticated endpoints (full URLs, no truncation)
- **Rejected endpoints** — reasons (requires *Include deduplicated endpoints* on the target)
- **Findings** — counts by severity; all severities listed with state (this scan only)

With `--show-requests`, sensitive headers (`Authorization`, auth cookies) are masked as `**********`. In interactive text mode, endpoint details are shown 10 at a time with a prompt to continue; use `--all-requests` for a full dump, or pipe output to auto-continue without prompts.

## Example

Text output (`--format text`):

```
================================================================================
                        SCAN INTEGRITY REPORT
                              v3.2
================================================================================

Target name:    Payments API (Production)
Target:         https://api.example.com
Target ID:      2eJXbYcRLhsQ
Scan ID:        M8jvAPmBJUJb
Status:         completed
Scan profile:   Full Scan (sp-default)
Started:        2026-05-25 05:14:22 EDT
Completed:      2026-05-25 05:47:03 EDT
Runtime:        28m 12s
Created by:     operator@example.com
Event source:   api

================================================================================
  COVERAGE SUMMARY
================================================================================

Total endpoints:     142
  Accepted:          128 (90.1%)
  Rejected (dedup):  14 (9.9%)
Auth. phase:         98 / 128 (76.6%)
Unauth. phase:       30 / 128 (23.4%)

Endpoints with non-2xx status codes:
  Method  URL                                      Status  Auth            Params  Req Size  Resp Size
  ──────  ────────────────────────────────────────  ──────  ──────────────  ──────  ────────  ─────────
  GET     https://api.example.com/api/v2/admin      403     unauthenticated  3       0.4 KB    0.2 KB

================================================================================
  FINDINGS SUMMARY
================================================================================

Total findings:   7
  Critical:       0
  High:           2
  Medium:         3
  Low:            2

High severity:
  - SQL Injection
    https://api.example.com/api/v2/search?q=test
    State: notfixed
  - Cross-Site Scripting (Reflected)
    https://api.example.com/api/v2/users/profile?name=test
    State: notfixed

================================================================================
Report generated: 2026-05-25 14:02:15 EDT
================================================================================
```

JSON output (`--format json`) includes `script_version`, `target_name`, structured `rejected_endpoints`, and `findings.items` grouped by severity:

```json
{
  "script_version": "v3.2",
  "target_name": "Payments API (Production)",
  "target": { "id": "2eJXbYcRLhsQ", "url": "https://api.example.com" },
  "scan": { "id": "M8jvAPmBJUJb", "status": "completed", "scan_profile": { "id": "sp-default", "name": "Full Scan" } },
  "coverage": { "total_endpoints": 142, "accepted": 128, "non_2xx": [...] },
  "rejected_endpoints": { "available": true, "total": 14, "by_reason": { "deduplicated (simhash)": 12 } },
  "findings": { "scope": "scan", "total": 7, "items": { "high": [{ "name": "SQL Injection", "state": "notfixed", ... }] } }
}
```
