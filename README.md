# Scan Integrity Report

A standalone Python tool that consumes the [Snyk API & Web](https://snyk.io/product/api-web-testing/) API to produce a structured **scan integrity report**. Security and release operators use it to verify DAST scan quality before approving application releases.

The script automates the manual checks operators typically perform when reviewing scan results: validating scan freshness, verifying authentication coverage, reviewing endpoint traffic, checking response codes for anomalies, and confirming the absence of critical findings.

## Background

Release approval workflows often require programmatic access to scan execution data—not just vulnerability findings, but what was scanned, how it was scanned, whether endpoints were reached with authentication, and who triggered the scan.

Recent API improvements expose this scan execution data through the existing Snyk API & Web API. This script is a reference implementation that consumes those endpoints and formats the results for human review or automated pipelines.

| Step | What operators check | API support |
|------|------------------------|-------------|
| 1. Validate scan freshness | Start/completion time, who triggered the scan | Scan API (includes creator and event source) |
| 2. Check for errors | Scan status and error messages | Scan API |
| 3. Review crawl content | Endpoints, methods, request details | Coverage endpoints API + endpoint detail API |
| 4. Verify authentication | Bearer tokens, auth state per endpoint | `authenticated` flag + request headers in detail API |
| 5. Compare coverage | Scanned endpoints vs expected inventory | Paginated JSON endpoint listing with unique IDs |
| 6. Check response codes & sizes | Anomalous 4xx/5xx, request/response sizes | `status_code`, size fields per endpoint |
| 7. Review findings | Critical/high severity vulnerabilities | Findings API with severity filtering |

## Requirements

- Python 3.9+
- `requests` library
- Snyk API & Web API key

## Setup

```bash
pip install requests

# Generate an API key at https://plus.probely.app/
# (Profile → API Keys → Generate)
export SAW_API_KEY="eyJhbG..."
```

Optionally, edit the configuration constants at the top of `scan-integrity-report.py`:

- `TENANT` — your organization identifier
- `API_BASE_URL` — API region endpoint (default: `https://api.us.probely.com`)

## Usage

The script accepts either a **scan ID** (review a specific scan) or a **target ID** (review the latest scan on that target).

```bash
# Report for a specific scan (primary use case)
python3 scan-integrity-report.py --scan-id M8jvAPmBJUJb

# Report for the latest scan on a target
python3 scan-integrity-report.py --target-id 2eJXbYcRLhsQ

# Interactive request details (10 at a time)
python3 scan-integrity-report.py --scan-id M8jvAPmBJUJb --show-requests

# Single endpoint detail
python3 scan-integrity-report.py --scan-id M8jvAPmBJUJb --endpoint-id 3Kx8mPqR2vNw

# JSON output for automation / CI pipelines
python3 scan-integrity-report.py --scan-id M8jvAPmBJUJb --format json

# JSON with all endpoint details
python3 scan-integrity-report.py --scan-id M8jvAPmBJUJb --format json --show-requests
```

### CLI options

| Option | Description |
|--------|-------------|
| `--scan-id` | Scan identifier |
| `--target-id` | Target identifier (uses latest scan; required if `--scan-id` is not set) |
| `--format` | Output format: `text` (default) or `json` |
| `--show-requests` | Include parsed HTTP request details for each endpoint |
| `--endpoint-id` | Show detail for a single endpoint without running the full report |

## Report sections

| Section | Description |
|---------|-------------|
| **Scan metadata** | Target URL, scan ID, status, profile, runtime, who triggered it and how |
| **Coverage summary** | Accepted/rejected counts, auth phase breakdown, size and parameter averages, status code distribution |
| **Non-2xx endpoints** | Endpoints that returned non-2xx status codes |
| **Authentication coverage** | Endpoints found during authenticated vs unauthenticated crawl phase |
| **Rejected endpoints** | Endpoints excluded from scanning, grouped by rejection reason |
| **Findings summary** | Vulnerabilities from this scan by severity, with critical and high listed individually |
| **Endpoint details** | Parsed HTTP request per endpoint (with `--show-requests`), 10 at a time |

## Example output

```
================================================================================
                        SCAN INTEGRITY REPORT
================================================================================

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

Avg request size:    1.2 KB
Avg response size:   8.4 KB
Total parameters:    847 (avg 6.6 per endpoint)

Status code distribution:
    200    98  (76.6%)
    201    12  (9.4%)
    403     2  (1.6%)
    ...

================================================================================
  FINDINGS SUMMARY
================================================================================

Total findings:   7
  Critical:       0
  High:           2
  Medium:         3
  Low:            2
```

With `--show-requests`, the script fetches and displays endpoint details 10 at a time, prompting to continue:

```
Endpoint 3Kx8mPqR2vNw
  POST /api/v2/users
  Status: 201  Authenticated: yes  Parameters: 5
  Content-Type: application/json
  Request size: 1.2 KB  Response size: 3.4 KB

  Request:
    POST /api/v2/users HTTP/1.1
    Host: api.example.com
    Content-Type: application/json
    Authorization: **********
    Cookie: session=**********; theme=dark

Shown 10/128. Show next 10? [y/n]
```

## Notes

- **Authenticated** — Whether the endpoint was found after login. Endpoints with unknown auth state are shown separately when present.
- **Runtime** — Active scanning time, excluding pauses.
- **Findings** — Filtered to the specific scan only (not all target findings).
- **Obfuscation** — Sensitive header values (Authorization, auth cookies, credential-referenced headers) are replaced with `**********` in endpoint details. Non-sensitive headers and cookies are preserved.
- **Rejected endpoints** — Only available when the target's *Include deduplicated endpoints* setting is enabled. Without it, the report notes that rejection reasons are unavailable.
- **Single endpoint** — Use `--endpoint-id` to fetch and display one endpoint without running the full report.

## API endpoints used

This script consumes the following Snyk API & Web API endpoints:

```
GET /scans/{scan_id}/
GET /targets/{target_id}/
GET /targets/{target_id}/scans/
GET /targets/{target_id}/scans/{scan_id}/endpoints/
GET /targets/{target_id}/scans/{scan_id}/endpoints/{endpoint_id}/
GET /targets/{target_id}/findings/?scan={scan_id}
```

## Related API improvements

The scan integrity workflow relies on several API enhancements:

1. **Enriched coverage data** — Endpoint ID and authentication state in CSV export and JSON API
2. **Coverage endpoints as JSON** — Paginated endpoint listing for programmatic filtering and comparison
3. **Endpoint detail with request data** — Structured HTTP request (method, URL, headers, body, parameters, sizes)
4. **Scan attribution** — Creator (name and email) and event source (UI, API, CLI, scheduled, integration)
5. **Request and response sizes** — Populated for all crawler types (API, web, Postman, GraphQL)

Planned follow-on capabilities include response headers, response bodies, and UI visualization of coverage data in the scan detail page.

## License

Reference implementation provided by Snyk. Customize and integrate into your release-approval pipelines as needed.
