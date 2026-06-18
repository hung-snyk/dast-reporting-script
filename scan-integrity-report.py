#!/usr/bin/env python3
"""
Scan Integrity Report

Generates a scan integrity report from the Snyk API & Web API.
Used by operators to approve releases based on DAST scan results.

Usage:
    export SAW_API_KEY="eyJhbG..."
    python3 scan-integrity-report.py --scan-id <scan_id>
    python3 scan-integrity-report.py --target-id <target_id>          (latest scan)
    python3 scan-integrity-report.py --scan-id <scan_id> --format json
    python3 scan-integrity-report.py --scan-id <scan_id> --show-requests
    python3 scan-integrity-report.py --scan-id <scan_id> --endpoint-id <ep_id>
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Configuration ──────────────────────────────────────────────────────────────

VERSION = "v3.1"
API_BASE_URL = "https://api.us.probely.com"
REQUEST_TIMEOUT = 30

# ── Helpers ────────────────────────────────────────────────────────────────────


def format_duration(duration_str):
    if not duration_str or duration_str == "—":
        return "—"
    days = 0
    if " " in duration_str:
        day_part, time_part = duration_str.split(" ", 1)
        days = int(day_part)
    else:
        time_part = duration_str
    time_part = time_part.split(".")[0]
    parts = time_part.split(":")
    h, m, s = int(parts[0]), int(parts[1]), int(parts[2])
    pieces = []
    if days > 0:
        pieces.append(f"{days}d")
    if h > 0 or days > 0:
        pieces.append(f"{h}h")
    if m > 0 or h > 0 or days > 0:
        pieces.append(f"{m:02d}m")
    pieces.append(f"{s:02d}s")
    return " ".join(pieces)


def format_timestamp(iso_str):
    if not iso_str or iso_str == "—":
        return "—"
    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    local_dt = dt.astimezone()
    return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def format_size(size_bytes):
    if size_bytes is None:
        return "—"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


class APIClient:
    def __init__(self, api_key, base_url=API_BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"JWT {api_key}",
            "Accept": "application/json",
        })
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, path, params=None):
        url = f"{self.base_url}{path}"
        resp = self.session.get(
            url, params=params, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()

    def get_all(self, path, params=None):
        params = dict(params or {})
        params.setdefault("length", 100)
        page = 1
        results = []
        while True:
            params["page"] = page
            data = self.get(path, params)
            results.extend(data.get("results", []))
            if page >= data.get("page_total", 1):
                break
            page += 1
        return results


# ── Data Fetching ──────────────────────────────────────────────────────────────


def fetch_scan_by_id(client, scan_id):
    return client.get(f"/scans/{scan_id}/")


def fetch_latest_scan(client, target_id):
    scans = client.get(
        f"/targets/{target_id}/scans/",
        params={"length": 1},
    )
    if not scans.get("results"):
        print(
            "Error: No scans found for this target.",
            file=sys.stderr,
        )
        sys.exit(1)
    return scans["results"][0]


def fetch_endpoints(client, target_id, scan_id):
    return client.get_all(
        f"/targets/{target_id}/scans/{scan_id}/endpoints/",
    )


def fetch_findings(client, target_id, scan_id):
    return client.get_all(
        f"/targets/{target_id}/findings/",
        params={"scan": scan_id},
    )


def fetch_target(client, target_id):
    return client.get(f"/targets/{target_id}/")


def fetch_endpoint_detail(client, target_id, scan_id, ep_id):
    try:
        return client.get(
            f"/targets/{target_id}/scans/{scan_id}"
            f"/endpoints/{ep_id}/"
        )
    except requests.HTTPError as e:
        print(
            f"Warning: failed to fetch endpoint {ep_id}: {e}",
            file=sys.stderr,
        )
        return None


def fetch_endpoint_details_batch(
    client, target_id, scan_id, endpoints, batch_size=10
):
    details = []
    total = len(endpoints)
    for i in range(0, total, batch_size):
        batch = endpoints[i : i + batch_size]
        for ep in batch:
            ep_id = ep.get("id")
            if ep_id:
                detail = fetch_endpoint_detail(
                    client, target_id, scan_id, ep_id
                )
                if detail:
                    details.append(detail)
        fetched = min(i + batch_size, total)
        print(
            f"  Fetched {fetched}/{total} endpoint details...",
            file=sys.stderr,
        )
    return details


# ── Analysis ───────────────────────────────────────────────────────────────────


def analyze_endpoints(endpoints):
    accepted = [
        e for e in endpoints if e.get("result") == "accepted"
    ]
    rejected = [
        e for e in endpoints if e.get("result") == "rejected"
    ]
    authenticated = [
        e for e in accepted if e.get("authenticated") is True
    ]
    unauthenticated = [
        e for e in accepted if e.get("authenticated") is False
    ]
    unknown_auth = [
        e for e in accepted if e.get("authenticated") is None
    ]

    status_codes = {}
    for e in accepted:
        code = e.get("status_code", "?")
        status_codes[code] = status_codes.get(code, 0) + 1

    req_sizes = [
        e["raw_request_size"]
        for e in accepted
        if e.get("raw_request_size")
    ]
    resp_sizes = [
        e["raw_response_size"]
        for e in accepted
        if e.get("raw_response_size")
    ]
    param_counts = [
        e["request_parameters_count"]
        for e in accepted
        if e.get("request_parameters_count")
    ]

    non_2xx = [
        e
        for e in accepted
        if not e.get("status_code", "200").startswith("2")
    ]

    return {
        "total": len(endpoints),
        "accepted": accepted,
        "rejected": rejected,
        "authenticated": authenticated,
        "unauthenticated": unauthenticated,
        "unknown_auth": unknown_auth,
        "status_codes": dict(sorted(status_codes.items())),
        "avg_request_size": (
            sum(req_sizes) / len(req_sizes) if req_sizes else 0
        ),
        "avg_response_size": (
            sum(resp_sizes) / len(resp_sizes) if resp_sizes else 0
        ),
        "total_parameters": sum(param_counts),
        "avg_parameters": (
            sum(param_counts) / len(param_counts)
            if param_counts
            else 0
        ),
        "non_2xx": non_2xx,
    }


SEVERITY_BY_SCORE = {
    40: "critical",
    30: "high",
    20: "medium",
    10: "low",
}


def normalize_severity(severity):
    if isinstance(severity, str):
        label = severity.lower()
        if label in SEVERITY_BY_SCORE.values():
            return label
    if isinstance(severity, (int, float)):
        return SEVERITY_BY_SCORE.get(int(severity), "low")
    return "low"


def analyze_findings(findings):
    by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for f in findings:
        sev = normalize_severity(f.get("severity", "low"))
        by_severity[sev].append(f)
    return by_severity


# ── Output ─────────────────────────────────────────────────────────────────────


def print_header(title):
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def print_table(indent, headers, rows):
    str_rows = [[str(cell) for cell in row] for row in rows]
    widths = [
        max(
            len(headers[i]),
            *(len(row[i]) for row in str_rows),
        )
        for i in range(len(headers))
    ]
    prefix = " " * indent
    sep = prefix + "  ".join("─" * w for w in widths)

    def fmt_row(cells):
        return prefix + "  ".join(
            f"{cell:<{widths[i]}}" for i, cell in enumerate(cells)
        )

    print(fmt_row(headers))
    print(sep)
    for row in str_rows:
        print(fmt_row(row))


def print_endpoint_detail(detail):
    ep_id = detail.get("id", "?")
    method = detail.get("request_method", "?")
    url = detail.get("url", "?")
    status_code = detail.get("status_code", "?")
    content_type = detail.get("content_type") or "—"
    auth = detail.get("authenticated")
    auth_str = (
        "yes" if auth is True else "no" if auth is False else "—"
    )
    params = detail.get("request_parameters_count") or 0
    req_size = format_size(detail.get("raw_request_size"))
    resp_size = format_size(detail.get("raw_response_size"))

    print(f"Endpoint {ep_id}")
    print(f"  {method} {url}")
    print(
        f"  Status: {status_code}  Authenticated: {auth_str}"
        f"  Parameters: {params}"
    )
    print(f"  Content-Type: {content_type}")
    print(f"  Request size: {req_size}  Response size: {resp_size}")

    parsed = detail.get("parsed_request")
    if parsed:
        print(f"\n  Request:")
        path = parsed.get("path", "?")
        params = parsed.get("params")
        if params:
            qs = "&".join(
                f"{k}={v[0]}" if len(v) == 1 else
                "&".join(f"{k}={vi}" for vi in v)
                for k, v in params.items()
            )
            path = f"{path}?{qs}"
        print(
            f"    {parsed.get('method', '?')} "
            f"{path} "
            f"HTTP/{parsed.get('http_version', '?')}"
        )
        for b64_name, b64_value in parsed.get("headers", []):
            name = base64.b64decode(b64_name).decode(
                "utf-8", errors="replace"
            )
            value = base64.b64decode(b64_value).decode(
                "utf-8", errors="replace"
            )
            print(f"    {name}: {value}")

    print(f"\n{'─' * 80}\n")


def print_text_report(
    target,
    scan,
    endpoint_analysis,
    finding_analysis,
    endpoint_details=None,
):
    print("=" * 80)
    print("                        SCAN INTEGRITY REPORT")
    print(f"                              {VERSION}")
    print("=" * 80)

    started = format_timestamp(scan.get("started", "—"))
    completed = format_timestamp(scan.get("completed", "—"))
    runtime_str = format_duration(scan.get("runtime", "—"))

    scan_profile = scan.get("scan_profile", "—")
    if isinstance(scan_profile, dict):
        scan_profile = (
            f"{scan_profile.get('name', '—')} "
            f"({scan_profile.get('id', '')})"
        )

    target_name = target_display_name(target, scan) or "—"
    print(f"\nTarget name:    {target_name}")
    print(
        f"Target:         "
        f"{target.get('site', {}).get('url', '—')}"
    )
    print(f"Target ID:      {target.get('id', '—')}")
    print(f"Scan ID:        {scan.get('id', '—')}")
    print(f"Status:         {scan.get('status', '—')}")
    print(f"Scan profile:   {scan_profile}")
    print(f"Started:        {started}")
    print(f"Completed:      {completed}")
    print(f"Runtime:        {runtime_str}")
    created_by = (
        scan.get("created_by", {}).get("email", "—")
        if scan.get("created_by")
        else "—"
    )
    print(f"Created by:     {created_by}")
    print(f"Event source:   {scan.get('event_source', '—')}")

    # Coverage summary
    print_header("COVERAGE SUMMARY")

    ea = endpoint_analysis
    accepted_count = len(ea["accepted"])
    rejected_count = len(ea["rejected"])
    auth_count = len(ea["authenticated"])
    unauth_count = len(ea["unauthenticated"])
    unknown_count = len(ea["unknown_auth"])

    print(f"Total endpoints:     {ea['total']}")
    if ea["total"] > 0:
        print(
            f"  Accepted:          {accepted_count} "
            f"({accepted_count / ea['total'] * 100:.1f}%)"
        )
        print(
            f"  Rejected (dedup):  {rejected_count} "
            f"({rejected_count / ea['total'] * 100:.1f}%)"
        )

    if accepted_count > 0:
        print(
            f"Auth. phase:         {auth_count} / {accepted_count} "
            f"({auth_count / accepted_count * 100:.1f}%)"
        )
        print(
            f"Unauth. phase:       {unauth_count} / {accepted_count} "
            f"({unauth_count / accepted_count * 100:.1f}%)"
        )
        if unknown_count > 0:
            print(
                f"Unknown:             {unknown_count} / "
                f"{accepted_count} "
                f"({unknown_count / accepted_count * 100:.1f}%)"
            )

    print(
        f"\nAvg request size:    "
        f"{format_size(int(ea['avg_request_size']))}"
    )
    print(
        f"Avg response size:   "
        f"{format_size(int(ea['avg_response_size']))}"
    )
    print(
        f"Total parameters:    {ea['total_parameters']} "
        f"(avg {ea['avg_parameters']:.1f} per endpoint)"
    )

    print(f"\nStatus code distribution:")
    for code, count in ea["status_codes"].items():
        pct = (
            count / accepted_count * 100 if accepted_count else 0
        )
        print(f"  {code:>5}  {count:>4}  ({pct:.1f}%)")

    if ea["non_2xx"]:
        print(f"\nEndpoints with non-2xx status codes:")
        non_2xx_rows = []
        for e in ea["non_2xx"]:
            auth = e.get("authenticated")
            auth_str = (
                "authenticated"
                if auth is True
                else "unauthenticated"
                if auth is False
                else "unknown"
            )
            non_2xx_rows.append([
                e.get("request_method", "?"),
                e.get("url", "?"),
                e.get("status_code", "?"),
                auth_str,
                e.get("request_parameters_count") or 0,
                format_size(e.get("raw_request_size")),
                format_size(e.get("raw_response_size")),
            ])
        print_table(
            2,
            [
                "Method",
                "URL",
                "Status",
                "Auth",
                "Params",
                "Req Size",
                "Resp Size",
            ],
            non_2xx_rows,
        )

    # Authentication coverage
    print_header("AUTHENTICATION COVERAGE")

    if accepted_count > 0:
        pct = auth_count / accepted_count * 100
        print(
            f"Authenticated:     {auth_count} / {accepted_count} "
            f"({pct:.1f}%)"
        )
        print(
            f"Unauthenticated:   {unauth_count} / {accepted_count} "
            f"({100 - pct:.1f}%)"
        )
    if unknown_count > 0:
        print(f"Unknown:           {unknown_count}")
    if unauth_count > 0:
        print(
            f"\nUnauthenticated endpoints:\n"
        )
        unauth_rows = []
        for e in ea["unauthenticated"]:
            unauth_rows.append([
                e.get("request_method", "?"),
                e.get("url", "?"),
                e.get("status_code", "?"),
                e.get("request_parameters_count") or 0,
                format_size(e.get("raw_request_size")),
                format_size(e.get("raw_response_size")),
            ])
        print_table(
            2,
            [
                "Method",
                "URL",
                "Status",
                "Params",
                "Req Size",
                "Resp Size",
            ],
            unauth_rows,
        )

    # Rejected endpoints
    print_header("REJECTED ENDPOINTS")

    include_dedup = target.get(
        "include_deduplicated_endpoints", False
    )

    if not include_dedup:
        print(
            "Rejected endpoints are not available.\n"
            "Enable 'Include deduplicated endpoints' in\n"
            "the target settings to see rejection reasons."
        )
    elif not ea["rejected"]:
        print("No rejected endpoints.")
    else:
        reasons = {}
        for e in ea["rejected"]:
            reason = (
                e.get("reason") or "no reason provided"
            )
            reasons[reason] = reasons.get(reason, 0) + 1

        print(f"Total rejected: {rejected_count}\n")
        print("By reason:")
        for reason, count in sorted(
            reasons.items(), key=lambda x: -x[1]
        ):
            print(f"  {count:>4}  {reason}")

        rejected_rows = []
        for e in ea["rejected"]:
            rejected_rows.append([
                e.get("request_method", "?"),
                e.get("url", "?"),
                e.get("reason") or "—",
            ])
        print()
        print_table(2, ["Method", "URL", "Reason"], rejected_rows)

    # Findings
    print_header("FINDINGS SUMMARY")

    fa = finding_analysis
    total_findings = sum(len(v) for v in fa.values())
    print(f"Total findings:   {total_findings}")
    print(f"  Critical:       {len(fa['critical'])}")
    print(f"  High:           {len(fa['high'])}")
    print(f"  Medium:         {len(fa['medium'])}")
    print(f"  Low:            {len(fa['low'])}")

    for sev in ("critical", "high", "medium", "low"):
        if fa[sev]:
            print(f"\n{sev.capitalize()} severity:")
            for f in fa[sev]:
                name = f.get("definition", {}).get(
                    "name", "Unknown"
                )
                url = f.get("url", "?")
                state = f.get("state", "")
                print(f"  - {name}")
                print(f"    {url}")
                if state:
                    print(f"    State: {state}")

    print(f"\n{'=' * 80}")
    print(
        f"Report generated: "
        f"{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}"
    )
    print(f"{'=' * 80}")


def auth_label(authenticated):
    if authenticated is True:
        return "authenticated"
    if authenticated is False:
        return "unauthenticated"
    return "unknown"


def target_display_name(target, scan=None):
    scan = scan or {}
    scan_target = scan.get("target") or {}
    for name in (
        target.get("site", {}).get("name"),
        scan_target.get("site", {}).get("name"),
        (scan.get("target_options") or {}).get("site", {}).get(
            "name"
        ),
        target.get("name"),
        scan_target.get("name"),
    ):
        if name:
            return name
    return None


def serialize_endpoint(endpoint):
    auth = endpoint.get("authenticated")
    return {
        "id": endpoint.get("id"),
        "method": endpoint.get("request_method"),
        "url": endpoint.get("url"),
        "status_code": endpoint.get("status_code"),
        "authenticated": auth,
        "auth": auth_label(auth),
        "parameters": endpoint.get("request_parameters_count"),
        "raw_request_size": endpoint.get("raw_request_size"),
        "raw_response_size": endpoint.get("raw_response_size"),
        "result": endpoint.get("result"),
        "reason": endpoint.get("reason") or None,
    }


def serialize_finding(finding):
    return {
        "id": finding.get("id"),
        "name": finding.get("definition", {}).get("name"),
        "url": finding.get("url"),
        "severity": normalize_severity(
            finding.get("severity", "low")
        ),
        "state": finding.get("state"),
        "parameter": finding.get("parameter") or None,
        "cwe_id": finding.get("definition", {}).get("cwe_id"),
    }


def rejected_reason_counts(rejected):
    reasons = {}
    for endpoint in rejected:
        reason = endpoint.get("reason") or "no reason provided"
        reasons[reason] = reasons.get(reason, 0) + 1
    return dict(
        sorted(reasons.items(), key=lambda item: -item[1])
    )


def scan_profile_value(scan):
    scan_profile = scan.get("scan_profile")
    if isinstance(scan_profile, dict):
        return {
            "id": scan_profile.get("id"),
            "name": scan_profile.get("name"),
        }
    return scan_profile


def print_json_report(
    target,
    scan,
    endpoint_analysis,
    finding_analysis,
    endpoint_details=None,
):
    ea = endpoint_analysis
    fa = finding_analysis
    include_dedup = target.get(
        "include_deduplicated_endpoints", False
    )

    report = {
        "script_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_name": target_display_name(target, scan),
        "target": {
            "id": target.get("id"),
            "name": target_display_name(target, scan),
            "url": target.get("site", {}).get("url"),
        },
        "scan": {
            "id": scan.get("id"),
            "status": scan.get("status"),
            "scan_profile": scan_profile_value(scan),
            "started": scan.get("started"),
            "completed": scan.get("completed"),
            "runtime": scan.get("runtime"),
            "created_by": (
                scan.get("created_by", {}).get("email")
                if scan.get("created_by")
                else None
            ),
            "event_source": scan.get("event_source"),
        },
        "coverage": {
            "total_endpoints": ea["total"],
            "accepted": len(ea["accepted"]),
            "rejected": len(ea["rejected"]),
            "authenticated": len(ea["authenticated"]),
            "unauthenticated": len(ea["unauthenticated"]),
            "unknown_auth": len(ea["unknown_auth"]),
            "status_codes": ea["status_codes"],
            "avg_request_size": int(ea["avg_request_size"]),
            "avg_response_size": int(
                ea["avg_response_size"]
            ),
            "total_parameters": ea["total_parameters"],
            "avg_parameters": round(ea["avg_parameters"], 1),
            "non_2xx": [
                serialize_endpoint(e) for e in ea["non_2xx"]
            ],
            "unauthenticated": [
                serialize_endpoint(e)
                for e in ea["unauthenticated"]
            ],
        },
        "rejected_endpoints": {
            "available": include_dedup,
            "total": len(ea["rejected"]),
            "by_reason": (
                rejected_reason_counts(ea["rejected"])
                if include_dedup
                else {}
            ),
            "items": (
                [
                    serialize_endpoint(e)
                    for e in ea["rejected"]
                ]
                if include_dedup
                else []
            ),
        },
        "findings": {
            "scope": "scan",
            "total": sum(len(v) for v in fa.values()),
            "critical": len(fa["critical"]),
            "high": len(fa["high"]),
            "medium": len(fa["medium"]),
            "low": len(fa["low"]),
            "items": {
                severity: [
                    serialize_finding(f) for f in fa[severity]
                ]
                for severity in (
                    "critical",
                    "high",
                    "medium",
                    "low",
                )
            },
        },
    }
    if endpoint_details:
        report["endpoint_details"] = endpoint_details
    print(json.dumps(report, indent=2))


# ── Main ───────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Scan Integrity Report for Snyk API & Web",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "--scan-id",
        default=None,
        help="Scan identifier",
    )
    parser.add_argument(
        "--target-id",
        default=None,
        help=(
            "Target identifier "
            "(required if --scan-id not provided)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--show-requests",
        action="store_true",
        help="Include parsed request details for each endpoint",
    )
    parser.add_argument(
        "--endpoint-id",
        default=None,
        help="Show detail for a single endpoint",
    )
    args = parser.parse_args()

    api_key = os.environ.get("SAW_API_KEY")
    if not api_key:
        print(
            "Error: SAW_API_KEY environment variable not set.\n"
            "Generate an API key at https://plus.probely.app/ "
            "and export it:\n\n"
            '  export SAW_API_KEY="eyJhbG..."\n',
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.scan_id and not args.target_id:
        print(
            "Error: provide --scan-id or --target-id.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    client = APIClient(api_key)

    if args.scan_id:
        scan = fetch_scan_by_id(client, args.scan_id)
        target_id = (
            scan.get("target", {}).get("id") or args.target_id
        )
        if not target_id:
            print(
                "Error: could not determine target ID from "
                "scan. Pass --target-id explicitly.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        target_id = args.target_id
        scan = fetch_latest_scan(client, target_id)

    scan_id = scan["id"]
    target = fetch_target(client, target_id)

    # Single endpoint detail mode
    if args.endpoint_id:
        detail = fetch_endpoint_detail(
            client, target_id, scan_id, args.endpoint_id
        )
        if detail:
            if args.output_format == "json":
                print(json.dumps(detail, indent=2))
            else:
                print_endpoint_detail(detail)
        else:
            print(
                f"Error: endpoint {args.endpoint_id} not found.",
                file=sys.stderr,
            )
            sys.exit(1)
        return

    # Full report mode
    endpoints = fetch_endpoints(client, target_id, scan_id)
    findings = fetch_findings(client, target_id, scan_id)

    endpoint_analysis = analyze_endpoints(endpoints)
    finding_analysis = analyze_findings(findings)

    if args.output_format == "json":
        endpoint_details = None
        if args.show_requests:
            accepted = endpoint_analysis["accepted"]
            endpoint_details = fetch_endpoint_details_batch(
                client, target_id, scan_id, accepted
            )
        print_json_report(
            target,
            scan,
            endpoint_analysis,
            finding_analysis,
            endpoint_details=endpoint_details,
        )
    else:
        print_text_report(
            target,
            scan,
            endpoint_analysis,
            finding_analysis,
        )

        if args.show_requests:
            accepted = endpoint_analysis["accepted"]
            total = len(accepted)
            if total == 0:
                print("\nNo accepted endpoints to show.")
            else:
                print_header("ENDPOINT DETAILS")
                print(
                    f"{total} accepted endpoints. "
                    f"Showing 10 at a time.\n"
                )
                page_size = 10
                for i in range(0, total, page_size):
                    batch = accepted[i : i + page_size]
                    for ep in batch:
                        ep_id = ep.get("id")
                        if not ep_id:
                            continue
                        detail = fetch_endpoint_detail(
                            client,
                            target_id,
                            scan_id,
                            ep_id,
                        )
                        if detail:
                            print_endpoint_detail(detail)

                    shown = min(i + page_size, total)
                    remaining = total - shown
                    if remaining > 0:
                        try:
                            answer = input(
                                f"Shown {shown}/{total}. "
                                f"Show next "
                                f"{min(page_size, remaining)}"
                                f"? [y/n] "
                            )
                        except (EOFError, KeyboardInterrupt):
                            print()
                            break
                        if answer.lower() not in (
                            "y",
                            "yes",
                            "",
                        ):
                            break


if __name__ == "__main__":
    main()
