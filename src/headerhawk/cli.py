from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .scanner import ScanResult, result_to_dict, scan_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerhawk",
        description="Check TLS details and common HTTP security headers for one or more URLs.",
    )
    parser.add_argument("targets", nargs="+", help="URL or hostname to scan")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--timeout", type=float, default=5.0, help="network timeout in seconds")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    results: list[ScanResult] = []
    had_error = False
    for target in args.targets:
        try:
            result = scan_target(target, timeout=args.timeout)
        except ValueError as exc:
            had_error = True
            if args.json:
                results.append(_invalid_result(target, str(exc)))
            else:
                print(f"{target}: {exc}", file=sys.stderr)
            continue

        had_error = had_error or bool(result.errors)
        results.append(result)

    if args.json:
        print(json.dumps([result_to_dict(result) for result in results], indent=2, sort_keys=True))
    else:
        for index, result in enumerate(results):
            if index:
                print()
            print(format_result(result))

    return 1 if had_error else 0


def format_result(result: ScanResult) -> str:
    lines = [
        result.url,
        f"Score: {result.score}/100",
    ]
    if result.status_code is not None:
        lines.append(f"HTTP status: {result.status_code}")
    if result.final_url and result.final_url != result.url:
        lines.append(f"Final URL: {result.final_url}")

    lines.extend(["", "TLS"])
    if result.tls.enabled:
        lines.append(f"  Common name: {result.tls.common_name or 'unknown'}")
        lines.append(f"  Issuer: {result.tls.issuer or 'unknown'}")
        lines.append(f"  Expires: {result.tls.expires_at or 'unknown'}")
        days = "unknown" if result.tls.days_remaining is None else str(result.tls.days_remaining)
        lines.append(f"  Days remaining: {days}")
        if result.tls.dns_names:
            preview = ", ".join(result.tls.dns_names[:5])
            suffix = " ..." if len(result.tls.dns_names) > 5 else ""
            lines.append(f"  DNS names: {preview}{suffix}")
    else:
        lines.append("  HTTPS is not enabled for this target.")

    for warning in result.tls.warnings:
        lines.append(f"  [warn] {warning}")

    lines.extend(["", "Headers"])
    for finding in result.headers:
        label = "ok" if finding.present else "missing"
        lines.append(f"  [{label}] {finding.name}")
        if finding.recommendation:
            lines.append(f"    {finding.recommendation}")

    if result.cookies:
        lines.extend(["", "Cookies"])
        for cookie in result.cookies:
            label = "ok" if not cookie.warnings else "warn"
            flags = ", ".join(cookie.warnings) if cookie.warnings else "all recommended flags present"
            lines.append(f"  [{label}] {cookie.name}: {flags}")

    if result.errors:
        lines.extend(["", "Errors"])
        lines.extend(f"  {error}" for error in result.errors)

    return "\n".join(lines)


def _invalid_result(target: str, message: str) -> ScanResult:
    from .scanner import TLSInfo

    return ScanResult(
        url=target,
        status_code=None,
        final_url=None,
        score=0,
        headers=[],
        cookies=[],
        tls=TLSInfo(enabled=False),
        errors=[message],
    )
