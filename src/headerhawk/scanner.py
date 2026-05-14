from __future__ import annotations

import datetime as dt
import socket
import ssl
from dataclasses import dataclass, field
from email.message import Message
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen


SECURITY_HEADERS: tuple[str, ...] = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
)


@dataclass(slots=True)
class HeaderFinding:
    name: str
    present: bool
    value: str | None = None
    recommendation: str | None = None


@dataclass(slots=True)
class CookieFinding:
    name: str
    secure: bool
    httponly: bool
    samesite: bool
    raw: str
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TLSInfo:
    enabled: bool
    common_name: str | None = None
    issuer: str | None = None
    expires_at: str | None = None
    days_remaining: int | None = None
    dns_names: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    url: str
    status_code: int | None
    final_url: str | None
    score: int
    headers: list[HeaderFinding]
    cookies: list[CookieFinding]
    tls: TLSInfo
    errors: list[str] = field(default_factory=list)


def normalize_url(target: str) -> str:
    candidate = target.strip()
    if not candidate:
        raise ValueError("target URL cannot be empty")
    if "://" not in candidate:
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("target URL must include a host")

    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def scan_target(target: str, timeout: float = 5.0) -> ScanResult:
    url = normalize_url(target)
    parsed = urlparse(url)
    errors: list[str] = []
    response_headers: Message | None = None
    status_code: int | None = None
    final_url: str | None = None

    tls = inspect_tls(parsed.hostname or "", parsed.port, timeout) if parsed.scheme == "https" else TLSInfo(
        enabled=False,
        warnings=["Target is not using HTTPS."],
    )

    try:
        status_code, final_url, response_headers = fetch_headers(url, timeout)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        errors.append(f"HTTP check failed: {exc}")

    header_findings = analyze_headers(response_headers)
    cookie_findings = analyze_cookies(response_headers)
    score = calculate_score(header_findings, cookie_findings, tls, parsed.scheme == "https")

    return ScanResult(
        url=url,
        status_code=status_code,
        final_url=final_url,
        score=score,
        headers=header_findings,
        cookies=cookie_findings,
        tls=tls,
        errors=errors,
    )


def fetch_headers(url: str, timeout: float) -> tuple[int | None, str | None, Message]:
    request = Request(url, method="HEAD", headers={"User-Agent": "HeaderHawk/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.url, response.headers
    except HTTPError as exc:
        if exc.code not in {403, 405, 501}:
            raise

    request = Request(url, method="GET", headers={"User-Agent": "HeaderHawk/0.1"})
    with urlopen(request, timeout=timeout) as response:
        return response.status, response.url, response.headers


def inspect_tls(hostname: str, port: int | None, timeout: float) -> TLSInfo:
    info = TLSInfo(enabled=True)
    if not hostname:
        info.warnings.append("Could not determine TLS hostname.")
        return info

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port or 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        info.warnings.append(f"Certificate verification failed: {exc.verify_message}")
        return info
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        info.warnings.append(f"TLS check failed: {exc}")
        return info

    info.common_name = _first_name_value(cert.get("subject", ()), "commonName")
    info.issuer = _first_name_value(cert.get("issuer", ()), "organizationName") or _first_name_value(
        cert.get("issuer", ()),
        "commonName",
    )
    info.dns_names = [
        value for key, value in cert.get("subjectAltName", ())
        if key.lower() == "dns"
    ]

    not_after = cert.get("notAfter")
    if not_after:
        expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        info.expires_at = expires.isoformat().replace("+00:00", "Z")
        info.days_remaining = (expires - now).days
        if info.days_remaining < 0:
            info.warnings.append("Certificate is expired.")
        elif info.days_remaining < 30:
            info.warnings.append("Certificate expires in less than 30 days.")

    return info


def analyze_headers(headers: Message | None) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    for name in SECURITY_HEADERS:
        value = headers.get(name) if headers else None
        recommendation = None if value else _header_recommendation(name)
        findings.append(HeaderFinding(name=name, present=bool(value), value=value, recommendation=recommendation))
    return findings


def analyze_cookies(headers: Message | None) -> list[CookieFinding]:
    if not headers:
        return []

    findings: list[CookieFinding] = []
    for raw_cookie in headers.get_all("Set-Cookie", []):
        parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
        name = parts[0].split("=", 1)[0] if parts else "unknown"
        attributes = {part.split("=", 1)[0].lower() for part in parts[1:]}
        finding = CookieFinding(
            name=name,
            secure="secure" in attributes,
            httponly="httponly" in attributes,
            samesite="samesite" in attributes,
            raw=raw_cookie,
        )
        if not finding.secure:
            finding.warnings.append("missing Secure")
        if not finding.httponly:
            finding.warnings.append("missing HttpOnly")
        if not finding.samesite:
            finding.warnings.append("missing SameSite")
        findings.append(finding)
    return findings


def calculate_score(
    headers: list[HeaderFinding],
    cookies: list[CookieFinding],
    tls: TLSInfo,
    uses_https: bool,
) -> int:
    score = 100
    score -= sum(8 for finding in headers if not finding.present)

    if not uses_https:
        score -= 20
    if tls.warnings:
        score -= min(20, len(tls.warnings) * 10)

    for cookie in cookies:
        score -= min(9, len(cookie.warnings) * 3)

    return max(0, min(100, score))


def result_to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "url": result.url,
        "status_code": result.status_code,
        "final_url": result.final_url,
        "score": result.score,
        "tls": {
            "enabled": result.tls.enabled,
            "common_name": result.tls.common_name,
            "issuer": result.tls.issuer,
            "expires_at": result.tls.expires_at,
            "days_remaining": result.tls.days_remaining,
            "dns_names": result.tls.dns_names,
            "warnings": result.tls.warnings,
        },
        "headers": [
            {
                "name": finding.name,
                "present": finding.present,
                "value": finding.value,
                "recommendation": finding.recommendation,
            }
            for finding in result.headers
        ],
        "cookies": [
            {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.httponly,
                "samesite": cookie.samesite,
                "warnings": cookie.warnings,
            }
            for cookie in result.cookies
        ],
        "errors": result.errors,
    }


def _first_name_value(names: object, key: str) -> str | None:
    for group in names if isinstance(names, tuple) else ():
        for item_key, item_value in group:
            if item_key == key:
                return item_value
    return None


def _header_recommendation(name: str) -> str:
    recommendations = {
        "Strict-Transport-Security": "Add HSTS after confirming the site is HTTPS-only.",
        "Content-Security-Policy": "Add a CSP that limits script, style, frame, and object sources.",
        "X-Content-Type-Options": "Set X-Content-Type-Options to nosniff.",
        "X-Frame-Options": "Set DENY or SAMEORIGIN, or use CSP frame-ancestors.",
        "Referrer-Policy": "Set a referrer policy such as strict-origin-when-cross-origin.",
        "Permissions-Policy": "Disable browser features that the application does not need.",
        "Cross-Origin-Opener-Policy": "Consider same-origin for pages that handle sensitive data.",
    }
    return recommendations[name]
