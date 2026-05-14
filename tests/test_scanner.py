from email.message import Message

import pytest

from headerhawk.scanner import analyze_cookies, analyze_headers, calculate_score, normalize_url, TLSInfo


def test_normalize_url_adds_https_and_path() -> None:
    assert normalize_url("example.com") == "https://example.com/"


def test_normalize_url_rejects_unsupported_scheme() -> None:
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_analyze_headers_marks_present_headers() -> None:
    headers = Message()
    headers["Content-Security-Policy"] = "default-src 'self'"

    findings = {finding.name: finding for finding in analyze_headers(headers)}

    assert findings["Content-Security-Policy"].present is True
    assert findings["Strict-Transport-Security"].present is False


def test_analyze_cookies_reports_missing_flags() -> None:
    headers = Message()
    headers["Set-Cookie"] = "session=abc; Path=/; Secure"

    [cookie] = analyze_cookies(headers)

    assert cookie.secure is True
    assert cookie.httponly is False
    assert cookie.samesite is False
    assert "missing HttpOnly" in cookie.warnings


def test_calculate_score_caps_at_zero() -> None:
    headers = analyze_headers(Message())
    cookies = analyze_cookies(Message())
    tls = TLSInfo(enabled=False, warnings=["no tls", "bad cert", "expired"])

    score = calculate_score(headers, cookies, tls, uses_https=False)

    assert score == 4
