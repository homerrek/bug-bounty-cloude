"""Tests for cors_scanner.py, ssti_scanner.py, open_redirect_scanner.py.

All network calls are mocked — no live HTTP traffic.
"""
import importlib
import json
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

# ─── CORS Scanner ─────────────────────────────────────────────────────────────

class TestCorsScanner:

    def _get_module(self):
        import importlib
        import cors_scanner
        importlib.reload(cors_scanner)
        return cors_scanner

    def test_import(self):
        import cors_scanner
        assert cors_scanner is not None

    def test_dry_run_no_requests(self):
        import cors_scanner
        importlib.reload(cors_scanner)
        cors_scanner.FINDINGS.clear()
        with patch.object(cors_scanner, "http_get") as mock_http:
            cors_scanner.test_origin_reflection("https://example.com", 0, dry_run=True)
            cors_scanner.test_null_origin("https://example.com", 0, dry_run=True)
            cors_scanner.test_credential_exposure("https://example.com", 0, dry_run=True)
            mock_http.assert_not_called()

    def test_payload_list(self):
        import cors_scanner
        assert cors_scanner.EVIL_ORIGIN.startswith("https://")
        assert len(cors_scanner.INTERNAL_ORIGINS) >= 3
        assert any("127.0.0.1" in o for o in cors_scanner.INTERNAL_ORIGINS)

    def test_json_output_structure(self):
        import cors_scanner
        importlib.reload(cors_scanner)
        cors_scanner.FINDINGS.clear()
        cors_scanner.record("test-origin-reflection", "SAFE", "no reflection", "info")
        assert isinstance(cors_scanner.FINDINGS, list)
        assert len(cors_scanner.FINDINGS) == 1
        f = cors_scanner.FINDINGS[0]
        assert "test" in f
        assert "result" in f
        assert "detail" in f
        assert "severity" in f

    def test_connection_error_graceful(self):
        import cors_scanner
        importlib.reload(cors_scanner)
        cors_scanner.FINDINGS.clear()
        with patch.object(cors_scanner, "http_get", return_value=(0, {}, "connection error")):
            # Should not raise (rate=1.0 avoids ZeroDivisionError)
            cors_scanner.test_origin_reflection("https://example.com", 1.0, dry_run=False)


# ─── SSTI Scanner ─────────────────────────────────────────────────────────────

class TestSstiScanner:

    def test_import(self):
        import ssti_scanner
        assert ssti_scanner is not None

    def test_dry_run_no_requests(self):
        import ssti_scanner
        importlib.reload(ssti_scanner)
        ssti_scanner.FINDINGS.clear()
        with patch.object(ssti_scanner, "http_get") as mock_http:
            ssti_scanner.test_universal_detection(
                "https://example.com", ["q"], 0, dry_run=True
            )
            mock_http.assert_not_called()

    def test_payload_list(self):
        import ssti_scanner
        payloads = [p for p, _ in ssti_scanner.UNIVERSAL_PAYLOADS]
        assert "{{7*7}}" in payloads
        assert "${7*7}" in payloads
        assert len(ssti_scanner.UNIVERSAL_PAYLOADS) >= 6

    def test_json_output_structure(self):
        import ssti_scanner
        importlib.reload(ssti_scanner)
        ssti_scanner.FINDINGS.clear()
        ssti_scanner.record("ssti-universal", "SAFE", "no reflection", "info")
        assert isinstance(ssti_scanner.FINDINGS, list)
        f = ssti_scanner.FINDINGS[0]
        for key in ("test", "result", "detail", "severity"):
            assert key in f

    def test_connection_error_graceful(self):
        import ssti_scanner
        importlib.reload(ssti_scanner)
        ssti_scanner.FINDINGS.clear()
        with patch.object(ssti_scanner, "http_get", return_value=(0, {}, "error")):
            ssti_scanner.test_universal_detection(
                "https://example.com", ["q"], 1.0, dry_run=False
            )


# ─── Open Redirect Scanner ────────────────────────────────────────────────────

class TestOpenRedirectScanner:

    def test_import(self):
        import open_redirect_scanner
        assert open_redirect_scanner is not None

    def test_dry_run_no_requests(self):
        import open_redirect_scanner
        importlib.reload(open_redirect_scanner)
        open_redirect_scanner.FINDINGS.clear()
        with patch.object(open_redirect_scanner, "http_get") as mock_http:
            open_redirect_scanner.test_redirect_params_baseline(
                "https://example.com", 0, dry_run=True
            )
            mock_http.assert_not_called()

    def test_redirect_param_list(self):
        import open_redirect_scanner
        params = open_redirect_scanner.REDIRECT_PARAMS
        assert "next" in params
        assert "redirect" in params
        assert "url" in params
        assert len(params) >= 10

    def test_bypass_payload_list(self):
        import open_redirect_scanner
        payloads = [p for p, _ in open_redirect_scanner.BYPASS_PAYLOADS]
        assert any("{evil}" in p for p in payloads)
        assert any("{domain}" in p for p in payloads)
        assert len(open_redirect_scanner.BYPASS_PAYLOADS) >= 5

    def test_json_output_structure(self):
        import open_redirect_scanner
        importlib.reload(open_redirect_scanner)
        open_redirect_scanner.FINDINGS.clear()
        open_redirect_scanner.record("open-redirect-baseline", "SAFE", "no redirect", "info")
        assert isinstance(open_redirect_scanner.FINDINGS, list)
        f = open_redirect_scanner.FINDINGS[0]
        for key in ("test", "result", "detail", "severity"):
            assert key in f

    def test_connection_error_graceful(self):
        import open_redirect_scanner
        importlib.reload(open_redirect_scanner)
        open_redirect_scanner.FINDINGS.clear()
        with patch.object(open_redirect_scanner, "http_get", return_value=(0, {}, "error")):
            open_redirect_scanner.test_redirect_params_baseline(
                "https://example.com", 1.0, dry_run=False
            )
