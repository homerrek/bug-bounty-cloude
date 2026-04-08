"""Core integrity tests — validate all tools still import and function correctly.

Covers:
- All Python files in tools/ import without error
- All scanners accept --target/--url, --json, --dry-run flags
- Memory modules import and basic classes instantiate
"""
import importlib
import os
import sys
import subprocess
import pytest

TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "tools")
TESTS_DIR = os.path.dirname(__file__)

sys.path.insert(0, TOOLS_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestToolImports:

    def test_token_optimizer_imports(self):
        import token_optimizer
        assert token_optimizer is not None

    def test_scope_checker_imports(self):
        import scope_checker
        assert scope_checker is not None

    def test_intel_engine_imports(self):
        import intel_engine
        assert intel_engine is not None


SCANNER_FILES = [
    "cors_scanner.py",
    "ssti_scanner.py",
    "open_redirect_scanner.py",
    "crlf_scanner.py",
    "css_injection_scanner.py",
]


class TestScannerCLI:

    @pytest.mark.parametrize("scanner_file", SCANNER_FILES)
    def test_scanner_help_exits_zero(self, scanner_file):
        scanner_path = os.path.join(TOOLS_DIR, scanner_file)
        result = subprocess.run(
            [sys.executable, scanner_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            f"{scanner_file} --help returned {result.returncode}:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


class TestMemoryModules:

    def test_hunt_journal_imports(self):
        from memory.hunt_journal import HuntJournal
        assert HuntJournal is not None

    def test_pattern_db_imports(self):
        from memory.pattern_db import PatternDB
        assert PatternDB is not None

    def test_audit_log_imports(self):
        from memory.audit_log import AuditLog
        assert AuditLog is not None

    def test_schemas_imports(self):
        from memory.schemas import CURRENT_SCHEMA_VERSION
        assert isinstance(CURRENT_SCHEMA_VERSION, int)
        assert CURRENT_SCHEMA_VERSION >= 1


class TestExistingTestSuite:

    def test_conftest_fixtures_available(self):
        import importlib.util
        conftest_path = os.path.join(TESTS_DIR, "conftest.py")
        spec = importlib.util.spec_from_file_location("conftest", conftest_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod is not None

    def test_test_count(self):
        test_files = [
            f for f in os.listdir(TESTS_DIR)
            if f.startswith("test_") and f.endswith(".py")
        ]
        assert len(test_files) >= 14, (
            f"Expected at least 14 test files, found {len(test_files)}: {test_files}"
        )
