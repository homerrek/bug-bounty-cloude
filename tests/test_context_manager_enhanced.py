"""Tests for enhanced context_manager features."""
import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

# Patch the tools.token_optimizer import used inside context_manager
import token_optimizer
import types
tools_pkg = types.ModuleType("tools")
tools_pkg.token_optimizer = token_optimizer
sys.modules.setdefault("tools", tools_pkg)
sys.modules.setdefault("tools.token_optimizer", token_optimizer)

from context_manager import ContextManager, AVAILABLE_CONTEXT


def _make_cm(tmp_path, name="test-session"):
    """Create a ContextManager rooted in tmp_path."""
    orig = os.getcwd()
    os.chdir(tmp_path)
    cm = ContextManager(name)
    os.chdir(orig)
    return cm, tmp_path


class TestAutoCompact:

    def test_no_compact_when_under_80(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            from unittest.mock import patch
            with patch.object(cm, "compact") as mock_compact:
                cm.add_item("small content", auto_compact=True)
                mock_compact.assert_not_called()
        finally:
            os.chdir(os.path.dirname(__file__))

    def test_compact_triggered_at_80(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            from unittest.mock import patch
            # Force total_tokens above 80% threshold
            cm.context["total_tokens"] = int(AVAILABLE_CONTEXT * 0.85)
            with patch.object(cm, "compact") as mock_compact:
                cm.add_item("trigger compact", auto_compact=True)
                mock_compact.assert_called_once()
        finally:
            os.chdir(os.path.dirname(__file__))


class TestSnapshot:

    def test_save_snapshot(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            cm.add_item("finding A")
            cm.save_snapshot("snap1")
            snap_path = base / ".context" / "test-session" / "snapshots" / "snap1.json"
            assert snap_path.exists()
        finally:
            os.chdir(os.path.dirname(__file__))

    def test_restore_snapshot(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            cm.add_item("finding A")
            original_count = len(cm.context["items"])
            cm.save_snapshot("snap1")
            cm.add_item("finding B")
            assert len(cm.context["items"]) == original_count + 1
            cm.restore_snapshot("snap1")
            assert len(cm.context["items"]) == original_count
        finally:
            os.chdir(os.path.dirname(__file__))

    def test_restore_missing_snapshot(self, tmp_path, capsys):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            cm.restore_snapshot("nonexistent")
            captured = capsys.readouterr()
            assert "not found" in captured.out.lower() or "error" in captured.out.lower()
        finally:
            os.chdir(os.path.dirname(__file__))


class TestDiffSnapshots:

    def test_diff_added_items(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            cm.add_item("item one")
            cm.save_snapshot("before")
            cm.add_item("item two")
            cm.save_snapshot("after")
            diff = cm.diff_snapshots("before", "after")
            assert len(diff["added"]) == 1
            assert len(diff["removed"]) == 0
        finally:
            os.chdir(os.path.dirname(__file__))

    def test_diff_empty_when_same(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            cm.add_item("only item")
            cm.save_snapshot("snap_a")
            cm.save_snapshot("snap_b")
            diff = cm.diff_snapshots("snap_a", "snap_b")
            assert diff["added"] == []
            assert diff["removed"] == []
        finally:
            os.chdir(os.path.dirname(__file__))


class TestGetItemContent:

    def test_get_content_by_id(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            item_id = cm.add_item("secret payload content")
            content = cm.get_item_content(item_id)
            assert content == "secret payload content"
        finally:
            os.chdir(os.path.dirname(__file__))

    def test_get_content_missing_id(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            result = cm.get_item_content(9999)
            assert result is None
        finally:
            os.chdir(os.path.dirname(__file__))


class TestLazyLoading:

    def test_metadata_only_has_no_content(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            cm.add_item("full content here", item_type="finding")
            meta_items = cm.get_item_metadata_only()
            assert len(meta_items) >= 1
            for item in meta_items:
                assert "content" not in item
        finally:
            os.chdir(os.path.dirname(__file__))

    def test_full_content_accessible(self, tmp_path):
        cm, base = _make_cm(tmp_path)
        os.chdir(base)
        try:
            item_id = cm.add_item("full content here")
            content = cm.get_item_content(item_id)
            assert "full content here" in content
        finally:
            os.chdir(os.path.dirname(__file__))
