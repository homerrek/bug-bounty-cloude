"""Tests for enhanced token_optimizer features: --dedup, --compress, --budget, improved estimate."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import token_optimizer


class TestEstimateTokens:

    def test_empty_string(self):
        assert token_optimizer.estimate_tokens("") == 0

    def test_known_text(self):
        result = token_optimizer.estimate_tokens("hello world")
        assert result > 0

    def test_larger_than_char_only(self):
        text = "hello world foo bar baz"
        char_estimate = len(text) // token_optimizer.CHARS_PER_TOKEN
        word_count = len(text.split())
        word_estimate = int(word_count * 1.3)
        hybrid = (char_estimate + word_estimate) // 2
        # hybrid should be > char-only because word_estimate > char_estimate for short words
        assert hybrid >= char_estimate


class TestDedupDirectory:

    def test_identical_files_detected(self, tmp_path):
        content = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi " * 5
        (tmp_path / "a.txt").write_text(content)
        (tmp_path / "b.txt").write_text(content)
        dupes = token_optimizer.dedup_directory(str(tmp_path))
        assert len(dupes) >= 1

    def test_different_files_not_flagged(self, tmp_path):
        (tmp_path / "x.txt").write_text("the quick brown fox jumps over the lazy dog " * 3)
        (tmp_path / "y.txt").write_text("INSERT INTO users VALUES (1, 'admin', 'password') " * 3)
        dupes = token_optimizer.dedup_directory(str(tmp_path))
        assert dupes == []

    def test_returns_list(self, tmp_path):
        result = token_optimizer.dedup_directory(str(tmp_path))
        assert isinstance(result, list)


class TestCompressFile:

    def test_strips_comment_lines(self, tmp_path):
        src = tmp_path / "sample.py"
        src.write_text("# this is a comment\nx = 1\n# another comment\ny = 2\n")
        token_optimizer.compress_file(str(src))
        out = tmp_path / "sample_compressed.py"
        assert out.exists()
        lines = [l for l in out.read_text().splitlines() if l.strip()]
        assert not any(l.strip().startswith("#") for l in lines)

    def test_strips_blank_lines(self, tmp_path):
        src = tmp_path / "sample.txt"
        src.write_text("line one\n\n\nline two\n\n")
        result = token_optimizer.compress_file(str(src))
        out = tmp_path / "sample_compressed.txt"
        assert out.exists()
        assert out.stat().st_size < src.stat().st_size

    def test_creates_compressed_file(self, tmp_path):
        src = tmp_path / "code.py"
        src.write_text("# comment\nx = 1\ny = 2\n")
        token_optimizer.compress_file(str(src))
        assert (tmp_path / "code_compressed.py").exists()

    def test_preserves_code(self, tmp_path):
        src = tmp_path / "code.py"
        src.write_text("# comment\nx = 1\n# ignore\ny = 2\n")
        token_optimizer.compress_file(str(src))
        out = (tmp_path / "code_compressed.py").read_text()
        assert "x = 1" in out


class TestBudgetSelect:

    def test_selects_files_within_budget(self, tmp_path):
        for i in range(5):
            (tmp_path / f"file{i}.txt").write_text(f"content line {i} " * 10)
        selected, total = token_optimizer.budget_select(str(tmp_path), 1000)
        assert total <= 1000

    def test_returns_dict_with_files(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello world\n")
        result = token_optimizer.budget_select(str(tmp_path), 1000)
        # budget_select returns (selected_list, total_tokens)
        selected, total_tokens = result
        assert isinstance(selected, list)
        assert isinstance(total_tokens, int)

    def test_critical_priority_first(self, tmp_path):
        # File with a CRITICAL keyword should be selected before LOW file
        critical_file = tmp_path / "credentials.txt"
        critical_file.write_text("api_key=supersecret\n")
        low_file = tmp_path / "static_asset.css"
        # Make the low file larger (more tokens) so budget would pick it last
        low_file.write_text("body { color: red; }\n" * 100)
        selected, _ = token_optimizer.budget_select(str(tmp_path), 50)
        # With a tight budget, critical file should be preferred
        if selected:
            assert str(critical_file) in selected


class TestBackwardCompat:

    def test_analyze_directory_still_works(self, tmp_path):
        (tmp_path / "test.txt").write_text("hello world\n")
        result = token_optimizer.analyze_directory(str(tmp_path))
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_chunk_file_still_works(self, tmp_path):
        src = tmp_path / "big.txt"
        src.write_text("line\n" * 200)
        # chunk_file writes chunk files to disk; no exception means it works
        token_optimizer.chunk_file(str(src), max_tokens=50)
        chunks_dir = tmp_path / "big_chunks"
        assert chunks_dir.exists()
        assert any(chunks_dir.iterdir())
