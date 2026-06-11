"""Tests for input processing — URL type identification and target preparation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sca_cli.core.downloader import is_archive, is_git_url, is_http_url, prepare_target


# ── URL type identification ──────────────────────────────────────────

class TestIsHttpUrl:
    """is_http_url — detect HTTP/HTTPS URLs."""

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://github.com/org/repo", True),
            ("http://example.com/archive.zip", True),
            ("git@github.com:org/repo.git", False),
            ("/local/path/to/dir", False),
            ("ssh://git@github.com/org/repo", False),
            ("", False),
        ],
    )
    def test_detection(self, url: str, expected: bool) -> None:
        assert is_http_url(url) is expected


class TestIsGitUrl:
    """is_git_url — detect Git repository URLs."""

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://github.com/org/repo.git", True),
            ("git@github.com:org/repo.git", True),
            ("ssh://git@github.com/org/repo", True),
            ("https://gitlab.com/org/repo", True),
            ("https://bitbucket.org/org/repo", True),
            ("https://example.com/archive.zip", False),
            ("/local/path", False),
            ("https://pypi.org/project/foo", False),
            ("git://github.com/org/repo", True),
        ],
    )
    def test_detection(self, url: str, expected: bool) -> None:
        assert is_git_url(url) is expected


class TestIsArchive:
    """is_archive — detect archive file extensions."""

    @pytest.mark.parametrize(
        ("path_or_url", "expected"),
        [
            ("/tmp/package.zip", True),
            ("https://example.com/pkg.tar", True),
            ("/tmp/file.tar.gz", True),
            ("https://example.com/pkg.tgz", True),
            ("/tmp/script.py", False),
            ("/tmp/directory", False),
            ("readme.md", False),
        ],
    )
    def test_detection(self, path_or_url: str, expected: bool) -> None:
        assert is_archive(path_or_url) is expected


# ── Target preparation ───────────────────────────────────────────────

class TestPrepareTarget:
    """prepare_target — classify and prepare a scan target."""

    def test_local_directory(self, tmp_path: Path) -> None:
        """A local existing directory is classified as 'directory'."""
        result = prepare_target(
            str(tmp_path),
            paths=MagicMock(),
            workspace=MagicMock(),
        )
        assert result.input_type == "directory"
        assert result.path == tmp_path.resolve()

    def test_local_archive(self, tmp_path: Path) -> None:
        """A local .zip file is extracted and classified as 'archive'."""
        archive = tmp_path / "pkg.zip"
        archive.write_text("not a real zip")
        extracted = tmp_path / "extracted"
        workspace = MagicMock()
        workspace.extracted = tmp_path

        with patch("sca_cli.core.downloader.safe_extract_archive") as mock_extract:
            mock_extract.return_value = None
            result = prepare_target(
                str(archive),
                paths=MagicMock(),
                workspace=workspace,
            )
        assert result.input_type == "archive"
        mock_extract.assert_called_once()

    def test_git_url(self) -> None:
        """A Git URL triggers a clone attempt."""
        workspace = MagicMock()
        workspace.input = Path("/tmp")

        with (
            patch("sca_cli.core.downloader.which", return_value="/usr/bin/git"),
            patch("sca_cli.core.downloader.run_tool") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            result = prepare_target(
                "https://github.com/org/repo.git",
                paths=MagicMock(),
                workspace=workspace,
            )
        assert result.input_type == "git"
        mock_run.assert_called_once()
        assert "clone" in str(mock_run.call_args[0][0])

    def test_http_archive_url(self) -> None:
        """An HTTP URL to an archive downloads and extracts."""
        workspace = MagicMock()
        workspace.extracted = Path("/tmp/extracted")
        paths = MagicMock()
        paths.downloads = Path("/tmp/downloads")

        with (
            patch("sca_cli.core.downloader.httpx.stream") as mock_stream,
            patch("sca_cli.core.downloader.safe_extract_archive") as mock_extract,
        ):
            ctx = MagicMock()
            ctx.__enter__.return_value = ctx
            ctx.headers.get.return_value = None
            ctx.iter_bytes.return_value = [b"data"]
            mock_stream.return_value = ctx
            mock_extract.return_value = None

            result = prepare_target(
                "https://example.com/pkg.tar.gz",
                paths=paths,
                workspace=workspace,
            )
        assert result.input_type == "url-archive"

    def test_unsupported_target_raises(self) -> None:
        """An unrecognised target raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Target not found or unsupported"):
            prepare_target(
                "not-a-real-path",
                paths=MagicMock(),
                workspace=MagicMock(),
            )
