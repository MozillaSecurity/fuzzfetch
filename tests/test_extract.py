# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch extract tests"""

import tarfile
import zipfile
from unittest.mock import patch

import pytest  # pylint: disable=import-error

from fuzzfetch.extract import LBZIP2_PATH, XZ_PATH, extract_tar, extract_zip


def create_test_archive(tmp_path, extension, mode):
    """Helper function to create a test archive with specified extension and mode."""
    (tmp_path / "empty").touch()
    archive_path = tmp_path / f"test{extension}"
    with tarfile.open(archive_path, f"w:{mode}" if mode != "r" else "w") as tar:
        tar.add(tmp_path / "empty", arcname="firefox/a.txt")
        tar.add(tmp_path / "empty", arcname="b.txt")
        tar.add(tmp_path / "empty", arcname="gtest/c.txt")
    return archive_path


def test_zipfile_extract(tmp_path):
    """basic extract_zip functions"""
    (tmp_path / "empty").touch()
    (tmp_path / "folder").mkdir()
    with zipfile.ZipFile(tmp_path / "test.zip", "w") as zip_fp:
        zip_fp.write(tmp_path / "empty", "./firefox/firefox")
        zip_fp.write(tmp_path / "empty", "buildinfo.txt")
        zip_fp.write(tmp_path / "folder", "folder")

    (tmp_path / "out").mkdir()
    extract_zip(tmp_path / "test.zip", tmp_path / "out")
    assert set((tmp_path / "out").glob("**/*")) == {
        tmp_path / "out" / "firefox",
        tmp_path / "out" / "folder",
        tmp_path / "out" / "buildinfo.txt",
    }
    assert (tmp_path / "out" / "firefox").is_file()
    assert (tmp_path / "out" / "folder").is_dir()
    assert (tmp_path / "out" / "buildinfo.txt").is_file()


@pytest.mark.parametrize(
    "extension, mode",
    [
        (".tar", "tar"),
        (".tar.bz2", "bz2"),
        (".tar.gz", "gz"),
        (".tar.xz", "xz"),
    ],
)
@patch("fuzzfetch.extract.LBZIP2_PATH", None)
@patch("fuzzfetch.extract.XZ_PATH", None)
def test_tarfile_good(tmp_path, extension, mode):
    """Test extract_tar with different extensions."""
    archive_path = create_test_archive(tmp_path, extension, mode)
    extract_tar(archive_path, mode=mode, path=tmp_path / "out")
    assert set((tmp_path / "out").glob("**/*")) == {
        tmp_path / "out" / "a.txt",
        tmp_path / "out" / "b.txt",
        tmp_path / "out" / "gtest",
        tmp_path / "out" / "gtest" / "c.txt",
    }


@pytest.mark.parametrize(
    "extension, mode, skip_if, reason",
    [
        (".tar.bz2", "bz2", LBZIP2_PATH is None, "Could not find lbzip2 binary"),
        (".tar.xz", "xz", XZ_PATH is None, "Could not find xz binary"),
    ],
    ids=["tar.bz2", "tar.xz"],
)
def test_extract_tar_modes(tmp_path, extension, mode, skip_if, reason):
    """Test extract_tar with different archive types and modes."""
    if skip_if:
        pytest.skip(reason)

    archive_path = create_test_archive(tmp_path, extension, mode)
    extract_tar(archive_path, mode=mode, path=tmp_path / "out")
    assert set((tmp_path / "out").glob("**/*")) == {
        tmp_path / "out" / "a.txt",
        tmp_path / "out" / "b.txt",
        tmp_path / "out" / "gtest",
        tmp_path / "out" / "gtest" / "c.txt",
    }


def test_tarfile_traversal_exc(tmp_path):
    """CVE-2007-4559"""
    (tmp_path / "empty").touch()
    with tarfile.open(tmp_path / "test.tar", "w") as tar:
        tar.add(tmp_path / "empty", "firefox/a.txt")
        tar.add(tmp_path / "empty", "b.txt")
        tar.add(tmp_path / "empty", "../x.txt")
    with pytest.raises(Exception) as exc:
        extract_tar(tmp_path / "test.tar", path=tmp_path / "out")
    assert "path traversal" in str(exc.value).lower()
    assert set((tmp_path / "out").glob("**/*")) == set()
