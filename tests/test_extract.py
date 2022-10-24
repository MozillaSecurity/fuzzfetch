"""fuzzfetch extract tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import tarfile

import pytest  # pylint: disable=import-error

from fuzzfetch.extract import extract_tar


def test_tarfile_good(tmp_path):
    """basic extract_tar functions"""
    (tmp_path / "empty").touch()
    with tarfile.open(tmp_path / "test.tar", "w") as tar:
        tar.add(tmp_path / "empty", "firefox/a.txt")
        tar.add(tmp_path / "empty", "b.txt")
    extract_tar(tmp_path / "test.tar", path=tmp_path / "out")
    assert set((tmp_path / "out").glob("**/*")) == {
        tmp_path / "out" / "a.txt",
        tmp_path / "out" / "b.txt",
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
