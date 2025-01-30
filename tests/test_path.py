# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch path module tests"""

import os
import stat
import sys
from unittest.mock import Mock, patch

import pytest  # pylint: disable=import-error

from fuzzfetch.path import islink, onerror, rmtree, symlink


@pytest.mark.parametrize("platform", ["win32", "linux"])
@patch("fuzzfetch.path.os.access")
@patch("fuzzfetch.path.os.chmod")
@patch("fuzzfetch.path.sys.platform")
def test_onerror_permission_error(
    mock_platform,
    mock_chmod,
    mock_access,
    tmp_path,
    platform,
):
    """Test onerror function adds write permission and retries on access error."""
    mock_platform.return_value = platform
    mock_access.return_value = False  # Simulate access denied error
    mock_func = Mock()

    path = tmp_path / "testfile"
    path.touch()
    path.chmod(0o444)  # Make read-only

    # Call the onerror function
    onerror(mock_func, path, None)

    # Check that chmod was called with the specific permission update
    mock_chmod.assert_any_call(path, stat.S_IWUSR)
    mock_func.assert_called_once_with(path)


@patch("fuzzfetch.path.os.access", return_value=True)
def test_onerror_re_raises_other_errors(mock_access, tmp_path):
    """Test onerror raises exceptions not related to access errors."""
    path = tmp_path / "testfile"
    path.touch()

    # Create a mock function that raises an exception when called
    mock_func = Mock(side_effect=Exception("Test exception"))

    # Manually raise an exception and call onerror within the exception context
    with pytest.raises(Exception, match="Test exception"):
        try:
            raise OSError("Test exception")
        except OSError:
            onerror(mock_func, path, None)

    # Ensure os.access was called with the correct path
    mock_access.assert_called_once_with(path, os.W_OK)


def test_rmtree_non_directory():
    """Test rmtree raises RuntimeError when called on a non-directory path."""
    path = "not_a_directory"
    with pytest.raises(RuntimeError, match="rmtree called on non-link/folder"):
        rmtree(path)


def test_rmtree_deletes_files_and_folders(tmp_path):
    """Test rmtree removes files and folders in a directory."""
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    file_path = subdir / "file.txt"
    file_path.touch()

    assert subdir.exists()
    assert file_path.exists()

    rmtree(tmp_path)

    assert not subdir.exists()
    assert not file_path.exists()


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows-only test")
@patch("fuzzfetch.path.os.lstat")
def test_islink_junction_point_windows(mock_lstat, tmp_path):
    """Test islink detects junction points on Windows."""
    mock_lstat.return_value.st_mode = stat.S_IFDIR
    mock_lstat.return_value.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT

    assert islink(tmp_path) is True
    mock_lstat.assert_called_once_with(tmp_path)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Non-Windows test")
@patch("fuzzfetch.path.os.path.islink", return_value=True)
def test_islink_non_windows(mock_islink, tmp_path):
    """Test islink uses os.path.islink on non-Windows systems."""
    assert islink(tmp_path) is True
    mock_islink.assert_called_once_with(tmp_path)


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows-only test")
@patch("fuzzfetch.path._winapi.CreateJunction")
def test_symlink_junction_windows(mock_create_junction, tmp_path):
    """Test symlink uses CreateJunction for Windows junction points."""
    target = tmp_path / "target"
    link = tmp_path / "link"
    target.mkdir()

    symlink(target, link)

    mock_create_junction.assert_called_once_with(str(target), str(link))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Non-Windows test")
@patch("fuzzfetch.path.os.symlink")
def test_symlink_non_windows(mock_symlink, tmp_path):
    """Test symlink creates symbolic links on non-Windows systems."""
    target = tmp_path / "target"
    link = tmp_path / "link"
    target.mkdir()

    symlink(target, link)

    mock_symlink.assert_called_once_with(target, link)
