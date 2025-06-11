# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch tests"""

import pytest  # pylint: disable=import-error

from fuzzfetch.core import Fetcher
from fuzzfetch.models import BuildFlags, BuildTask, Platform


@pytest.mark.vcr()
@pytest.mark.usefixtures("fetcher_mock_resolve_targets")
def test_extract_build_linux(tmp_path, mocker):
    """Test linux build layout"""

    def fake_extract_tar(_self, _url, path):
        (path / "firefox").touch()

    mocker.patch("fuzzfetch.core.Fetcher.extract_tar", new=fake_extract_tar)

    flags = BuildFlags(debug=True, fuzzing=True)
    platform = Platform("Linux", "x86_64")
    task = BuildTask("latest", "central", flags, platform)
    fetcher = Fetcher("central", task, flags, ["firefox"], platform)
    fetcher.extract_build(tmp_path)
    assert set(tmp_path.glob("**/*")) == {
        tmp_path / "taskcluster-build-task",
        tmp_path / "firefox",
        tmp_path / "firefox.fuzzmanagerconf",
    }


@pytest.mark.vcr()
@pytest.mark.usefixtures("fetcher_mock_resolve_targets")
def test_extract_build_macos(tmp_path, mocker):
    """Test macOS build layout"""

    def fake_extract_dmg(_self, path):
        ff_path = path / "Fake.app" / "Contents" / "MacOS"
        ff_path.mkdir(parents=True)
        (ff_path / "firefox").touch()

    # pylint: disable=unused-argument
    def fake_extract_zip(_self, url, path):
        pass

    mocker.patch("fuzzfetch.core.Fetcher.extract_dmg", fake_extract_dmg)
    mocker.patch("fuzzfetch.core.Fetcher.extract_zip", fake_extract_zip)

    flags = BuildFlags(debug=True, fuzzing=True)
    platform = Platform("Darwin", "x86_64")
    task = BuildTask("latest", "central", flags, platform)
    fetcher = Fetcher("central", task, flags, ["firefox"], platform)
    fetcher.extract_build(tmp_path)
    assert set(tmp_path.glob("**/*")) == {
        tmp_path / "taskcluster-build-task",
        tmp_path / "Fake.app",
        tmp_path / "Fake.app" / "Contents",
        tmp_path / "Fake.app" / "Contents" / "MacOS",
        tmp_path / "Fake.app" / "Contents" / "MacOS" / "firefox",
        tmp_path / "Fake.app" / "Contents" / "MacOS" / "firefox.fuzzmanagerconf",
        tmp_path / "Fake.app" / "Contents" / "MacOS" / "symbols",
    }
