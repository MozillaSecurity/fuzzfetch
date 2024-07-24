"""fuzzfetch tests"""

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from unittest.mock import patch

import pytest  # pylint: disable=import-error

from fuzzfetch.core import Fetcher
from fuzzfetch.models import BuildFlags, BuildTask, Platform


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_extract_build_linux(tmp_path):
    """test linux build layout"""
    flags = BuildFlags(debug=True, fuzzing=True)
    platform = Platform("Linux", "x86_64")

    def fake_extract_tar(_self, _url, path):
        (path / "firefox").touch()

    with patch("fuzzfetch.core.Fetcher.extract_tar", new=fake_extract_tar):
        fetcher = Fetcher(
            "central",
            BuildTask("latest", "central", flags, platform),
            flags,
            ["firefox"],
            platform,
        )
        fetcher.extract_build(tmp_path)
        assert set(tmp_path.glob("**/*")) == {
            tmp_path / "taskcluster-build-task",
            tmp_path / "firefox",
            tmp_path / "firefox.fuzzmanagerconf",
            tmp_path / "symbols",
        }


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_extract_build_macos(tmp_path):
    """test macos build layout"""
    flags = BuildFlags(debug=True, fuzzing=True)
    platform = Platform("Darwin", "x86_64")

    def fake_extract_dmg(_self, path):
        ff_path = path / "Fake.app" / "Contents" / "MacOS"
        ff_path.mkdir(parents=True)
        (ff_path / "firefox").touch()

    with patch("fuzzfetch.core.Fetcher.extract_dmg", new=fake_extract_dmg):
        fetcher = Fetcher(
            "central",
            BuildTask("latest", "central", flags, platform),
            flags,
            ["firefox"],
            platform,
        )
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
