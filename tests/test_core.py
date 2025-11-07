# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch tests"""

import pytest  # pylint: disable=import-error
from freezegun import freeze_time  # pylint: disable=import-error

from fuzzfetch.core import Fetcher
from fuzzfetch.models import BuildFlags, BuildTask, Platform, Product


@pytest.mark.vcr()
@pytest.mark.usefixtures("fetcher_mock_resolve_targets")
def test_extract_build_linux(tmp_path, mocker):
    """Test linux build layout"""

    def fake_extract_tar(_self, _url, path):
        (path / "firefox").touch()

    mocker.patch("fuzzfetch.core.Fetcher.extract_tar", new=fake_extract_tar)

    flags = BuildFlags(debug=True, fuzzing=True)
    platform = Platform("Linux", "x86_64")
    task = next(
        BuildTask.iterall("latest", "central", flags, Product("firefox"), platform)
    )
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
    task = next(
        BuildTask.iterall("latest", "central", flags, Product("firefox"), platform)
    )
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


@freeze_time("2025-11-07")
@pytest.mark.vcr()
@pytest.mark.parametrize(
    "branch, product, expected",
    [
        ("central", "firefox", "m-c-20251107164336-opt"),
        ("try", "firefox", "try-20251107165543-opt"),
        ("autoland", "firefox", "autoland-20251107165513-opt"),
        ("esr140", "firefox", "m-esr140-20251106203603-opt"),
        ("beta", "firefox", "m-b-20251107021527-opt"),
        ("release", "firefox", "m-r-20251106194447-opt"),
        ("central", "thunderbird", "c-c-20251106232556-opt"),
        ("try", "thunderbird", "try-c-c-20251107030132-opt"),
        ("esr140", "thunderbird", "c-esr140-20251107133303-opt"),
        ("beta", "thunderbird", "c-b-20251103170853-opt"),
        ("release", "thunderbird", "c-r-20251106212021-opt"),
    ],
)
def test_auto_name(branch, mocker, product, expected):
    """Test automatic output directory name"""
    mocker.patch("fuzzfetch.models.plat_system", lambda: "Linux")
    mocker.patch("fuzzfetch.models.plat_machine", lambda: "AMD64")
    platform = Platform("Linux", "x86_64")
    fetch = Fetcher(branch, "latest", BuildFlags(), [], platform, product=product)
    assert fetch.get_auto_name() == expected
