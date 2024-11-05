# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch internal model tests"""

from datetime import datetime
from unittest.mock import patch

import pytest  # pylint: disable=import-error

from fuzzfetch import FetcherException
from fuzzfetch.models import HgRevision, Platform


@pytest.mark.vcr
@pytest.mark.parametrize(
    "known_branch, known_revision",
    [
        ["autoland", "9efa2d7e9e4c"],
        ["central", "2cb6128d7dca"],
        ["release", "16fc978cb4f0"],
        ["beta", "64afe096714f"],
        ["try", "001e4eea9c6d"],
    ],
)
def test_hgrevision_properties(known_branch, known_revision):
    """Test HgRevision properties with a real revision and branch."""
    revision = HgRevision(revision=known_revision, branch=known_branch)

    assert isinstance(revision.pushdate, datetime)
    assert revision.pushdate.tzinfo is not None
    assert revision.pushdate.tzinfo.zone == "EST"

    assert isinstance(revision.hash, str)
    assert len(revision.hash) == 40


def test_platform_initialization():
    """Test initialization of Platform with valid system and machine."""
    platform = Platform(system="Linux", machine="x86_64")
    assert platform.system == "Linux"
    assert platform.machine == "x86_64"
    assert platform.gecko_platform == "linux64"


def test_platform_initialization_with_alias():
    """Test initialization with a CPU alias."""
    platform = Platform(system="Linux", machine="x64")
    assert platform.system == "Linux"
    assert platform.machine == "x86_64"
    assert platform.gecko_platform == "linux64"


def test_platform_initialization_unsupported_system():
    """Test initialization raises error for unsupported system."""
    with pytest.raises(FetcherException, match="Unknown system: SunOS"):
        Platform(system="SunOS", machine="x86_64")


def test_platform_initialization_unsupported_machine():
    """Test initialization raises error for unsupported machine."""
    with pytest.raises(FetcherException, match="Unknown machine for Linux: sparc64"):
        Platform(system="Linux", machine="sparc64")


@pytest.mark.parametrize(
    "build_string, expected",
    [
        ("macosx64-aarch64", ("Darwin", "arm64", "macosx64-aarch64")),
        ("linux64", ("Linux", "x86_64", "linux64")),
        ("win64-aarch64", ("Windows", "arm64", "win64-aarch64")),
        ("android-aarch64", ("Android", "arm64", "android-aarch64")),
    ],
)
def test_from_platform_guess(build_string, expected):
    """Test from_platform_guess method with valid build strings."""
    platform = Platform.from_platform_guess(build_string)
    assert platform.system == expected[0]
    assert platform.machine == expected[1]
    assert platform.gecko_platform == expected[2]


def test_from_platform_guess_invalid():
    """Test from_platform_guess raises error for unknown platform string."""
    with pytest.raises(
        FetcherException, match="Could not extract platform from unknown_build"
    ):
        Platform.from_platform_guess("unknown_build")


@pytest.mark.parametrize(
    "system, machine, native_system, native_machine, expected_prefix",
    [
        ("Linux", "x86_64", "Linux", "x86_64", ""),
        ("Linux", "x86_64", "Windows", "x86_64", "linux64-"),
        ("Android", "arm64", "Linux", "x86_64", "android-arm64-"),
        ("Windows", "x86", "Windows", "x86_64", "win32-"),
    ],
)
@patch("platform.system")
@patch("platform.machine")
def test_auto_name_prefix(
    mock_machine,
    mock_system,
    system,
    machine,
    native_system,
    native_machine,
    expected_prefix,
):
    """Test auto_name_prefix method generates correct prefixes."""
    # Mock platform.system and platform.machine to simulate native platform
    mock_system.return_value = native_system
    mock_machine.return_value = native_machine

    # Create a Platform instance
    platform = Platform(system=system, machine=machine)

    # Assert that the auto_name_prefix output matches the expected prefix
    assert platform.auto_name_prefix() == expected_prefix
