# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Assorted fuzzfetch utilities"""

import pytest  # pylint: disable=import-error

from fuzzfetch.utils import is_date, is_namespace, is_rev


@pytest.mark.parametrize(
    "build, expected_date, expected_rev, expected_namespace",
    [
        ("2024-01-01", True, False, False),  # Date string
        ("20240101120000", True, False, False),  # build id Date
        ("a1b2c3d4e5f6", False, True, False),  # 12-character rev
        ("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", False, True, False),  # 40-char rev
        (
            "gecko.v2.mozilla-central.latest.firefox.linux64-opt",
            False,
            False,
            True,
        ),  # Namespace
        ("latest", False, False, False),
    ],
)
def test_build_identifiers(build, expected_date, expected_rev, expected_namespace):
    """Test is_date, is_rev, and is_namespace functions."""
    assert is_date(build) == expected_date
    assert is_rev(build) == expected_rev
    assert is_namespace(build) == expected_namespace
