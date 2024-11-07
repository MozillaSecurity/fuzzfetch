# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Offline cache for testing code using requests_mock"""

from unittest.mock import patch

import pytest  # pylint: disable=import-error

from fuzzfetch import FetcherArgs


@pytest.fixture
def fetcher_mock_resolve_targets():
    """mock Fetcher.resolve_targets to prevent downloading builds on init"""
    with patch("fuzzfetch.core.Fetcher.resolve_targets") as mock:
        yield mock


@pytest.fixture
def fetcher_args():
    """Fixture providing a FetcherArgs instance for tests."""
    return FetcherArgs()


@pytest.fixture(scope="module")
def vcr_config():
    """Configuration settings for pytest-recording."""
    return {
        "decode_compressed_response": True,
        "allow_playback_repeats": True,
    }
