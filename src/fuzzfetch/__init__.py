# coding=utf-8
"fuzzfetch module"
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=wrong-import-position


class FetcherException(Exception):
    """Exception raised for any Fetcher errors"""


from .args import FetcherArgs  # noqa
from .core import Fetcher, __version__  # noqa
from .download import download_url, get_url, iec, si  # noqa
from .models import BuildFlags, BuildSearchOrder, BuildTask, Platform  # noqa

__author__ = "Jesse Schwartzentruber, Jason Kratzer"
