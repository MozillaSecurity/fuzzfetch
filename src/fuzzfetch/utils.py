# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Assorted fuzzfetch utilities"""
import re
from datetime import datetime

from pytz import timezone

from .errors import FetcherException


def extract_branch_from_ns(build: str) -> str:
    """Identify branch from namespace build string.

    Args:
        build: Build string.
    """
    branch = re.search(r"\.(autoland|try|mozilla-(?P<branch>[a-z]+[0-9]*))\.", build)

    if branch:
        return branch.group("branch")

    raise FetcherException("Unable to identify branch from namespace")


def is_date(build: str) -> bool:
    """Determine if the supplied build string is a date.

    Args:
        build: Build string.
    """
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", build))


def is_rev(build: str) -> bool:
    """Determine if the supplied build string is a date.

    Args:
        build: Build string.
    """
    return bool(re.match(r"^([0-9A-F]{12}|[0-9A-F]{40})$", build, re.IGNORECASE))


def is_namespace(build: str) -> bool:
    """Determine if the supplied build string is a namespace.

    Args:
        build: Build string.
    """
    return not is_date(build) and not is_rev(build) and build != "latest"


def _create_utc_datetime(datetime_string: str) -> datetime:
    """Convert build_string to time-zone aware datetime object"""
    dt_obj = datetime.strptime(datetime_string, "%Y%m%d%H%M%S")
    return timezone("UTC").localize(dt_obj)
