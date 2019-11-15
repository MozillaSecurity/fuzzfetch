# coding=utf-8
"""Shim for backported imports."""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=too-many-statements

# shutil.which was added in Python 3.3
try:
    from shutil import which  # noqa pylint: disable=unused-import
except ImportError:
    from backports.shutil_which import which  # noqa pylint: disable=unused-import
