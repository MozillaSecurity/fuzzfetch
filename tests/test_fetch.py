#!/usr/bin/env python
# coding=utf-8
"fuzzfetch tests"
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import, division, print_function, unicode_literals

import calendar
import itertools
import logging
import platform
import time

import pytest
import fuzzfetch

log = logging.getLogger("fuzzfetch_test")  # pylint: disable=invalid-name
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("flake8").setLevel(logging.WARNING)


def format_elapsed(elapsed):
    """Given a number of elapsed seconds, format it into a human readable string."""
    periods = ((60, "second"), (60, "minute"), (24, "hour"), (7, "day"))
    period_strs = []
    for units_per_period, period_str in periods:
        elapsed, period_units = divmod(elapsed, units_per_period)
        if period_units or (not period_strs and not elapsed):
            period_strs.append("%d %s%s" % (period_units, period_str, "s" if period_units != 1 else ""))
    if elapsed:
        period_strs.append("%d week%s" % (elapsed, "s" if elapsed != 1 else ""))
    return ", ".join(reversed(period_strs))


def get_builds_to_test():
    """Get permutations for testing build branches and flags"""
    possible_flags = (fuzzfetch.BuildFlags(asan=False, debug=False, fuzzing=False, coverage=False),  # opt
                      fuzzfetch.BuildFlags(asan=False, debug=True, fuzzing=False, coverage=False),  # debug
                      fuzzfetch.BuildFlags(asan=False, debug=False, fuzzing=False, coverage=True),  # cov
                      fuzzfetch.BuildFlags(asan=True, debug=False, fuzzing=False, coverage=False),  # asan-opt
                      fuzzfetch.BuildFlags(asan=True, debug=True, fuzzing=False, coverage=False),  # asan-debug
                      fuzzfetch.BuildFlags(asan=True, debug=False, fuzzing=True, coverage=False))  # asan-fuzz
    possible_branches = ("central", "inbound", "esr", "beta", "release")

    for branch, flags in itertools.product(possible_branches, possible_flags):
        if platform.system() == "Linux" and flags.coverage and branch != "central":
            # coverage builds are only done on central
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif platform.system() == "Linux" and flags.fuzzing and branch == "esr":
            # fuzzing builds not done on esr
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif platform.system() == "Darwin" and (flags.asan or flags.coverage):
            # asan/coverage builds not done for macos yet
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif platform.system() == "Windows" and flags.asan and branch not in {"central", "inbound"}:
            # asan builds for windows are only done for central/inbound
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif platform.system() == "Windows" and flags.coverage:
            # coverage builds not done for windows yet
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif platform.system() == "Windows" and flags.asan and (flags.fuzzing or flags.debug):
            # windows only has asan-opt ?
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif platform.system() == "Windows" and flags.asan:
            # https://bugzilla.mozilla.org/show_bug.cgi?id=1394543
            yield pytest.param(branch, flags, marks=pytest.mark.skip)
        elif branch == "release":
            yield pytest.param(branch, flags, marks=pytest.mark.xfail)  # ?
        else:
            yield pytest.param(branch, flags)


@pytest.mark.parametrize('branch, build_flags', get_builds_to_test())
def test_metadata(branch, build_flags):
    """Instantiate a Fetcher (which downloads metadata from TaskCluster) and check that the build is recent"""
    # BuildFlags(asan, debug, fuzzing, coverage)
    # Fetcher(target, branch, build, flags)
    for as_args in (True, False):  # try as API and as command line
        if as_args:
            args = ["--" + name for arg, name in zip(build_flags, fuzzfetch.BuildFlags._fields) if arg]
            fetcher = fuzzfetch.Fetcher.from_args(["--" + branch] + args)[0]
        else:
            if branch == "esr":
                branch = "esr52"
            fetcher = fuzzfetch.Fetcher("firefox", branch, "latest", build_flags)
        log.debug("succeeded creating Fetcher")

        log.debug("buildid: %s", fetcher.build_id)
        log.debug("hgrev: %s", fetcher.changeset)

        # check that build is not too old
        if branch.startswith("esr"):
            max_age = (3 * 24 + 1) * 60 * 60  # 3d
        elif branch == "release":
            max_age = (7 * 24 + 1) * 60 * 60  # 1w
        else:
            max_age = (24 + 1) * 60 * 60  # 1d
        time_obj = time.strptime(fetcher.build_id, "%Y%m%d%H%M%S")
        timestamp = calendar.timegm(time_obj)
        assert timestamp > time.time() - max_age, "%s is more than %s old" % (fetcher.build_id, format_elapsed(max_age))

        # yyyy-mm-dd is also accepted as a build input
        date_str = "%d-%02d-%02d" % (time_obj.tm_year, time_obj.tm_mon, time_obj.tm_mday)
        if as_args:
            fuzzfetch.Fetcher.from_args(["--" + branch, "--build", date_str] + args)
        else:
            fuzzfetch.Fetcher("firefox", branch, date_str, build_flags)

        # hg rev is also accepted as a build input
        rev = fetcher.changeset
        if as_args:
            fuzzfetch.Fetcher.from_args(["--" + branch, "--build", rev] + args)
        else:
            fuzzfetch.Fetcher("firefox", branch, rev, build_flags)
        # namespace = fetcher.build

        # TaskCluster namespace is also accepted as a build input
        # namespace = ?
        # fuzzfetch.Fetcher("firefox", branch, namespace, (asan, debug, fuzzing, coverage))
