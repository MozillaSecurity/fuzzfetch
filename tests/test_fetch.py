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


@pytest.mark.parametrize(
    'branch, asan, debug, fuzzing, coverage, as_args',
    itertools.product(("central", "inbound", "esr", "beta", "release"),  # branch
                      (True, False),  # asan
                      (True, False),  # debug
                      (True, False),  # fuzzing
                      (True, False),  # coverage
                      (True, False)))  # as_args
def test_metadata(branch, asan, debug, fuzzing, coverage, as_args):
    """Instantiate a Fetcher (which downloads metadata from TaskCluster) and check that the build is recent"""
    # BuildFlags(asan, debug, fuzzing, coverage)
    # Fetcher(target, branch, build, flags)
    try:
        if as_args:
            arg_strs = ["asan", "debug", "fuzzing", "coverage"]
            args = ["--" + arg_strs[i] for i, arg in enumerate((asan, debug, fuzzing, coverage)) if arg]
            fetcher = fuzzfetch.Fetcher.from_args(["--" + branch] + args)[0]
        else:
            if branch == "esr":
                branch = "esr52"
            fetcher = fuzzfetch.Fetcher("firefox", branch, "latest", (asan, debug, fuzzing, coverage))
        log.debug("succeeded creating Fetcher")
    except fuzzfetch.FetcherException:
        if asan or fuzzing or coverage:
            pytest.skip("%r doesn't seem to exist" % (fuzzfetch.BuildFlags(asan, debug, fuzzing, coverage),))
        raise

    log.debug("buildid: %s", fetcher.build_id)
    log.debug("hgrev: %s", fetcher.changeset)

    # check that build is not too old
    if branch.startswith("esr"):
        max_age = 3 * 24 * 60 * 60  # 3d
    elif branch == "release":
        max_age = 7 * 24 * 60 * 60  # 1w
    else:
        max_age = 24 * 60 * 60  # 1d
    time_obj = time.strptime(fetcher.build_id, "%Y%m%d%H%M%S")
    timestamp = calendar.timegm(time_obj)
    assert timestamp > time.time() - max_age, "%s is more than %s old" % (fetcher.build_id, format_elapsed(max_age))

    # yyyy-mm-dd is also accepted as a build input
    date_str = "%d-%02d-%02d" % (time_obj.tm_year, time_obj.tm_mon, time_obj.tm_mday)
    if as_args:
        fuzzfetch.Fetcher.from_args(["--" + branch, "--build", date_str] + args)
    else:
        fuzzfetch.Fetcher("firefox", branch, date_str, (asan, debug, fuzzing, coverage))

    # hg rev is also accepted as a build input
    rev = fetcher.changeset
    if as_args:
        fuzzfetch.Fetcher.from_args(["--" + branch, "--build", rev] + args)
    else:
        fuzzfetch.Fetcher("firefox", branch, rev, (asan, debug, fuzzing, coverage))
    # namespace = fetcher.build

    # TaskCluster namespace is also accepted as a build input
    # namespace = ?
    # fuzzfetch.Fetcher("firefox", branch, namespace, (asan, debug, fuzzing, coverage))
