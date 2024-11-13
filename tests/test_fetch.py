# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch tests"""

import logging
from dataclasses import fields
from datetime import datetime
from itertools import product

import pytest  # pylint: disable=import-error
from freezegun import freeze_time  # pylint: disable=import-error

from fuzzfetch import (
    BuildFlags,
    BuildSearchOrder,
    Fetcher,
    FetcherException,
    Platform,
    is_date,
    is_rev,
)

LOG = logging.getLogger("fuzzfetch_test")
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("flake8").setLevel(logging.WARNING)

DEFAULT_TARGETS = ("firefox",)


def get_builds_to_test():
    """Get permutations for testing build branches and flags."""
    possible_flags = (
        # opt
        BuildFlags(),
        # debug
        BuildFlags(debug=True),
        # ccov
        BuildFlags(coverage=True),
        # asan-opt
        BuildFlags(asan=True),
        # asan-opt-fuzzing
        BuildFlags(asan=True, fuzzing=True),
        # tsan-opt
        BuildFlags(tsan=True),
        # tsan-opt-fuzzing
        BuildFlags(tsan=True, fuzzing=True),
        # debug-fuzzing
        BuildFlags(debug=True, fuzzing=True),
        # ccov-fuzzing
        BuildFlags(fuzzing=True, coverage=True),
        # valgrind-opt
        BuildFlags(valgrind=True),
    )
    possible_branches = ("central", "try", "esr-stable")
    possible_os = ("Android", "Darwin", "Linux", "Windows")
    possible_cpus = ("x86", "x64", "arm", "arm64")

    for branch, flags, os_, cpu in product(
        possible_branches, possible_flags, possible_os, possible_cpus
    ):
        try:
            Platform(os_, cpu)
        except FetcherException:
            continue
        opt = not any(flags)
        esr = branch.startswith("esr")
        if flags.coverage and (
            os_ not in {"Linux", "Windows"} or cpu != "x64" or branch != "central"
        ):
            # coverage builds not done for android/macos
            # coverage builds are only done on central
            continue
        if flags.asan and cpu == "arm":
            continue
        if flags.tsan and ((cpu != "x64" or os_ != "Linux") or esr):
            continue
        if flags.valgrind:
            continue
        if cpu == "arm64" and os_ == "Linux" and not opt:
            continue
        if cpu == "arm64" and os_ == "Darwin" and not (opt or flags.fuzzing):
            continue
        if branch == "central" and cpu == "x86" and os_ == "Linux" and flags.fuzzing:
            continue
        if (os_, cpu) in {
            ("Darwin", "x64"),
            ("Linux", "x86"),
        } and flags == BuildFlags(asan=True):
            continue
        if os_ == "Android":
            if cpu == "x86":
                continue
            if flags.fuzzing and (cpu != "x86" or flags.asan or not flags.debug):
                continue
            if flags.debug and not flags.fuzzing and cpu != "arm":
                continue
            if not flags.fuzzing and flags.asan:
                continue
            if esr:
                continue
        if os_ == "Windows":
            if flags.asan and branch != "central":
                # asan builds for windows are only done for central
                continue
            if flags.asan and (flags.fuzzing or flags.debug):
                # windows only has asan-opt ?
                continue
            if cpu == "arm64" and flags.fuzzing and flags.debug:
                continue
            if cpu != "x64" and flags.asan:
                # windows asan builds are x64 only atm
                continue
            if esr and flags.fuzzing:
                continue
        if os_ == "Linux" and cpu == "x86" and flags.fuzzing and esr:
            continue
        if branch == "esr-stable":
            if cpu.startswith("arm"):
                # arm builds aren't available for esr-stable
                continue

        yield pytest.param(
            branch,
            flags,
            os_,
            cpu,
            id=f"{branch} [{os_}-{cpu}{flags.build_string()}]",
        )


@pytest.mark.vcr()
@pytest.mark.parametrize("branch, build_flags, os_, cpu", get_builds_to_test())
@pytest.mark.parametrize("as_args", (True, False))
@pytest.mark.usefixtures("fetcher_mock_resolve_targets")
def test_metadata(branch, build_flags, os_, cpu, as_args):
    """Instantiate a Fetcher (which downloads metadata from TaskCluster) and check that
    the build is recent.
    """
    platform_ = Platform(os_, cpu)
    if as_args:
        args = []
        for field in fields(BuildFlags):
            if getattr(build_flags, field.name):
                args.append(f"--{field.name}")
        fetcher = Fetcher.from_args(
            ["--branch", branch, "--cpu", cpu, "--os", os_] + args
        )[0]
    else:
        if branch.startswith("esr"):
            branch = Fetcher.resolve_esr(branch)
        fetcher = Fetcher(
            branch,
            "latest",
            build_flags,
            DEFAULT_TARGETS,
            platform_,
        )

    LOG.debug("succeeded creating Fetcher")
    LOG.debug("buildid: %s", fetcher.id)
    LOG.debug("hgrev: %s", fetcher.changeset)


# When updating the cassettes:
# - update freeze time to current date
# - builds with an ascending search order should be older than 365 days
# - builds with a descending order should be in the future
@freeze_time("2024-11-06")
@pytest.mark.vcr()
@pytest.mark.parametrize(
    "requested, expected, direction",
    (
        # Requested data is older than available (-365 days)
        ("2023-11-06", "2023-11-07", BuildSearchOrder.ASC),
        # Requested build is in the future (+1 days)
        ("2024-11-07", "2024-11-06", BuildSearchOrder.DESC),
        # Requested rev is older than available (-365)
        (
            "a53a2b4b87d3cffa7582c252478f44077faa7775",
            "5d6699b34edce04ffd8886be86de9d604d88a89a",
            BuildSearchOrder.ASC,
        ),
    ),
)
@pytest.mark.parametrize("is_namespace", (True, False))
@pytest.mark.usefixtures("fetcher_mock_resolve_targets")
def test_nearest_retrieval(requested, expected, direction, is_namespace):
    """Attempt to retrieve a build near the supplied build_id."""
    build_str = requested
    if is_namespace:
        if is_date(requested):
            date = requested.replace("-", ".")
            build_str = f"gecko.v2.mozilla-central.pushdate.{date}.firefox.linux64-opt"
        else:
            build_str = (
                f"gecko.v2.mozilla-central.revision.{requested}.firefox.linux64-opt"
            )

    flags = BuildFlags()
    platform = Platform("Linux", "x86_64")

    build = Fetcher(
        "central",
        build_str,
        flags,
        DEFAULT_TARGETS,
        platform=platform,
        nearest=direction,
    )

    if is_date(expected):
        assert datetime.strftime(build.datetime, "%Y-%m-%d") == expected
    else:
        assert is_rev(expected)
        assert build.changeset == expected


@pytest.mark.vcr(allow_playback_repeats=True)
@pytest.mark.usefixtures("fetcher_mock_resolve_targets")
@pytest.mark.parametrize(
    "flag_params, targets",
    [
        ({"debug": True, "fuzzilli": True}, ["js"]),
        ({"asan": True, "fuzzing": True, "nyx": True, "coverage": False}, ["firefox"]),
        ({"asan": True, "fuzzing": True, "nyx": True, "coverage": True}, ["firefox"]),
        ({"asan": True, "fuzzing": True, "afl": True}, ["firefox"]),
        ({"searchfox": True, "debug": True}, ["searchfox"]),
    ],
)
def test_fetcher_variants(flag_params, targets):
    """Test Fetcher with different configurations."""
    flags = BuildFlags(**flag_params)
    Fetcher(
        "central",
        "latest",
        flags,
        targets,
    )
