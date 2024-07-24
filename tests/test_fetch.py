"""fuzzfetch tests"""

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import time
from dataclasses import fields
from datetime import datetime
from itertools import product

import pytest  # pylint: disable=import-error
from freezegun import freeze_time  # pylint: disable=import-error

from fuzzfetch import (
    BuildFlags,
    BuildSearchOrder,
    BuildTask,
    Fetcher,
    FetcherException,
    Platform,
)

LOG = logging.getLogger("fuzzfetch_test")
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("flake8").setLevel(logging.WARNING)

DEFAULT_TARGETS = ("firefox",)


def get_builds_to_test():
    """Get permutations for testing build branches and flags"""
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


@pytest.mark.parametrize("branch, build_flags, os_, cpu", get_builds_to_test())
@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_metadata(branch, build_flags, os_, cpu):
    """Instantiate a Fetcher (which downloads metadata from TaskCluster) and check that
    the build is recent.
    """
    platform_ = Platform(os_, cpu)
    for as_args in (True, False):  # try as API and as command line
        if as_args:
            args = []
            for field in fields(BuildFlags):
                if getattr(build_flags, field.name):
                    args.append(f"--{field.name}")
            fetcher = Fetcher.from_args(
                [f"--{branch}", "--cpu", cpu, "--os", os_] + args
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

        time_obj = time.strptime(fetcher.id, "%Y%m%d%H%M%S")

        # yyyy-mm-dd is also accepted as a build input
        date_str = f"{time_obj.tm_year:d}-{time_obj.tm_mon:02d}-{time_obj.tm_mday:02d}"
        if as_args:
            Fetcher.from_args(
                [f"--{branch}", "--cpu", cpu, "--os", os_, "--build", date_str] + args
            )
        else:
            Fetcher(branch, date_str, build_flags, DEFAULT_TARGETS, platform_)

        # hg rev is also accepted as a build input
        rev = fetcher.changeset
        if as_args:
            Fetcher.from_args(
                [f"--{branch}", "--cpu", cpu, "--os", os_, "--build", rev] + args
            )
        else:
            Fetcher(branch, rev, build_flags, DEFAULT_TARGETS, platform_)
        # namespace = fetcher.build

        # TaskCluster namespace is also accepted as a build input
        # namespace = ?
        # Fetcher(branch, namespace, (asan, debug, fuzzing, coverage))


# whenever BUILD_CACHE is set:
# - requested should be set to the near future, or the hg hash of a changeset prior to
#   the first build yesterday
# - expected should be updated to the value that asserts
@pytest.mark.parametrize(
    "requested, expected, direction",
    (
        ("2022-12-31", "2023-01-03", BuildSearchOrder.ASC),
        ("2024-01-03", "2024-01-02", BuildSearchOrder.DESC),
        (
            "5096e8be57730ef6902aaa8954b79aa0a21b32d6",
            "2288a4992fac2e0ecb886f1f9bfcdbe39cc18393",
            BuildSearchOrder.ASC,
        ),
    ),
)
@pytest.mark.parametrize("is_namespace", [True, False])
@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_nearest_retrieval(requested, expected, direction, is_namespace):
    """
    Attempt to retrieve a build near the supplied build_id
    """
    # Set freeze_time to a date ahead of the latest mock build
    with freeze_time("2024-01-02"):
        LOG.debug("looking for nearest to %s", requested)
        if is_namespace:
            if BuildTask.RE_DATE.match(requested):
                date = requested.replace("-", ".")
                build_id = (
                    f"gecko.v2.mozilla-central.pushdate.{date}.firefox.linux64-opt"
                )
            else:
                build_id = (
                    f"gecko.v2.mozilla-central.revision.{requested}.firefox.linux64-opt"
                )
        else:
            build_id = requested

        build = Fetcher(
            "central",
            build_id,
            BuildFlags(),
            DEFAULT_TARGETS,
            nearest=direction,
        )
        if BuildTask.RE_DATE.match(expected):
            build_date = datetime.strftime(build.datetime, "%Y-%m-%d")
            assert build_date == expected
        else:
            assert BuildTask.RE_REV.match(expected)
            assert build.changeset == expected


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_hash_resolution():
    """
    Test shortened hashes are resolved
    """
    rev = "10aa7423789835a7dbd24b0b44ad1ae2ad77b59b"
    build = Fetcher(
        "central",
        rev[:12],
        BuildFlags(),
        DEFAULT_TARGETS,
    )
    assert build.changeset == rev


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_fuzzilli_builds():
    """
    One-off test for retrieving fuzzilli enabled builds
    """
    Fetcher(
        "central",
        "latest",
        BuildFlags(debug=True, fuzzilli=True),
        DEFAULT_TARGETS,
    )


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_nyx_builds():
    """
    Test for retrieving Nyx snapshot enabled builds
    """
    Fetcher(
        "central",
        "latest",
        BuildFlags(asan=True, fuzzing=True, nyx=True),
        DEFAULT_TARGETS,
    )
    Fetcher(
        "central",
        "latest",
        BuildFlags(asan=True, fuzzing=True, nyx=True, coverage=True),
        DEFAULT_TARGETS,
    )


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_searchfox_data():
    """
    Test for retrieving SearchFox source data
    """
    Fetcher(
        "central",
        "latest",
        BuildFlags(searchfox=True, debug=True),
        ["searchfox"],
    )


@pytest.mark.usefixtures("fetcher_mock_resolve_targets", "requests_mock_cache")
def test_afl_builds():
    """
    Test for retrieving AFL++ enabled builds
    """
    Fetcher(
        "central",
        "latest",
        BuildFlags(asan=True, fuzzing=True, afl=True),
        DEFAULT_TARGETS,
    )
