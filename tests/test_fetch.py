"""fuzzfetch tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import time
from datetime import datetime
from itertools import product, repeat

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


def build_flags_factory(**kwds):
    """BuildFlags with all fields defaulted to False"""
    return BuildFlags._make(repeat(False, len(BuildFlags._fields)))._replace(**kwds)


def get_builds_to_test():
    """Get permutations for testing build branches and flags"""
    possible_flags = (
        # opt
        build_flags_factory(),
        # debug
        build_flags_factory(debug=True),
        # ccov
        build_flags_factory(coverage=True),
        # asan-opt
        build_flags_factory(asan=True),
        # asan-opt-fuzzing
        build_flags_factory(asan=True, fuzzing=True),
        # tsan-opt
        build_flags_factory(tsan=True),
        # tsan-opt-fuzzing
        build_flags_factory(tsan=True, fuzzing=True),
        # debug-fuzzing
        build_flags_factory(debug=True, fuzzing=True),
        # ccov-fuzzing
        build_flags_factory(fuzzing=True, coverage=True),
        # valgrind-opt
        build_flags_factory(valgrind=True),
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
        if flags.valgrind and (os_ != "Linux" or cpu != "x64" or esr):
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
        } and flags == build_flags_factory(asan=True):
            continue
        if os_ == "Android":
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
@pytest.mark.usefixtures("requests_mock_cache")
def test_metadata(branch, build_flags, os_, cpu):
    """Instantiate a Fetcher (which downloads metadata from TaskCluster) and check that
    the build is recent.
    """
    # BuildFlags(asan, debug, fuzzing, coverage, valgrind)
    # Fetcher(branch, build, flags, arch_32)
    # Set freeze_time to a date ahead of the latest mock build
    platform_ = Platform(os_, cpu)
    for as_args in (True, False):  # try as API and as command line
        if as_args:
            args = [
                f"--{name}" for arg, name in zip(build_flags, BuildFlags._fields) if arg
            ]
            fetcher = Fetcher.from_args(
                [f"--{branch}", "--cpu", cpu, "--os", os_] + args
            )[0]
        else:
            if branch.startswith("esr"):
                branch = Fetcher.resolve_esr(branch)
            fetcher = Fetcher(branch, "latest", build_flags, platform_)

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
            Fetcher(branch, date_str, build_flags, platform_)

        # hg rev is also accepted as a build input
        rev = fetcher.changeset
        if as_args:
            Fetcher.from_args(
                [f"--{branch}", "--cpu", cpu, "--os", os_, "--build", rev] + args
            )
        else:
            Fetcher(branch, rev, build_flags, platform_)
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
        ("2020-06-06", "2020-06-09", BuildSearchOrder.ASC),
        ("2021-06-09", "2021-06-08", BuildSearchOrder.DESC),
        (
            "32fba417ebd01dfb2c2a392cdb1fad7ef66e96e8",
            "7f7b983390650cbc7d736e92fd3e1f629a30ac02",
            BuildSearchOrder.ASC,
        ),
    ),
)
@pytest.mark.parametrize("is_namespace", [True, False])
@pytest.mark.usefixtures("requests_mock_cache")
def test_nearest_retrieval(requested, expected, direction, is_namespace):
    """
    Attempt to retrieve a build near the supplied build_id
    """
    # Set freeze_time to a date ahead of the latest mock build
    with freeze_time("2021-06-08"):
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

        build = Fetcher("central", build_id, build_flags_factory(), nearest=direction)
        if BuildTask.RE_DATE.match(expected):
            build_date = datetime.strftime(build.datetime, "%Y-%m-%d")
            assert build_date == expected
        else:
            assert BuildTask.RE_REV.match(expected)
            assert build.changeset == expected


@pytest.mark.usefixtures("requests_mock_cache")
def test_hash_resolution():
    """
    Test shortened hashes are resolved
    """
    rev = "24938c537a55f9db3913072d33b178b210e7d6b5"
    build = Fetcher("central", rev[:12], build_flags_factory())
    assert build.changeset == rev


@pytest.mark.usefixtures("requests_mock_cache")
def test_fuzzilli_builds():
    """
    One-off test for retrieving fuzzilli enabled builds
    """
    Fetcher("central", "latest", build_flags_factory(debug=True, fuzzilli=True))


@pytest.mark.usefixtures("requests_mock_cache")
def test_nyx_builds():
    """
    Test for retrieving Nyx snapshot enabled builds
    """
    Fetcher("central", "latest", build_flags_factory(asan=True, fuzzing=True, nyx=True))
