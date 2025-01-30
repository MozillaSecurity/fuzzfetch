# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch args module tests"""

from pathlib import Path

import pytest  # pylint: disable=import-error

from fuzzfetch import FetcherArgs


def test_default_target(fetcher_args):
    """Test default target is set to DEFAULT_TARGETS when --target not specified."""
    args = fetcher_args.parse_args([])
    assert args.target == list(FetcherArgs.DEFAULT_TARGETS)


def test_custom_target(fetcher_args):
    """Test custom targets parsed correctly with --target."""
    args = fetcher_args.parse_args(["--target", "js", "common"])
    assert args.target == ["js", "common"]


def test_build_options(fetcher_args):
    """Test build options like --asan and --coverage parsed as True flags."""
    args = fetcher_args.parse_args(["--asan", "--coverage"])
    assert args.asan
    assert args.coverage


def test_branch_default(fetcher_args):
    """Test default branch is 'central' if --branch not specified."""
    args = fetcher_args.parse_args(["--build", "2024-01-01"])
    assert args.branch == "central"


@pytest.mark.parametrize("conflicts", [["--branch", "release"], ["--asan"]])
def test_invalid_namespace_conflict(fetcher_args, conflicts):
    """Test error raised if branch or flag specified with namespace."""
    with pytest.raises(SystemExit):
        args = fetcher_args.parse_args(
            [
                "--build",
                "gecko.v2.mozilla-central.latest.firefox.linux64-asan-opt",
                *conflicts,
            ]
        )
        fetcher_args.sanity_check(args)


def test_output_directory(fetcher_args):
    """Test --out correctly sets output directory."""
    args = fetcher_args.parse_args(["--out", "/tmp"])
    assert args.out.resolve() == Path("/tmp").resolve()


def test_fuzzilli_firefox_conflict(fetcher_args):
    """Test error raised if --target firefox and --fuzzilli both specified."""
    with pytest.raises(SystemExit):
        args = fetcher_args.parse_args(["--target", "firefox", "--fuzzilli"])
        fetcher_args.sanity_check(args)


def test_sim_js_target_requirement(fetcher_args):
    """Test error raised if --sim specified without JS target."""
    with pytest.raises(SystemExit):
        args = fetcher_args.parse_args(["--sim", "arm"])
        fetcher_args.sanity_check(args)


def test_target_assigned_searchfox_when_flag_provided(fetcher_args):
    """Test 'searchfox' added to target when --searchfox provided."""
    args = fetcher_args.parse_args(["--searchfox"])
    assert args.target == ["searchfox"]


def test_target_assigned_searchfox_when_build_contains_searchfox(fetcher_args):
    """Test 'searchfox' added to target if --build contains '-searchfox'."""
    args = fetcher_args.parse_args(
        [
            "--build",
            "gecko.v2.mozilla-central.latest.firefox.android-aarch64-searchfox-debug",
        ]
    )
    assert args.target == ["searchfox"]
