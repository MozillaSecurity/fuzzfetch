# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch argument parser"""

from __future__ import annotations

from argparse import ArgumentParser, Namespace
from itertools import chain
from logging import getLogger
from pathlib import Path
from platform import machine, system
from typing import TYPE_CHECKING

from .models import BuildSearchOrder, Platform
from .utils import extract_branch_from_ns, is_namespace

if TYPE_CHECKING:
    from collections.abc import Sequence

LOG = getLogger("fuzzfetch")


class FetcherArgs:
    """Class for parsing and recording Fetcher arguments"""

    DEFAULT_TARGETS = ("firefox",)

    BUILD_OPTIONS = (
        # Build flags
        (["--asan", "-a"], "AddressSanitizer builds"),
        (["--debug", "-d"], "debug builds"),
        (["--tsan", "-t"], "ThreadSanitizer builds"),
        (["--fuzzing"], "fuzzing builds"),
        (["--coverage"], "coverage builds"),
        (["--no-opt"], "non-optimized builds"),
        (["--valgrind"], "Valgrind builds"),
        # Fuzzer specific builds
        (["--afl"], "AFL++ builds"),
        (["--fuzzilli"], "JS Fuzzilli builds"),
        (["--nyx"], "Nyx builds"),
        # Searchfox data
        (["--searchfox"], "Searchfox data"),
    )

    def __init__(self) -> None:
        """Instantiate a new FetcherArgs instance"""
        super().__init__()  # call super for multiple-inheritance support
        if not hasattr(self, "parser"):
            self.parser = ArgumentParser(conflict_handler="resolve", prog="fuzzfetch")

        target_group = self.parser.add_argument_group("Target")
        target_group.add_argument(
            "--target",
            nargs="*",
            default=[],
            help="Specify the build artifacts to download. "
            "Valid options: firefox js common gtest mozharness searchfox "
            f"(default: {' '.join(FetcherArgs.DEFAULT_TARGETS)})",
        )
        target_group.add_argument(
            "--os",
            choices=sorted(Platform.SUPPORTED),
            help=f"Specify the target system. (default: {system()})",
        )
        cpu_choices = sorted(
            set(
                chain(
                    chain.from_iterable(Platform.SUPPORTED.values()),
                    Platform.CPU_ALIASES,
                )
            )
        )
        target_group.add_argument(
            "--cpu",
            choices=cpu_choices,
            help=f"Specify the target CPU. (default: {machine()})",
        )
        target_group.add_argument(
            "--sim",
            choices=["arm", "arm64"],
            help="Specify the simulated architecture",
        )

        type_group = self.parser.add_argument_group("Build")
        type_group.add_argument(
            "--build",
            default="latest",
            metavar="DATE|REV|NS",
            help="Specify the build to download, (default: %(default)s)"
            " Accepts values in format YYYY-MM-DD (2017-01-01),"
            " BuildID (20170101120101),"
            " revision (57b37213d81150642f5139764e7044b07b9dccc3),"
            " or TaskCluster namespace (gecko.v2....)",
        )

        branch_group = self.parser.add_argument_group("Branch")
        branch_group.add_argument(
            "--branch",
            choices=[
                "central",
                "release",
                "beta",
                "esr-stable",
                "esr-next",
                "try",
                "autoland",
            ],
            help="Specify the branch to download from "
            "(default: mozilla-central unless namespace build is supplied)",
        )

        # Build Options
        build_group = self.parser.add_argument_group("Build Arguments")
        for options, desc in self.BUILD_OPTIONS:
            build_group.add_argument(
                *options, action="store_true", help=f"Download {desc}"
            )

        misc_group = self.parser.add_argument_group("Misc. Arguments")
        misc_group.add_argument("-n", "--name", help="Specify a name (default=auto)")
        misc_group.add_argument(
            "-o",
            "--out",
            type=Path,
            default=Path.cwd().resolve(),
            help="Specify output directory (default=.)",
        )
        misc_group.add_argument(
            "--dry-run",
            action="store_true",
            help="Search for build and output metadata only, don't download anything.",
        )

        near_group = self.parser.add_argument_group(
            "Near Arguments",
            "If the specified build isn't found, iterate over "
            "builds in the specified direction",
        )
        near_args = near_group.add_mutually_exclusive_group()
        near_args.add_argument(
            "--nearest-newer",
            action="store_const",
            const=BuildSearchOrder.ASC,
            dest="nearest",
            help="Search from specified build in ascending order",
        )
        near_args.add_argument(
            "--nearest-older",
            action="store_const",
            const=BuildSearchOrder.DESC,
            dest="nearest",
            help="Search from the specified build in descending order",
        )

    def sanity_check(self, args: Namespace) -> None:
        """Perform parser checks

        Arguments:
            args: Parsed arguments
        """
        # multiple-inheritance support
        if hasattr(super(), "sanity_check"):
            # pylint: disable=no-member
            super().sanity_check(args)  # type: ignore  # pragma: no cover

        if is_namespace(args.build):
            branch = extract_branch_from_ns(args.build)
            if args.branch is None:
                args.branch = branch
            elif args.branch != branch:
                self.parser.error(
                    f"Branch ({args.branch}) doesn't match namespace ({args.build})"
                )

            # All build flags cannot be used with namespace
            conflicting_args = []
            for opts, _ in self.BUILD_OPTIONS:
                assert len(opts) >= 1 and opts[0].startswith("--")
                conflicting_args.append(opts[0].lstrip("-").replace("-", "_"))

            for arg in conflicting_args:
                if getattr(args, arg):
                    self.parser.error(f"Cannot specify --build namespace and --{arg}")

        if args.branch is None:
            args.branch = "central"

        if "firefox" in args.target and args.fuzzilli:
            self.parser.error("Cannot specify --target firefox and --fuzzilli")

        if "js" not in args.target and args.sim:
            self.parser.error("Simulator builds are only available for JS targets")

    def parse_args(self, argv: Sequence[str] | None = None) -> Namespace:
        """Parse and validate args

        Arguments:
            argv: a list of arguments
        """
        args = self.parser.parse_args(argv)

        if not args.target:
            if args.searchfox or (
                is_namespace(args.build) and "-searchfox" in args.build
            ):
                args.target.append("searchfox")
            else:
                args.target.extend(self.DEFAULT_TARGETS)

        self.sanity_check(args)
        return args
