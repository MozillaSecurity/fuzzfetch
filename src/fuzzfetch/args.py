# coding=utf-8
"""fuzzfetch argument parser"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import itertools
import os
import platform as std_platform
import re
from argparse import SUPPRESS, ArgumentParser, Namespace
from logging import getLogger
from typing import Optional, Sequence

from .models import BuildSearchOrder, Platform

LOG = getLogger("fuzzfetch")


class FetcherArgs:
    """Class for parsing and recording Fetcher arguments"""

    DEFAULT_TARGETS = ["firefox"]

    def __init__(self) -> None:
        """Instantiate a new FetcherArgs instance"""
        super().__init__()  # call super for multiple-inheritance support
        if not hasattr(self, "parser"):
            self.parser = ArgumentParser(conflict_handler="resolve", prog="fuzzfetch")

        self.parser.set_defaults(
            target="firefox", build="latest", tests=None
        )  # branch default is set after parsing

        target_group = self.parser.add_argument_group("Target")
        target_group.add_argument(
            "--target",
            nargs="*",
            default=FetcherArgs.DEFAULT_TARGETS,
            help="Specify the build artifacts to download. "
            "Valid options: firefox js common gtest "
            f"(default: {' '.join(FetcherArgs.DEFAULT_TARGETS)})",
        )
        target_group.add_argument(
            "--os",
            choices=sorted(Platform.SUPPORTED),
            help=f"Specify the target system. (default: {std_platform.system()})",
        )
        cpu_choices = sorted(
            set(
                itertools.chain(
                    itertools.chain.from_iterable(Platform.SUPPORTED.values()),
                    Platform.CPU_ALIASES,
                )
            )
        )
        target_group.add_argument(
            "--cpu",
            choices=cpu_choices,
            help=f"Specify the target CPU. (default: {std_platform.machine()})",
        )

        type_group = self.parser.add_argument_group("Build")
        type_group.add_argument(
            "--build",
            metavar="DATE|REV|NS",
            help="Specify the build to download, (default: %(default)s)"
            " Accepts values in format YYYY-MM-DD (2017-01-01)"
            " revision (57b37213d81150642f5139764e7044b07b9dccc3)"
            " or TaskCluster namespace (gecko.v2....)",
        )

        branch_group = self.parser.add_argument_group("Branch")
        branch_args = branch_group.add_mutually_exclusive_group()
        branch_args.add_argument(
            "--central",
            action="store_const",
            const="central",
            dest="branch",
            help="Download from mozilla-central (default)",
        )
        branch_args.add_argument(
            "--release",
            action="store_const",
            const="release",
            dest="branch",
            help="Download from mozilla-release",
        )
        branch_args.add_argument(
            "--beta",
            action="store_const",
            const="beta",
            dest="branch",
            help="Download from mozilla-beta",
        )
        branch_args.add_argument(
            "--esr-stable",
            action="store_const",
            const="esr-stable",
            dest="branch",
            help="Download from esr-stable",
        )
        branch_args.add_argument(
            "--esr-next",
            action="store_const",
            const="esr-next",
            dest="branch",
            help="Download from esr-next",
        )
        branch_args.add_argument(
            "--try",
            action="store_const",
            const="try",
            dest="branch",
            help="Download from try",
        )
        branch_args.add_argument(
            "--autoland",
            action="store_const",
            const="autoland",
            dest="branch",
            help="Download from autoland",
        )

        build_group = self.parser.add_argument_group("Build Arguments")
        build_group.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help="Get debug builds w/ symbols (default=optimized).",
        )
        build_group.add_argument(
            "-a",
            "--asan",
            action="store_true",
            help="Download AddressSanitizer builds.",
        )
        build_group.add_argument(
            "-t", "--tsan", action="store_true", help="Download ThreadSanitizer builds."
        )
        build_group.add_argument(
            "--fuzzing", action="store_true", help="Download --enable-fuzzing builds."
        )
        build_group.add_argument(
            "--fuzzilli",
            action="store_true",
            help="Download --enable-js-fuzzilli builds.",
        )
        build_group.add_argument(
            "--coverage", action="store_true", help="Download --coverage builds."
        )
        build_group.add_argument(
            "--valgrind", action="store_true", help="Download Valgrind builds."
        )
        build_group.add_argument(
            "--no-opt", action="store_true", help="Download non-optimized builds."
        )

        self.parser.add_argument(
            "--gtest",
            action="store_true",
            help=SUPPRESS,
        )

        misc_group = self.parser.add_argument_group("Misc. Arguments")
        misc_group.add_argument("-n", "--name", help="Specify a name (default=auto)")
        misc_group.add_argument(
            "-o",
            "--out",
            default=os.getcwd(),
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

    @staticmethod
    def is_build_ns(build_id: str) -> bool:
        """Check if supplied build_id is a namespace

        Arguments:
            build_id: Build identifier to check
        """
        return (
            re.match(
                r"(\d{4}-\d{2}-\d{2}|[0-9A-Fa-f]{12}|[0-9A-Fa-f]{40}|latest)$", build_id
            )
            is None
        )

    def sanity_check(self, args: Namespace) -> None:
        """Perform parser checks

        Arguments:
            args: Parsed arguments
        """
        # multiple-inheritance support
        if hasattr(super(), "sanity_check"):
            # pylint: disable=no-member
            super().sanity_check(args)  # type: ignore

        if self.is_build_ns(args.build):
            # this is a custom build
            # ensure conflicting options are not set
            if args.branch is not None:
                self.parser.error(
                    "Cannot specify --build namespace and branch argument: "
                    f"{args.branch}"
                )
            if args.debug:
                self.parser.error("Cannot specify --build namespace and --debug")
            if args.asan:
                self.parser.error("Cannot specify --build namespace and --asan")
            if args.tsan:
                self.parser.error("Cannot specify --build namespace and --tsan")
            if args.fuzzing:
                self.parser.error("Cannot specify --build namespace and --fuzzing")
            if args.coverage:
                self.parser.error("Cannot specify --build namespace and --coverage")
            if args.valgrind:
                self.parser.error("Cannot specify --build namespace and --valgrind")
            if args.no_opt:
                self.parser.error("Cannot specify --build namespace and --no-opt")

        if args.gtest:
            LOG.warning(
                "--gtest is deprecated, add 'gtest' to --target instead "
                "(e.g. --target firefox gtest)"
            )
            args.target.append("gtest")

        if "firefox" in args.target and args.fuzzilli:
            self.parser.error("Cannot specify --target firefox and --fuzzilli")

    def parse_args(self, argv: Optional[Sequence[str]] = None) -> Namespace:
        """Parse and validate args

        Arguments:
            argv: a list of arguments
        """
        args = self.parser.parse_args(argv)
        self.sanity_check(args)
        return args
