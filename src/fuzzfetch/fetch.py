# coding=utf-8
"""Core fuzzfetch implementation"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import configparser
import itertools
import logging
import os
import platform as std_platform
import re
import shutil
import tempfile
import time
from argparse import SUPPRESS, ArgumentParser, Namespace
from collections import namedtuple
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from sys import version_info
from typing import Any, Dict, Iterator, Optional, Sequence, Tuple, Union

from pytz import timezone
from requests import Response, Session
from requests.exceptions import RequestException

from .extract import extract_dmg, extract_tar, extract_zip
from .path import PathArg, onerror
from .path import rmtree as junction_rmtree

if version_info[:2] < (3, 8):
    # pylint: disable=import-error
    from importlib_metadata import PackageNotFoundError, version
else:
    # pylint: disable=import-error
    from importlib.metadata import PackageNotFoundError, version


__all__ = (
    "__version__",
    "BuildFlags",
    "BuildSearchOrder",
    "BuildTask",
    "Fetcher",
    "FetcherArgs",
    "FetcherException",
    "Platform",
    "get_url",
    "download_url",
    "iec",
    "si",
)

try:
    __version__ = version("fuzzfetch")
except PackageNotFoundError:
    # package is not installed
    __version__ = None

LOG = logging.getLogger("fuzzfetch")


BUG_URL = "https://github.com/MozillaSecurity/fuzzfetch/issues/"
HTTP_SESSION = Session()


class FetcherException(Exception):
    """Exception raised for any Fetcher errors"""


def iec(number: Union[float, int]) -> str:
    """Format a number using IEC multi-byte prefixes.

    Arguments:
        number: Number to format.

    Returns:
        Input number, formatted to the largest whole SI prefix.
    """
    prefixes = ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"]
    while number > 1024:
        number /= 1024.0
        prefixes.pop(0)
    return f"{number:0.2f}{prefixes[0]}"


def si(number: Union[float, int]) -> str:  # pylint: disable=invalid-name
    """Format a number using SI prefixes.

    Arguments:
        number: Number to format.

    Returns:
        Input number, formatted to the largest whole SI prefix.
    """
    prefixes = ["", "k", "M", "G", "T", "P", "E", "Z", "Y"]
    while number > 1000:
        number /= 1000.0
        prefixes.pop(0)
    return f"{number:0.2f}{prefixes[0]}"


def get_url(url: str) -> Response:
    """Retrieve requested URL"""
    try:
        data = HTTP_SESSION.get(url, stream=True)
        data.raise_for_status()
    except RequestException as exc:
        raise FetcherException(exc) from None

    return data


def resolve_url(url: str) -> Response:
    """Resolve requested URL"""
    try:
        data = HTTP_SESSION.head(url)
        data.raise_for_status()
    except RequestException as exc:
        raise FetcherException(exc) from None

    return data


class HgRevision:
    """Class representing a Mercurial revision."""

    def __init__(self, revision: str, branch: str):
        """Create a Mercurial revision object.

        Arguments:
            revision: revision hash (short or long)
            branch: branch where revision is located
        """
        if branch is None or branch == "?":
            raise FetcherException(f"Can't lookup revision date for branch: {branch}")

        if branch == "autoland":
            branch = f"integration/{branch}"
        elif branch in {"release", "beta"} or branch.startswith("esr"):
            branch = f"releases/mozilla-{branch}"
        elif branch != "try":
            branch = f"mozilla-{branch}"
        self._data = get_url(
            f"https://hg.mozilla.org/{branch}/json-rev/{revision}"
        ).json()

    @property
    def pushdate(self) -> datetime:
        """Get datetime object representing pushdate of the revision."""
        push_date = datetime.fromtimestamp(self._data["pushdate"][0])
        # For some reason this timestamp is always EST despite saying it has an UTC
        # offset of 0.
        return timezone("EST").localize(push_date)

    @property
    def hash(self) -> str:
        """Get the long hash of the revision."""
        return self._data["node"]


def download_url(url: str, outfile: PathArg) -> None:
    """Download a URL to a local path.

    Arguments:
        url: URL to download.
        outfile: Path to output file.
    """
    downloaded = 0
    start_time = report_time = time.time()
    resp = get_url(url)
    total_size = int(resp.headers["Content-Length"])
    LOG.info("> Downloading: %s (%sB total)", url, iec(total_size))
    with open(outfile, "wb") as build_zip:
        for chunk in resp.iter_content(1024 * 1024):
            build_zip.write(chunk)
            downloaded += len(chunk)
            now = time.time()
            if (now - report_time) > 30 and downloaded != total_size:
                LOG.info(
                    ".. still downloading (%0.1f%%, %sB/s)",
                    100.0 * downloaded / total_size,
                    si(float(downloaded) / (now - start_time)),
                )
                report_time = now
    LOG.info(
        ".. downloaded (%sB/s)", si(float(downloaded) / (time.time() - start_time))
    )


def _create_utc_datetime(datetime_string: str) -> datetime:
    """Convert build_string to time-zone aware datetime object"""
    dt_obj = datetime.strptime(datetime_string, "%Y%m%d%H%M%S")
    return timezone("UTC").localize(dt_obj)


class BuildFlags(
    namedtuple(
        "BuildFlagsBase",
        (
            "asan",
            "tsan",
            "debug",
            "fuzzing",
            "coverage",
            "valgrind",
            "no_opt",
            "fuzzilli",
        ),
    )
):
    """Class for storing TaskCluster build flags"""

    def build_string(self) -> str:
        """
        Taskcluster denotes builds in one of two formats:
        i.e. linux64-asan or linux64-asan-opt
        The latter is generated. If it fails, the caller should try the former.
        """
        return (
            ("-ccov" if self.coverage else "")
            + ("-fuzzilli" if self.fuzzilli else "")
            + ("-fuzzing" if self.fuzzing else "")
            + ("-asan" if self.asan else "")
            + ("-tsan" if self.tsan else "")
            + ("-valgrind" if self.valgrind else "")
            + ("-noopt" if self.no_opt else "")
            + ("-debug" if self.debug else "")
            + ("-opt" if not self.no_opt and not self.debug else "")
        )


class Platform:
    """Class representing target OS and CPU, and how it maps to a Gecko mozconfig"""

    SUPPORTED = {
        "Darwin": {"x86_64": "macosx64"},
        "Linux": {"x86_64": "linux64", "x86": "linux"},
        "Windows": {"x86_64": "win64", "arm64": "win64-aarch64"},
        "Android": {
            "x86_64": "android-x86_64",
            "x86": "android-x86",
            "arm": "android-api-16",
            "arm64": "android-aarch64",
        },
    }
    CPU_ALIASES = {
        "ARM64": "arm64",
        "AMD64": "x86_64",
        "aarch64": "arm64",
        "i686": "x86",
        "x64": "x86_64",
    }

    def __init__(self, system: Optional[str] = None, machine: Optional[str] = None):
        if system is None:
            system = std_platform.system()
        if machine is None:
            machine = std_platform.machine()
        if system not in self.SUPPORTED:
            raise FetcherException(f"Unknown system: {system}")
        fixed_machine = self.CPU_ALIASES.get(machine, machine)
        if fixed_machine not in self.SUPPORTED[system]:
            raise FetcherException(f"Unknown machine for {system}: {machine}")
        self.system = system
        self.machine = fixed_machine
        self.gecko_platform = self.SUPPORTED[system][fixed_machine]

    @classmethod
    def from_platform_guess(cls, build_string: str) -> "Platform":
        """Create a platform object from a namespace build string"""
        match = []
        for system, platform in cls.SUPPORTED.items():
            for machine, platform_guess in platform.items():
                if platform_guess in build_string and (
                    not match or len(match[2]) < len(platform_guess)
                ):
                    match = [system, machine, platform_guess]
        if match:
            return cls(match[0], match[1])
        raise FetcherException(f"Could not extract platform from {build_string}")

    def auto_name_prefix(self) -> str:
        """
        Generate platform prefix for cross-platform downloads.
        """
        # if the platform is not native, auto_name would clobber native downloads.
        # make a prefix to avoid this
        native_system = std_platform.system()
        native_machine = self.CPU_ALIASES.get(
            std_platform.machine(), std_platform.machine()
        )
        if native_system == self.system and native_machine == self.machine:
            return ""
        platform = {
            "linux": "linux32",
            "android-api-16": "android-arm",
            "android-aarch64": "android-arm64",
        }.get(self.gecko_platform, self.gecko_platform)
        return f"{platform}-"


class BuildTask:
    """Class for storing TaskCluster build information"""

    TASKCLUSTER_API = "https://firefox-ci-tc.services.mozilla.com/api/%s/v1"
    RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    RE_REV = re.compile(r"^([0-9A-F]{12}|[0-9A-F]{40})$", re.IGNORECASE)

    def __init__(
        self,
        build: str,
        branch: str,
        flags: BuildFlags,
        platform: Optional[Platform] = None,
        _blank: bool = False,
    ):
        """Retrieve the task JSON object

        Requires first generating the task URL based on the specified build type and
        platform
        """
        if _blank:
            self.url = None
            self.queue_server = None
            self._data = {}
            return
        for obj in self.iterall(build, branch, flags, platform=platform):
            self.url = obj.url
            self.queue_server = obj.queue_server
            self._data = obj._data  # pylint: disable=protected-access
            break
        else:
            raise FetcherException(
                f"Unable to find usable archive for {self._debug_str(build)}"
            )

    @classmethod
    def _debug_str(cls, build: str) -> str:
        if cls.RE_DATE.match(build):
            return f"pushdate {build}"
        if cls.RE_REV.match(build):
            return f"revision {build}"
        return build

    @classmethod
    def iterall(
        cls,
        build: str,
        branch: str,
        flags: BuildFlags,
        platform: Optional[Platform] = None,
    ) -> Iterator["BuildTask"]:
        """Generator for all possible BuildTasks with these parameters"""
        # Prepare build type
        if platform is None:
            platform = Platform()
        target_platform = platform.gecko_platform

        is_namespace = False
        if cls.RE_DATE.match(build):
            flag_str = flags.build_string()
            task_template_paths = tuple(
                (template, path + flag_str)
                for (template, path) in cls._pushdate_template_paths(
                    build.replace("-", "."), branch, target_platform
                )
            )

        elif cls.RE_REV.match(build):
            # If a short hash was supplied, resolve it to a long one.
            if len(build) == 12:
                build = HgRevision(build, branch).hash
            flag_str = flags.build_string()
            task_paths = tuple(
                path + flag_str
                for path in cls._revision_paths(build.lower(), branch, target_platform)
            )
            task_template_paths = itertools.product((cls.TASKCLUSTER_API,), task_paths)

        elif build == "latest":
            if branch not in {"autoland", "try"}:
                branch = f"mozilla-{branch}"

            if not any(flags):
                # Opt builds are now indexed under 'shippable'
                namespace = f"gecko.v2.{branch}.shippable.latest"
            else:
                namespace = f"gecko.v2.{branch}.latest"

            prod = "mobile" if "android" in target_platform else "firefox"
            task_path = (
                f"/task/{namespace}.{prod}.{target_platform}{flags.build_string()}",
                f"/task/{namespace}.{prod}.sm-{target_platform}{flags.build_string()}",
            )
            task_template_paths = itertools.product((cls.TASKCLUSTER_API,), task_path)

        else:
            # try to use build argument directly as a namespace
            task_path = f"/task/{build}"
            is_namespace = True
            task_template_paths = ((cls.TASKCLUSTER_API, task_path),)

        for (template_path, try_wo_opt) in itertools.product(
            task_template_paths, (False, True)
        ):

            template, path = template_path

            if try_wo_opt:
                if "-opt" not in path or is_namespace:
                    continue
                path = path.replace("-opt", "")

            try:
                url = (template % ("index",)) + path
                data = HTTP_SESSION.get(url)
                data.raise_for_status()
            except RequestException:
                continue

            obj = cls(None, None, None, _blank=True)
            obj.url = url
            obj.queue_server = template % ("queue",)
            obj._data = data.json()  # pylint: disable=protected-access

            LOG.debug("Found archive for %s", cls._debug_str(build))
            yield obj

    def __getattr__(self, name: str) -> Any:
        if name in self._data:
            return self._data[name]
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    @classmethod
    def _pushdate_template_paths(
        cls, pushdate: str, branch: str, target_platform: str
    ) -> Iterator[Tuple[str, str]]:
        """Multiple entries exist per push date. Iterate over all until a working entry
        is found
        """
        if branch not in {"autoland", "try"}:
            branch = f"mozilla-{branch}"

        paths = (
            f"/namespaces/gecko.v2.{branch}.shippable.{pushdate}",
            f"/namespaces/gecko.v2.{branch}.pushdate.{pushdate}",
        )

        for path in paths:
            index_base = cls.TASKCLUSTER_API % ("index",)
            url = index_base + path
            try:
                base = HTTP_SESSION.post(url, json={})
                base.raise_for_status()
            except RequestException:
                continue

            product = "mobile" if "android" in target_platform else "firefox"
            json = base.json()
            for namespace in sorted(json["namespaces"], key=lambda x: x["name"]):
                task_paths = (
                    f"/task/{namespace['namespace']}.{product}.{target_platform}",
                    f"/task/{namespace['namespace']}.{product}.sm-{target_platform}",
                )
                for pair in itertools.product((cls.TASKCLUSTER_API,), task_paths):
                    yield pair

    @classmethod
    def _revision_paths(
        cls, rev: str, branch: str, target_platform: str
    ) -> Iterator[str]:
        """Retrieve the API path for revision based builds"""
        if branch not in {"autoland", "try"}:
            branch = f"mozilla-{branch}"

        namespaces = (
            f"gecko.v2.{branch}.revision.{rev}",
            f"gecko.v2.{branch}.shippable.revision.{rev}",
        )

        for namespace in namespaces:
            product = "mobile" if "android" in target_platform else "firefox"
            yield f"/task/{namespace}.{product}.{target_platform}"
            yield f"/task/{namespace}.{product}.sm-{target_platform}"


class FetcherArgs:
    """Class for parsing and recording Fetcher arguments"""

    DEFAULT_TARGETS = ["firefox"]

    def __init__(self):
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
            help="Download from try",
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
            super().sanity_check(args)  # pylint: disable=no-member

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
            LOG.warning("--gtest is deprecated, add 'gtest' to --target instead.")
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


class BuildSearchOrder(Enum):
    """Search direction when searching for "nearest" builds"""

    ASC = 1
    DESC = 2


class Fetcher:
    """Fetcher fetches build artifacts from TaskCluster and unpacks them"""

    re_target = re.compile(
        r"(\.linux-(x86_64|i686)(-asan)?|target|mac(64)?|win(32|64))\.json$"
    )

    def __init__(
        self,
        branch: str,
        build: str,
        flags: Union[Sequence[bool], BuildFlags],
        platform: Optional[Platform] = None,
        nearest: Optional[BuildSearchOrder] = None,
    ):
        """
        Arguments:
            branch: a valid gecko branch, eg. 'central', 'autoland', 'beta',
                    'release', 'esr52', etc.
            build: build identifier. acceptable identifiers are: TaskCluster
                   namespace, hg changeset, date, 'latest'
            flags: ('asan', 'debug', 'fuzzing', 'coverage', 'valgrind', 'tsan',
                    'no_opt', 'fuzzilli'),
                   each a bool, not all combinations exist in TaskCluster
            platform: force platform if different than current system
            nearest: Search for nearest build, not exact
        """
        self._memo = {}
        "memorized values for @properties"
        self._branch = branch
        self._flags = BuildFlags(*flags)
        self._platform = platform or Platform()
        self._task = None

        if not isinstance(build, BuildTask):
            # If build doesn't match the following, assume it's a namespace
            if (
                not BuildTask.RE_DATE.match(build)
                and not BuildTask.RE_REV.match(build)
                and build != "latest"
            ):
                # platform in namespace may not match the current platform
                self._platform = Platform.from_platform_guess(build)

                # If branch wasn't set, try and retrieve it from the build string
                if self._branch is None:
                    branch = re.search(
                        r"\.(autoland|try|mozilla-(?P<branch>[a-z]+[0-9]*))\.", build
                    )
                    self._branch = branch.group("branch") if branch is not None else "?"
                    if self._branch is None:
                        self._branch = branch.group(1)

                # '?' is special case used for unknown build types
                if self._branch != "?" and self._branch not in build:
                    raise FetcherException(
                        "'build' and 'branch' arguments do not match. "
                        f"(build={build}, branch={self._branch})"
                    )

                # If flags weren't set, try and retrieve it from the build string
                (
                    asan,
                    debug,
                    fuzzing,
                    coverage,
                    valgrind,
                    tsan,
                    no_opt,
                    fuzzilli,
                ) = self._flags
                if not debug:
                    debug = "-debug" in build or "-dbg" in build
                if not asan:
                    asan = "-asan" in build
                if not tsan:
                    tsan = "-tsan" in build
                if not fuzzing:
                    fuzzing = "-fuzzing" in build
                if not coverage:
                    coverage = "-ccov" in build
                if not valgrind:
                    valgrind = "-valgrind" in build
                if not no_opt:
                    no_opt = "-noopt" in build
                if not fuzzilli:
                    fuzzilli = "-fuzzilli" in build

                self._flags = BuildFlags(
                    asan, tsan, debug, fuzzing, coverage, valgrind, no_opt, fuzzilli
                )

                # Validate flags
                if self._flags.asan and "-asan" not in build:
                    raise FetcherException(
                        "'build' is not an asan build, but asan=True given "
                        f"(build={build})"
                    )
                if self._flags.tsan and "-tsan" not in build:
                    raise FetcherException(
                        "'build' is not an tsan build, but tsan=True given "
                        f"(build={build})"
                    )
                if self._flags.debug and not ("-dbg" in build or "-debug" in build):
                    raise FetcherException(
                        "'build' is not a debug build, but debug=True given "
                        f"(build={build})"
                    )
                if self._flags.fuzzing and "-fuzzing" not in build:
                    raise FetcherException(
                        "'build' is not a fuzzing build, but fuzzing=True given "
                        f"(build={build})"
                    )
                if self._flags.coverage and "-ccov" not in build:
                    raise FetcherException(
                        "'build' is not a coverage build, but coverage=True given "
                        f"(build={build})"
                    )
                if self._flags.valgrind and "-valgrind" not in build:
                    raise FetcherException(
                        "'build' is not a valgrind build, but valgrind=True given "
                        f"(build={build})"
                    )
                if self._flags.no_opt and "-noopt" not in build:
                    raise FetcherException(
                        "'build' is not a non-optimized build, but no_opt=True given "
                        f"(build={build})"
                    )
                if self._flags.fuzzilli and "-fuzzilli" not in build:
                    raise FetcherException(
                        "'build' is not a fuzzilli build, but fuzzilli=True given "
                        f"(build={build})"
                    )

            # Attempt to fetch the build.  If it fails and nearest is set, try and find
            # the nearest build that matches
            now = datetime.now(timezone("UTC"))

            try:
                self._task = BuildTask(build, branch, self._flags, self._platform)
            except FetcherException:
                if not nearest:
                    raise

                requested = None
                asc = nearest == BuildSearchOrder.ASC
                if "latest" in build:
                    requested = now
                elif BuildTask.RE_DATE.match(build) is not None:
                    date = datetime.strptime(build, "%Y-%m-%d")
                    requested = timezone("UTC").localize(date)
                elif BuildTask.RE_REV.match(build) is not None:
                    requested = HgRevision(build, branch).pushdate
                else:
                    # If no match, assume it's a TaskCluster namespace
                    if re.match(r".*[0-9]{4}\.[0-9]{2}\.[0-9]{2}.*", build) is not None:
                        match = re.search(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}", build)
                        date = datetime.strptime(match.group(0), "%Y.%m.%d")
                        requested = timezone("UTC").localize(date)
                    elif re.match(r".*revision.*[0-9[a-f]{40}", build):
                        match = re.search(r"[0-9[a-f]{40}", build)
                        requested = HgRevision(match.group(0), branch).pushdate

                # If start date is outside the range of the newest/oldest available
                # build, adjust it
                if asc:
                    start = min(max(requested, now - timedelta(days=364)), now)
                    end = now
                else:
                    end = now - timedelta(days=364)
                    start = max(min(requested, now), end)
                LOG.debug(
                    "searching for nearest build to %s from %s -> %s",
                    requested,
                    start,
                    end,
                )

                while start <= end if asc else start >= end:
                    search_build = start.strftime("%Y-%m-%d")

                    # in the case where a calendar date was specified, we've already
                    # tried it directly
                    if search_build != build:
                        LOG.debug("trying %s", search_build)
                        try:
                            # iterate over all builds for the day, and take the next
                            # older/newer build available
                            build_tasks = BuildTask.iterall(
                                search_build, branch, self._flags, self._platform
                            )
                            if not asc:
                                build_tasks = reversed(list(build_tasks))

                            for task in build_tasks:
                                task_date = timezone("EST").localize(
                                    datetime.fromtimestamp(task.rank)
                                )
                                LOG.debug("got %s", task_date)
                                if (asc and task_date >= requested) or (
                                    not asc and task_date <= requested
                                ):
                                    self._task = task
                                    break
                        except FetcherException:
                            LOG.warning(
                                "Unable to find build for %s",
                                start.strftime("%Y-%m-%d"),
                            )

                    if self._task is not None:
                        # a task was found
                        break

                    # Increment start date
                    start = (
                        start + timedelta(days=1) if asc else start - timedelta(days=1)
                    )

                else:
                    raise FetcherException(
                        f"Failed to find build near {build}"
                    ) from None

            if build == "latest" and (now - self.datetime).total_seconds() > 86400:
                LOG.warning("Latest available build is older than 1 day: %s", self.id)

        else:
            self._task = build

        # build the automatic name
        if (
            not isinstance(build, BuildTask)
            and self.moz_info["platform_guess"] is not None
            and self.moz_info["platform_guess"] in build
        ):
            options = build.split(self.moz_info["platform_guess"], 1)[1]
        else:
            options = self._flags.build_string()
        if self._branch in {"autoland", "try"}:
            branch = self._branch
        else:
            branch = f"m-{self._branch[0]}"
        self._auto_name = (
            f"{self._platform.auto_name_prefix()}{branch}-{self.id}{options}"
        )

    @staticmethod
    def resolve_esr(branch: str) -> str:
        """Retrieve esr version based on keyword"""
        if branch not in {"esr-stable", "esr-next"}:
            raise FetcherException(f"Invalid ESR branch specified: {branch}")

        resp = get_url("https://product-details.mozilla.org/1.0/firefox_versions.json")
        key = "FIREFOX_ESR" if branch == "esr-stable" else "FIREFOX_ESR_NEXT"
        match = re.search(r"^\d+", resp.json()[key])
        if match is None:
            raise FetcherException(f"Unable to identify ESR version for {branch}")

        return f"esr{match.group(0)}"

    @property
    def _artifacts(self) -> Dict[str, Sequence[Dict[str, str]]]:
        """Retrieve the artifacts json object"""
        if "_artifacts" not in self._memo:
            json = get_url(self._artifacts_url).json()
            self._memo["_artifacts"] = json["artifacts"]
        return self._memo["_artifacts"]

    @property
    def _artifact_base(self) -> str:
        """
        Build the artifact basename
        Builds are base.tar.bz2, info is base.json, shell is base.jsshell.zip...
        """
        if "_artifact_base" not in self._memo:
            for artifact in self._artifacts:
                if self.re_target.search(artifact["name"]) is not None:
                    artifact_base = os.path.splitext(artifact["name"])[0]
                    break
            else:
                raise FetcherException("Could not find build info in artifacts")
            self._memo["_artifact_base"] = artifact_base
        return self._memo["_artifact_base"]

    @property
    def _artifacts_url(self) -> str:
        """Build the artifacts url"""
        return f"{self._task.queue_server}/task/{self.task_id}/artifacts"

    @property
    def id(self) -> str:
        """Return the build's id (date stamp)"""
        # pylint: disable=invalid-name
        return self.build_info["buildid"]

    @property
    def datetime(self) -> datetime:
        """Return a datetime representation of the build's id"""
        return _create_utc_datetime(self.id)

    @property
    def build_info(self) -> Dict[str, str]:
        """Return the build's info"""
        if "build_info" not in self._memo:
            self._memo["build_info"] = get_url(self.artifact_url("json")).json()
        return self._memo["build_info"]

    @property
    def changeset(self) -> str:
        """Return the build's revision"""
        return self.build_info["moz_source_stamp"]

    @property
    def moz_info(self) -> Dict[str, Union[str, bool, int]]:
        """Return the build's mozinfo"""
        if "moz_info" not in self._memo:
            self._memo["moz_info"] = get_url(self.artifact_url("mozinfo.json")).json()
        return self._memo["moz_info"]

    @property
    def rank(self) -> int:
        """Return the build's rank"""
        return self._task.rank

    @property
    def task_id(self) -> str:
        """Return the build's TaskCluster ID"""
        return self._task.taskId

    @property
    def task_url(self) -> str:
        """Return the TaskCluster base url"""
        return self._task.url

    def artifact_url(self, suffix: str) -> str:
        """
        Get the Taskcluster artifact url

        Arguments:
            suffix
        """
        return f"{self._artifacts_url}/{self._artifact_base}.{suffix}"

    def get_auto_name(self) -> str:
        """Get the automatic directory name"""
        return self._auto_name

    def resolve_targets(self, targets: Sequence[str]) -> None:
        """Check that all targets are downloadable.

        This is used to check target validity prior to calling `extract_build()`

        Arguments:
            targets: build artifacts to download
        """
        # this should mirror extract_build(), but do HTTP HEAD requests only
        # to check that targets exist
        targets_remaining = set(targets)
        have_exec = False

        if "js" in targets_remaining:
            have_exec = True
            targets_remaining.remove("js")
            resolve_url(self.artifact_url("jsshell.zip"))

        if "firefox" in targets_remaining:
            have_exec = True
            targets_remaining.remove("firefox")
            if self._platform.system == "Linux":
                resolve_url(self.artifact_url("tar.bz2"))
            elif self._platform.system == "Darwin":
                resolve_url(self.artifact_url("dmg"))
            elif self._platform.system == "Windows":
                resolve_url(self.artifact_url("zip"))
            elif self._platform.system == "Android":
                artifact_path = "/".join(self._artifact_base.split("/")[:-1])
                url = f"{self._artifacts_url}/{artifact_path}/geckoview_example.apk"
                resolve_url(url)
            else:
                raise FetcherException(
                    f"'{self._platform.system}' is not a supported platform"
                )

        if have_exec:
            if self._flags.coverage:
                resolve_url(self.artifact_url("code-coverage-gcno.zip"))

            if (
                not self._flags.asan
                and not self._flags.tsan
                and not self._flags.valgrind
            ):
                try:
                    resolve_url(self.artifact_url("crashreporter-symbols.zip"))
                except FetcherException:
                    if not (self._flags.fuzzing or self._flags.fuzzilli):
                        raise

        for target in targets_remaining:
            try:
                resolve_url(self.artifact_url(f"{target}.tests.tar.gz"))
            except FetcherException:
                resolve_url(self.artifact_url(f"{target}.tests.zip"))

    def extract_build(self, targets: Sequence[str], path: PathArg = ".") -> None:
        """Download and extract the build and requested extra artifacts.

        If an executable target is requested (js/firefox), coverage data
        and/or symbols may be downloaded for the build.

        Arguments:
            targets: build artifacts to download
            path: Path to extract downloaded artifacts.
        """
        # sanity check all targets before downloading any
        self.resolve_targets(targets)
        path = Path(path)

        targets_remaining = set(targets)
        have_exec = False

        if "js" in targets_remaining:
            targets_remaining.remove("js")
            have_exec = True
            self.extract_zip("jsshell.zip", path=path / "dist" / "bin")
            self._write_fuzzmanagerconf("js", path)

        if "firefox" in targets_remaining:
            targets_remaining.remove("firefox")
            have_exec = True
            if self._platform.system == "Linux":
                self.extract_tar("tar.bz2", path)
            elif self._platform.system == "Darwin":
                self.extract_dmg(path)
            elif self._platform.system == "Windows":
                self.extract_zip("zip", path)
                # windows builds are extracted under 'firefox/'
                # move everything under firefox/ up a level to the destination path
                firefox = path / "firefox"
                for root, dirs, files in os.walk(firefox):
                    newroot = path / root.relative_to(firefox)
                    for dirname in dirs:
                        (newroot / dirname).mkdir()
                    for filename in files:
                        Path(root / filename).rename(newroot / filename)
                shutil.rmtree(firefox, onerror=onerror)
            elif self._platform.system == "Android":
                self.download_apk(path)
            else:
                raise FetcherException(
                    f"'{self._platform.system}' is not a supported platform"
                )
            self._write_fuzzmanagerconf("firefox", path)

        if "gtest" in targets_remaining:
            targets_remaining.remove("gtest")
            try:
                self.extract_tar("gtest.tests.tar.gz", path=path)
            except FetcherException:
                self.extract_zip("gtest.tests.zip", path=path)
            if self._platform.system == "Windows":
                libxul = "xul.dll"
            elif self._platform.system == "Linux":
                libxul = "libxul.so"
            elif self._platform.system == "Darwin":
                libxul = "XUL"
            else:
                raise FetcherException(
                    f"'{self._platform.system}' is not a supported platform for gtest"
                )
            (path / "gtest" / "gtest_bin" / "gtest" / libxul).rename(
                path / "gtest" / libxul
            )
            shutil.copy(
                path / "gtest" / "dependentlibs.list.gtest",
                path / "dependentlibs.list.gtest",
            )

        if have_exec:
            if self._flags.coverage:
                self.extract_zip("code-coverage-gcno.zip", path=path)

            if (
                not self._flags.asan
                and not self._flags.tsan
                and not self._flags.valgrind
            ):
                (path / "symbols").mkdir()
                try:
                    self.extract_zip("crashreporter-symbols.zip", path=path / "symbols")
                except FetcherException:
                    # fuzzing debug builds no longer have crashreporter-symbols.zip
                    # (bug 1649062)
                    # we want to maintain support for older builds for now
                    if not (self._flags.fuzzing or self._flags.fuzzilli):
                        raise

        # any still remaining targets are assumed to be test artifacts
        for target in targets_remaining:
            try:
                self.extract_tar(f"{target}.tests.tar.gz", path=path)
            except FetcherException:
                self.extract_zip(f"{target}.tests.zip", path=path)

        LOG.info("Extracted into %s", path)

    def _write_fuzzmanagerconf(self, target: str, path: Path) -> None:
        """
        Write fuzzmanager config file for selected build

        Arguments:
            target: firefox/js
            path: fuzzmanager config path
        """
        output = configparser.RawConfigParser()
        output.add_section("Main")
        output.set("Main", "platform", self.moz_info["processor"].replace("_", "-"))
        output.set("Main", "product", f"mozilla-{self._branch}")
        output.set("Main", "product_version", f"{self.id:.8}-{self.changeset:.12}")
        # make sure 'os' match what FM expects
        os_name = self.moz_info["os"].lower()
        if os_name.startswith("android"):
            output.set("Main", "os", "android")
        elif os_name.startswith("lin"):
            output.set("Main", "os", "linux")
        elif os_name.startswith("mac"):
            output.set("Main", "os", "macosx")
        elif os_name.startswith("win"):
            output.set("Main", "os", "windows")
        else:
            output.set("Main", "os", self.moz_info["os"])
        output.add_section("Metadata")
        output.set("Metadata", "pathPrefix", self.moz_info["topsrcdir"])
        output.set("Metadata", "buildType", self._flags.build_string().lstrip("-"))

        if self._platform.system == "Windows":
            fm_name = f"{target}.exe.fuzzmanagerconf"
        elif self._platform.system == "Android":
            fm_name = "target.apk.fuzzmanagerconf"
        elif self._platform.system == "Darwin" and target == "firefox":
            ff_loc = list(path.glob("*.app/Contents/MacOS/firefox"))
            assert len(ff_loc) == 1
            fm_name = f"{target}.fuzzmanagerconf"
            path = ff_loc[0].parent
        elif self._platform.system in {"Darwin", "Linux"}:
            fm_name = f"{target}.fuzzmanagerconf"
        else:
            raise FetcherException(
                f"Unknown platform/target: {self._platform.system}/{target}"
            )
        if target == "js":
            conf_path = path / "dist" / "bin" / fm_name
        else:
            conf_path = path / fm_name
        with open(conf_path, "w") as conf_fp:
            output.write(conf_fp)

    def extract_zip(self, suffix: str, path: PathArg = ".") -> None:
        """
        Download and extract a zip artifact

        Arguments:
            suffix: artifact to download
            path: path to extract zip to
        """
        zip_fd, zip_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".zip")
        os.close(zip_fd)
        try:
            download_url(self.artifact_url(suffix), zip_fn)
            LOG.info(".. extracting")
            extract_zip(zip_fn, path)
        finally:
            os.unlink(zip_fn)

    def extract_tar(self, suffix: str, path: PathArg = ".") -> None:
        """
        Extract builds with .tar.(*) extension
        When unpacking a build archive, only extract the firefox directory

        Arguments:
            suffix: artifact to download
            path: path to extract tar to
        """
        mode = suffix.split(".")[-1]
        tar_fd, tar_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=f".tar.{mode}")
        os.close(tar_fd)
        try:
            download_url(self.artifact_url(suffix), tar_fn)
            LOG.info(".. extracting")
            extract_tar(tar_fn, mode, path)
        finally:
            os.unlink(tar_fn)

    def download_apk(self, path: PathArg = ".") -> None:
        """
        Download Android .apk

        Arguments:
            path
        """
        apk_fd, apk_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".apk")
        os.close(apk_fd)
        try:
            # _artifact_base is like 'path/to/target' .. but geckoview doesn't
            # use target as a basename, so we need to extract just the path
            artifact_path = "/".join(self._artifact_base.split("/")[:-1])
            url = f"{self._artifacts_url}/{artifact_path}/geckoview_example.apk"
            download_url(url, apk_fn)
            shutil.copy(apk_fn, Path(path) / "target.apk")
        finally:
            os.unlink(apk_fn)

    def extract_dmg(self, path: PathArg = ".") -> None:
        """
        Extract builds with .dmg extension

        Will only work if `hdiutil` is available.

        Arguments:
            path: path to extract dmg contents to
        """
        dmg_fd, dmg_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".dmg")
        os.close(dmg_fd)
        try:
            download_url(self.artifact_url("dmg"), dmg_fn)
            if std_platform.system() == "Darwin":
                LOG.info(".. extracting")
                extract_dmg(dmg_fn, path)
            else:
                LOG.warning(".. can't extract target.dmg on %s", std_platform.system())
                shutil.copy(dmg_fn, Path(path) / "target.dmg")
        finally:
            os.unlink(dmg_fn)

    @classmethod
    def from_args(
        cls, args: Optional[Sequence[str]] = None, skip_dir_check: bool = False
    ) -> Tuple["Fetcher", Dict[str, Union[bool, Path, Sequence[str]]]]:
        """
        Construct a Fetcher from given command line arguments.

        Arguments:
            args (list(str)): Command line arguments (optional). Default is to use args
                              from sys.argv
            skip_dir_check (bool): Boolean identifying whether to check for existing
                                   build directory

        Returns:
            tuple(Fetcher, output path): Returns a Fetcher object and keyword arguments
                                         for extract_build.
        """
        parser = FetcherArgs()
        parser.parser.add_argument(
            "-V", "--version", action="store_true", help="print version and exit"
        )
        args = parser.parse_args(args)
        if args.version:
            print(f"fuzzfetch {__version__}")
            raise SystemExit(0)

        # do this default manually so we can error if combined with --build namespace
        # parser.set_defaults(branch='central')
        if not parser.is_build_ns(args.build):
            if args.branch is None:
                args.branch = "central"
            elif args.branch.startswith("esr"):
                args.branch = Fetcher.resolve_esr(args.branch)

        flags = BuildFlags(
            args.asan,
            args.tsan,
            args.debug,
            args.fuzzing,
            args.coverage,
            args.valgrind,
            args.no_opt,
            args.fuzzilli,
        )
        obj = cls(
            args.branch,
            args.build,
            flags,
            Platform(args.os, args.cpu),
            args.nearest,
        )

        if args.name is None:
            args.name = obj.get_auto_name()

        final_dir = os.path.realpath(os.path.join(args.out, args.name))
        if not skip_dir_check and os.path.exists(final_dir):
            parser.parser.error(f"Folder exists: {final_dir} .. exiting")

        extract_options = {
            "dry_run": args.dry_run,
            "out": final_dir,
            "targets": args.target,
        }

        return obj, extract_options

    @classmethod
    def main(cls) -> None:
        """
        fuzzfetch main entry point

        Run with --help for usage
        """
        log_level = logging.INFO
        log_fmt = "[%(asctime)s] %(message)s"
        if bool(os.getenv("DEBUG")):
            log_level = logging.DEBUG
            log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
        logging.basicConfig(
            format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level
        )
        logging.getLogger("requests").setLevel(logging.WARNING)

        obj, extract_args = cls.from_args()

        LOG.info("Identified task: %s", obj.task_url)
        LOG.info("> Task ID: %s", obj.task_id)
        LOG.info("> Rank: %s", obj.rank)
        LOG.info("> Changeset: %s", obj.changeset)
        LOG.info("> Build ID: %s", obj.id)

        if extract_args["dry_run"]:
            return

        out = extract_args["out"]
        os.mkdir(out)

        try:
            obj.extract_build(extract_args["targets"], out)
            os.makedirs(os.path.join(out, "download"))
            with open(os.path.join(out, "download", "firefox-temp.txt"), "a") as dl_fd:
                dl_fd.write(f"buildID={obj.id}{os.linesep}")
        except:  # noqa
            if os.path.isdir(out):
                junction_rmtree(out)
            raise
