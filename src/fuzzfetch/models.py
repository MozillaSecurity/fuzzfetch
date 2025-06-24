# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch internal models"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from enum import Enum
from itertools import product
from logging import getLogger
from platform import machine as plat_machine
from platform import system as plat_system
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pytz import timezone
from requests import RequestException

from .download import HTTP_SESSION, get_url
from .errors import FetcherException
from .utils import is_date, is_namespace, is_rev

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

LOG = getLogger("fuzzfetch")


@dataclass
class BuildFlags:
    """Class for representing possible build flags"""

    asan: bool = False
    tsan: bool = False
    debug: bool = False
    fuzzing: bool = False
    coverage: bool = False
    valgrind: bool = False
    no_opt: bool = False
    fuzzilli: bool = False
    nyx: bool = False
    searchfox: bool = False
    afl: bool = False

    def __iter__(self) -> Iterator[bool]:
        """Yield field values"""
        for field in fields(self):
            yield getattr(self, field.name)

    def build_string(self) -> str:
        """
        Taskcluster denotes builds in one of two formats:
        i.e. linux64-asan or linux64-asan-opt
        The latter is generated. If it fails, the caller should try the former.
        """
        return (
            f"{'-ccov' if self.coverage else ''}"
            f"{'-fuzzilli' if self.fuzzilli else ''}"
            f"{'-fuzzing' if self.fuzzing else ''}"
            f"{'-asan' if self.asan else ''}"
            f"{'-tsan' if self.tsan else ''}"
            f"{'-afl' if self.afl else ''}"
            f"{'-nyx' if self.nyx else ''}"
            f"{'-valgrind' if self.valgrind else ''}"
            f"{'-noopt' if self.no_opt else ''}"
            f"{'-searchfox' if self.searchfox else ''}"
            f"{'-debug' if self.debug else ''}"
            f"{'-opt' if not self.no_opt and not self.debug else ''}"
        )

    def update_from_string(self, build_string: str) -> None:
        """Update flags based on substrings found in the build information string."""
        flag_suffixes = {
            "debug": ["-debug", "-dbg"],
            "asan": ["-asan"],
            "afl": ["-afl"],
            "tsan": ["-tsan"],
            "fuzzing": ["-fuzzing"],
            "coverage": ["-ccov"],
            "valgrind": ["-valgrind"],
            "no_opt": ["-noopt"],
            "fuzzilli": ["-fuzzilli"],
            "nyx": ["-nyx"],
            "searchfox": ["-searchfox"],
        }

        # Update flags based on the presence of substrings in the build string
        for flag, substrs in flag_suffixes.items():
            value = any(substr in build_string for substr in substrs)
            if value is False and getattr(self, flag):
                raise FetcherException(
                    f"Build flag '{flag}' is true but suffix is missing from build "
                    f"string (build={build_string})"
                )

            setattr(self, flag, value)


class BuildSearchOrder(Enum):
    """Search direction when searching for "nearest" builds"""

    ASC = 1
    DESC = 2


class BuildTask:
    """Class for storing TaskCluster build information"""

    TASKCLUSTER_API = "https://firefox-ci-tc.services.mozilla.com/api/%s/v1"

    def __init__(
        self,
        build: str | None,
        branch: str | None,
        flags: BuildFlags | None,
        platform: Platform | None = None,
        simulated: str | None = None,
        _blank: bool = False,
    ) -> None:
        """Retrieve the task JSON object

        Requires first generating the task URL based on the specified build type and
        platform
        """
        if _blank:
            self.url: str | None = None
            self.queue_server: str | None = None
            self._data: dict[str, Any] = {}
            return
        assert build is not None
        assert branch is not None
        assert flags is not None
        for obj in self.iterall(
            build,
            branch,
            flags,
            platform=platform,
            simulated=simulated,
        ):
            self.url = obj.url
            self.queue_server = obj.queue_server
            self._data = obj._data  # pylint: disable=protected-access
            break
        else:
            raise FetcherException(
                f"Unable to find usable archive for {BuildTask._debug_str(build)}"
            )

    @staticmethod
    def _debug_str(build: str) -> str:
        if is_date(build):
            return f"pushdate {build}"
        if is_rev(build):
            return f"revision {build}"
        return build

    @classmethod
    def iterall(
        cls,
        build: str,
        branch: str,
        flags: BuildFlags,
        platform: Platform | None = None,
        simulated: str | None = None,
    ) -> Iterator[BuildTask]:
        """Generator for all possible BuildTasks with these parameters"""
        # Prepare build type
        if platform is None:
            platform = Platform()
        target_platform = platform.gecko_platform

        if is_date(build):
            flag_str = flags.build_string()
            if "-" in build:
                build_date_ns = build.replace("-", ".")
                filt = ""
            else:
                build_date_ns = f"{build[:4]}.{build[4:6]}.{build[6:8]}"
                filt = build
            task_template_paths: Iterable[tuple[str, str]] = tuple(
                (template, f"{path}{flag_str}")
                for (template, path) in cls._pushdate_template_paths(
                    build_date_ns, branch, target_platform
                )
                if filt in path
            )

        elif is_rev(build):
            # If a short hash was supplied, resolve it to a long one.
            if len(build) == 12:
                build = HgRevision(build, branch).hash
            flag_str = flags.build_string()
            task_paths = tuple(
                f"{path}{flag_str}"
                for path in cls._revision_paths(build.lower(), branch, target_platform)
            )
            task_template_paths = product((cls.TASKCLUSTER_API,), task_paths)

        elif build == "latest":
            if branch not in {"autoland", "try"}:
                branch = f"mozilla-{branch}"

            namespaces = []
            if not any(flags):
                # Opt builds are now indexed under 'shippable'
                namespaces.append(f"gecko.v2.{branch}.shippable.latest")
            namespaces.append(f"gecko.v2.{branch}.latest")

            prod = "mobile" if "android" in target_platform else "firefox"
            suffix = f"{target_platform}{flags.build_string()}"

            def generate_task_paths(
                namespaces_: list[str],
                prod_: str,
                suffix_: str,
                simulated_: str | None,
            ) -> Iterator[str]:
                for namespace in namespaces_:
                    if simulated_ is not None:
                        yield f"/task/{namespace}.{prod_}.sm-{simulated_}-sim-{suffix_}"
                    else:
                        yield f"/task/{namespace}.{prod_}.{suffix_}"
                        yield f"/task/{namespace}.{prod_}.sm-{suffix_}"

            task_paths = tuple(generate_task_paths(namespaces, prod, suffix, simulated))
            task_template_paths = product((cls.TASKCLUSTER_API,), task_paths)

        else:
            # try to use build argument directly as a namespace
            task_path = f"/task/{build}"
            task_template_paths = ((cls.TASKCLUSTER_API, task_path),)

        for template_path, try_wo_opt in product(task_template_paths, (False, True)):
            template, path = template_path

            if try_wo_opt:
                if "-opt" not in path or is_namespace(build):
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
        cls,
        pushdate: str,
        branch: str,
        target_platform: str,
    ) -> Iterator[tuple[str, str]]:
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
            url = f"{index_base}{path}"
            try:
                base = HTTP_SESSION.post(url, json={})
                base.raise_for_status()
            except RequestException:
                continue

            prod = "mobile" if "android" in target_platform else "firefox"
            json = base.json()
            for namespace in sorted(json["namespaces"], key=lambda x: str(x["name"])):
                task_paths = (
                    f"/task/{namespace['namespace']}.{prod}.{target_platform}",
                    f"/task/{namespace['namespace']}.{prod}.sm-{target_platform}",
                )
                yield from product((cls.TASKCLUSTER_API,), task_paths)

    @classmethod
    def _revision_paths(
        cls,
        rev: str,
        branch: str,
        target_platform: str,
    ) -> Iterator[str]:
        """Retrieve the API path for revision based builds"""
        if branch not in {"autoland", "try"}:
            branch = f"mozilla-{branch}"

        namespaces = (
            f"gecko.v2.{branch}.shippable.revision.{rev}",
            f"gecko.v2.{branch}.revision.{rev}",
        )

        for namespace in namespaces:
            prod = "mobile" if "android" in target_platform else "firefox"
            yield f"/task/{namespace}.{prod}.{target_platform}"
            yield f"/task/{namespace}.{prod}.sm-{target_platform}"


class HgRevision:
    """Class representing a Mercurial revision."""

    def __init__(self, revision: str, branch: str) -> None:
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
        assert isinstance(self._data["node"], str)
        return self._data["node"]


class Platform:
    """Class representing target OS and CPU, and how it maps to a Gecko mozconfig"""

    SUPPORTED = MappingProxyType(
        {
            "Darwin": MappingProxyType(
                {
                    "arm64": "macosx64-aarch64",
                    "x86_64": "macosx64",
                }
            ),
            "Linux": MappingProxyType(
                {
                    "arm64": "linux64-aarch64",
                    "x86": "linux",
                    "x86_64": "linux64",
                }
            ),
            "Windows": MappingProxyType(
                {
                    "arm64": "win64-aarch64",
                    "x86": "win32",
                    "x86_64": "win64",
                }
            ),
            "Android": MappingProxyType(
                {
                    "arm": "android-arm",
                    "arm64": "android-aarch64",
                    "x86": "android-x86",
                    "x86_64": "android-x86_64",
                }
            ),
        }
    )
    CPU_ALIASES = MappingProxyType(
        {
            "ARM64": "arm64",
            "AMD64": "x86_64",
            "aarch64": "arm64",
            "i686": "x86",
            "x64": "x86_64",
        }
    )

    def __init__(
        self,
        system: str | None = None,
        machine: str | None = None,
    ) -> None:
        if system is None:
            system = plat_system()
        if machine is None:
            machine = plat_machine()
        if system not in self.SUPPORTED:
            raise FetcherException(f"Unknown system: {system}")
        fixed_machine = self.CPU_ALIASES.get(machine, machine)
        if fixed_machine not in self.SUPPORTED[system]:
            raise FetcherException(f"Unknown machine for {system}: {machine}")
        self.system = system
        self.machine = fixed_machine
        self.gecko_platform = self.SUPPORTED[system][fixed_machine]

    @classmethod
    def from_platform_guess(cls, build_string: str) -> Platform:
        """Create a platform object from a namespace build string"""
        match: list[str] = []
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
        """Generate platform prefix for cross-platform downloads."""
        # if the platform is not native, auto_name would clobber native downloads.
        # make a prefix to avoid this
        native_system = plat_system()
        native_machine = self.CPU_ALIASES.get(plat_machine(), plat_machine())
        if native_system == self.system and native_machine == self.machine:
            return ""
        platform = {
            "linux": "linux32",
            "android-arm": "android-arm",
            "android-aarch64": "android-arm64",
        }.get(self.gecko_platform, self.gecko_platform)
        return f"{platform}-"
