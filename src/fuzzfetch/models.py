# coding=utf-8
"""fuzzfetch internal models"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import itertools
import platform as std_platform
import re
from collections import namedtuple
from datetime import datetime
from enum import Enum
from logging import getLogger
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from pytz import timezone
from requests import RequestException

from . import FetcherException
from .download import HTTP_SESSION, get_url

LOG = getLogger("fuzzfetch")


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


class BuildSearchOrder(Enum):
    """Search direction when searching for "nearest" builds"""

    ASC = 1
    DESC = 2


class BuildTask:
    """Class for storing TaskCluster build information"""

    TASKCLUSTER_API = "https://firefox-ci-tc.services.mozilla.com/api/%s/v1"
    RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    RE_REV = re.compile(r"^([0-9A-F]{12}|[0-9A-F]{40})$", re.IGNORECASE)

    def __init__(
        self,
        build: Optional[str],
        branch: Optional[str],
        flags: Optional[BuildFlags],
        platform: Optional["Platform"] = None,
        _blank: bool = False,
    ) -> None:
        """Retrieve the task JSON object

        Requires first generating the task URL based on the specified build type and
        platform
        """
        if _blank:
            self.url: Optional[str] = None
            self.queue_server: Optional[str] = None
            self._data: Dict[str, Any] = {}
            return
        assert build is not None
        assert branch is not None
        assert flags is not None
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
        platform: Optional["Platform"] = None,
    ) -> Iterator["BuildTask"]:
        """Generator for all possible BuildTasks with these parameters"""
        # Prepare build type
        if platform is None:
            platform = Platform()
        target_platform = platform.gecko_platform

        is_namespace = False
        if cls.RE_DATE.match(build):
            flag_str = flags.build_string()
            task_template_paths: Iterable[Tuple[str, str]] = tuple(
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
            task_paths = (
                f"/task/{namespace}.{prod}.{target_platform}{flags.build_string()}",
                f"/task/{namespace}.{prod}.sm-{target_platform}{flags.build_string()}",
            )
            task_template_paths = itertools.product((cls.TASKCLUSTER_API,), task_paths)

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
            for namespace in sorted(json["namespaces"], key=lambda x: str(x["name"])):
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

    def __init__(
        self, system: Optional[str] = None, machine: Optional[str] = None
    ) -> None:
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
        match: List[str] = []
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
