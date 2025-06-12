# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Core fuzzfetch implementation"""

from __future__ import annotations

import os
import re
from configparser import RawConfigParser
from contextlib import suppress
from datetime import datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from logging import DEBUG, INFO, WARNING, basicConfig, getLogger
from pathlib import Path
from platform import system
from shutil import copy
from tempfile import mkstemp
from typing import TYPE_CHECKING, Any

from pytz import timezone

from .args import FetcherArgs
from .download import download_url, get_url, resolve_url
from .errors import FetcherException
from .extract import LBZIP2_PATH, XZ_PATH, extract_dmg, extract_tar, extract_zip
from .models import BuildFlags, BuildSearchOrder, BuildTask, HgRevision, Platform
from .path import PathArg
from .path import rmtree as junction_rmtree
from .utils import _create_utc_datetime, is_date, is_namespace, is_rev

if TYPE_CHECKING:
    from collections.abc import Sequence

try:
    __version__ = version("fuzzfetch")
except PackageNotFoundError:
    # package is not installed
    __version__ = "unknown"

LOG = getLogger("fuzzfetch")
BUG_URL = "https://github.com/MozillaSecurity/fuzzfetch/issues/"


class Fetcher:
    """Fetcher fetches build artifacts from TaskCluster and unpacks them"""

    re_target = re.compile(
        r"(\.linux-(x86_64|i686)(-asan)?|target|mac(64)?|win(32|64))\.json$"
    )

    def __init__(
        self,
        branch: str,
        build: str | BuildTask,
        flags: Sequence[bool] | BuildFlags,
        targets: Sequence[str],
        platform: Platform | None = None,
        simulated: str | None = None,
        nearest: BuildSearchOrder | None = None,
    ) -> None:
        """
        Arguments:
            branch: a valid gecko branch, eg. 'central', 'autoland', 'beta',
                    'release', 'esr52', etc.
            build: build identifier. acceptable identifiers are: TaskCluster
                   namespace, hg changeset, date, 'latest'
            flags: ('asan', 'debug', 'fuzzing', 'coverage', 'valgrind', 'tsan',
                    'no_opt', 'fuzzilli', 'nyx', 'searchfox', 'afl'),
                   each a bool, not all combinations exist in TaskCluster
            platform: force platform if different than current system
            nearest: Search for nearest build, not exact
        """
        self._memo: dict[str, Any] = {}
        "memorized values for @properties"
        self._branch = branch
        self._flags = BuildFlags(*flags)
        self._platform = platform or Platform()
        self._simulated = simulated
        self._targets = targets
        self._task: BuildTask | None = None

        if not isinstance(build, BuildTask):
            if is_namespace(build):
                # platform in namespace may not match the current platform
                self._platform = Platform.from_platform_guess(build)

                # Ensure flags match the build string
                self._flags.update_from_string(build)

            # Attempt to fetch the build.  If it fails and nearest is set, try and find
            # the nearest build that matches
            now = datetime.now(timezone("UTC"))

            try:
                self._task = BuildTask(
                    build,
                    branch,
                    self._flags,
                    self._platform,
                    self._simulated,
                )
                self.resolve_targets(self._targets)
            except FetcherException:
                if not nearest:
                    raise

                requested = None
                asc = nearest == BuildSearchOrder.ASC
                if "latest" in build:
                    requested = now
                elif is_date(build):
                    if "-" in build:
                        date = datetime.strptime(build, "%Y-%m-%d")
                    else:
                        date = datetime.strptime(build, "%Y%m%d%H%M%S")
                    requested = timezone("UTC").localize(date)
                elif is_rev(build):
                    requested = HgRevision(build, branch).pushdate
                else:
                    # If no match, assume it's a TaskCluster namespace
                    if re.match(r".*[0-9]{4}\.[0-9]{2}\.[0-9]{2}.*", build) is not None:
                        match = re.search(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}", build)
                        assert match is not None
                        date = datetime.strptime(match.group(0), "%Y.%m.%d")
                        requested = timezone("UTC").localize(date)
                    elif re.match(r".*revision.*[0-9[a-f]{40}", build):
                        match = re.search(r"[0-9[a-f]{40}", build)
                        assert match is not None
                        requested = HgRevision(match.group(0), branch).pushdate
                assert isinstance(requested, datetime)

                # If start date is outside the range of the newest/oldest available
                # build, adjust it
                if asc:
                    start = min(max(requested, now - timedelta(days=365)), now)
                    end = now
                else:
                    end = now - timedelta(days=365)
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
                        # iterate over all builds for the day, and take the next
                        # older/newer build available
                        build_tasks = BuildTask.iterall(
                            search_build,
                            branch,
                            self._flags,
                            self._platform,
                            self._simulated,
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
                                try:
                                    self._task = task
                                    self.resolve_targets(self._targets)
                                    break
                                except FetcherException:
                                    LOG.warning(
                                        "Unable to find build for %s",
                                        start.strftime("%Y-%m-%d"),
                                    )
                        else:
                            self._task = None

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
    def _artifacts(self) -> Sequence[dict[str, str]]:
        """Retrieve the artifacts json object"""
        if "_artifacts" not in self._memo:
            json = get_url(self._artifacts_url).json()
            self._memo["_artifacts"] = json["artifacts"]
        assert isinstance(self._memo["_artifacts"], list)
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
        assert isinstance(self._memo["_artifact_base"], str)
        return self._memo["_artifact_base"]

    @property
    def _artifacts_url(self) -> str:
        """Build the artifacts url"""
        assert self._task is not None
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
    def build_info(self) -> dict[str, str]:
        """Return the build's info"""
        if "build_info" not in self._memo:
            self._memo["build_info"] = get_url(self.artifact_url("json")).json()
        assert isinstance(self._memo["build_info"], dict)
        return self._memo["build_info"]

    @property
    def changeset(self) -> str:
        """Return the build's revision"""
        return self.build_info["moz_source_stamp"]

    @property
    def moz_info(self) -> dict[str, str | bool | int]:
        """Return the build's mozinfo"""
        if "moz_info" not in self._memo:
            try:
                self._memo["moz_info"] = get_url(
                    self.artifact_url("mozinfo.json")
                ).json()
            except FetcherException:
                # If mozinfo doesn't exist, set the default topsrcdir
                self._memo["moz_info"] = {"topsrcdir": "/builds/worker/checkouts/gecko"}

        assert isinstance(self._memo["moz_info"], dict)
        return self._memo["moz_info"]

    @property
    def rank(self) -> int:
        """Return the build's rank"""
        assert self._task is not None
        assert isinstance(self._task.rank, int)
        return self._task.rank

    @property
    def task_id(self) -> str:
        """Return the build's TaskCluster ID"""
        assert self._task is not None
        assert isinstance(self._task.taskId, str)
        return self._task.taskId

    @property
    def task_url(self) -> str:
        """Return the TaskCluster base url"""
        assert self._task is not None
        assert isinstance(self._task.url, str)
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
        syms_wanted = False

        if "js" in targets_remaining:
            have_exec = True
            targets_remaining.remove("js")
            resolve_url(self.artifact_url("jsshell.zip"))

        if "firefox" in targets_remaining:
            have_exec = True
            # We only check that crashreporter symbols exist for builds where it is
            # enabled and only if downloading firefox itself.
            # Add --disable-crashreporter to mozconfig if you don't need them.
            syms_wanted = bool(self.moz_info["crashreporter"])
            targets_remaining.remove("firefox")
            if self._platform.system == "Linux":
                for ext in ("xz", "bz2"):
                    url = self.artifact_url(f"tar.{ext}")
                    with suppress(FetcherException):
                        resolve_url(url)
                        break
                else:
                    raise FetcherException("Failed to resolve linux artifacts!")
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

        if "mozharness" in targets_remaining:
            targets_remaining.remove("mozharness")
            artifact_path = "/".join(self._artifact_base.split("/")[:-1])
            url = f"{self._artifacts_url}/{artifact_path}/mozharness.zip"
            resolve_url(url)

        if have_exec:
            if self._flags.coverage and not self._flags.nyx:
                resolve_url(self.artifact_url("code-coverage-gcno.zip"))

            if syms_wanted:
                resolve_url(self.artifact_url("crashreporter-symbols.zip"))

        if "searchfox" in targets_remaining:
            targets_remaining.remove("searchfox")
            resolve_url(self.artifact_url("mozsearch-index.zip"))
            resolve_url(self.artifact_url("generated-files.tar.gz"))
            resolve_url(self.artifact_url("mozsearch-distinclude.map"))

        for target in targets_remaining:
            try:
                resolve_url(self.artifact_url(f"{target}.tests.tar.gz"))
            except FetcherException:  # noqa: PERF203
                resolve_url(self.artifact_url(f"{target}.tests.zip"))

    def extract_build(self, path: PathArg) -> None:
        """Download and extract the build and requested extra artifacts.

        If an executable target is requested (js/firefox), coverage data
        and/or symbols may be downloaded for the build.

        Arguments:
            path: Path to extract downloaded artifacts.
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        targets_remaining = set(self._targets)
        syms_wanted = False
        have_exec = False

        if "js" in targets_remaining:
            targets_remaining.remove("js")
            have_exec = True
            _path = path / "dist" / "bin"
            self.extract_zip(self.artifact_url("jsshell.zip"), _path)
            self._write_fuzzmanagerconf("js", path)

        if "firefox" in targets_remaining:
            targets_remaining.remove("firefox")
            # We only check that crashreporter symbols exist for builds where it is
            # enabled and only if downloading firefox itself.
            # Add --disable-crashreporter to mozconfig if you don't need them.
            syms_wanted = bool(self.moz_info["crashreporter"])
            have_exec = True
            if self._platform.system == "Linux":
                for ext in ("xz", "bz2"):
                    url = self.artifact_url(f"tar.{ext}")
                    with suppress(FetcherException):
                        resolve_url(url)
                        break
                # warn if we don't have a fast decompressor for bz2
                if ext == "bz2" and LBZIP2_PATH is None:
                    LOG.warning("WARNING: Install lbzip2 for much faster extraction.")
                elif ext == "xz" and XZ_PATH is None:
                    LOG.warning("WARNING: Install xz-utils for much faster extraction.")
                self.extract_tar(url, path)
            elif self._platform.system == "Darwin":
                self.extract_dmg(path)
            elif self._platform.system == "Windows":
                self.extract_zip(self.artifact_url("zip"), path)
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
                self.extract_tar(self.artifact_url("gtest.tests.tar.gz"), path)
            except FetcherException:
                self.extract_zip(self.artifact_url("gtest.tests.zip"), path)
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
            copy(
                path / "gtest" / "dependentlibs.list.gtest",
                path / "dependentlibs.list.gtest",
            )

        if "mozharness" in targets_remaining:
            targets_remaining.remove("mozharness")
            artifact_path = "/".join(self._artifact_base.split("/")[:-1])
            url = f"{self._artifacts_url}/{artifact_path}/mozharness.zip"
            self.extract_zip(url, path)

        if have_exec:
            if self._flags.coverage and not self._flags.nyx:
                self.extract_zip(self.artifact_url("code-coverage-gcno.zip"), path)

            if syms_wanted:
                if self._platform.system == "Darwin":
                    sym_path = next(path.glob("*.app/Contents/MacOS")) / "symbols"
                else:
                    sym_path = path / "symbols"
                sym_path.mkdir()
                self.extract_zip(
                    self.artifact_url("crashreporter-symbols.zip"),
                    path=sym_path,
                )

        if "searchfox" in targets_remaining:
            targets_remaining.remove("searchfox")
            self.extract_zip(self.artifact_url("mozsearch-index.zip"), path=path)
            self.extract_tar(self.artifact_url("generated-files.tar.gz"), path=path)
            download_url(
                self.artifact_url("mozsearch-distinclude.map"),
                outfile=path / "mozsearch-distinclude.map",
            )

        # any still remaining targets are assumed to be test artifacts
        for target in targets_remaining:
            try:
                self.extract_tar(self.artifact_url(f"{target}.tests.tar.gz"), path=path)
            except FetcherException:  # noqa: PERF203
                self.extract_zip(self.artifact_url(f"{target}.tests.zip"), path=path)

        # used by Pernosco to locate source ('\n' is expected)
        (path / "taskcluster-build-task").write_bytes(f"{self.task_id}\n".encode())

        LOG.info("Extracted into %s", path)

    def _write_fuzzmanagerconf(self, target: str, path: Path) -> None:
        """
        Write fuzzmanager config file for selected build

        Arguments:
            target: firefox/js
            path: fuzzmanager config path
        """
        output = RawConfigParser()
        output.add_section("Main")
        processor = self._platform.machine
        assert isinstance(processor, str)
        output.set("Main", "platform", processor.replace("_", "-"))
        output.set("Main", "product", f"mozilla-{self._branch}")
        output.set("Main", "product_version", f"{self.id:.8}-{self.changeset:.12}")
        if self._platform.system == "Android":
            output.set("Main", "os", "android")
        elif self._platform.system == "Linux":
            output.set("Main", "os", "linux")
        elif self._platform.system == "Darwin":
            output.set("Main", "os", "macosx")
        elif self._platform.system == "Windows":
            output.set("Main", "os", "windows")
        output.add_section("Metadata")
        topsrcdir = self.moz_info["topsrcdir"]
        assert isinstance(topsrcdir, str)
        output.set("Metadata", "pathPrefix", topsrcdir)
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

    def extract_zip(self, url: str, path: PathArg = ".") -> None:
        """
        Download and extract a zip artifact

        Arguments:
            url: artifact to download
            path: path to extract zip to
        """
        zip_fd, zip_fn = mkstemp(prefix="fuzzfetch-", suffix=".zip")
        os.close(zip_fd)
        try:
            download_url(url, zip_fn)
            LOG.info(".. extracting")
            extract_zip(zip_fn, path)
        finally:
            os.unlink(zip_fn)

    def extract_tar(self, url: str, path: PathArg = ".") -> None:
        """
        Extract builds with .tar.(*) extension
        When unpacking a build archive, only extract the firefox directory

        Arguments:
            url: artifact to download
            path: path to extract tar to
        """
        mode = url.split(".")[-1]
        tar_fd, tar_fn = mkstemp(prefix="fuzzfetch-", suffix=f".tar.{mode}")
        os.close(tar_fd)
        try:
            download_url(url, tar_fn)
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
        apk_fd, apk_fn = mkstemp(prefix="fuzzfetch-", suffix=".apk")
        os.close(apk_fd)
        try:
            # _artifact_base is like 'path/to/target' .. but geckoview doesn't
            # use target as a basename, so we need to extract just the path
            artifact_path = "/".join(self._artifact_base.split("/")[:-1])
            url = f"{self._artifacts_url}/{artifact_path}/geckoview_example.apk"
            download_url(url, apk_fn)
            copy(apk_fn, Path(path) / "target.apk")
        finally:
            os.unlink(apk_fn)

    def extract_dmg(self, path: PathArg = ".") -> None:
        """
        Extract builds with .dmg extension

        Will only work if `hdiutil` is available.

        Arguments:
            path: path to extract dmg contents to
        """
        dmg_fd, dmg_fn = mkstemp(prefix="fuzzfetch-", suffix=".dmg")
        os.close(dmg_fd)
        try:
            download_url(self.artifact_url("dmg"), dmg_fn)
            if system() == "Darwin":
                LOG.info(".. extracting")
                extract_dmg(dmg_fn, path)
            else:
                LOG.warning(".. can't extract target.dmg on %s", system())
                copy(dmg_fn, Path(path) / "target.dmg")
        finally:
            os.unlink(dmg_fn)

    @classmethod
    def from_args(
        cls,
        argv: Sequence[str] | None = None,
        skip_dir_check: bool = False,
    ) -> tuple[Fetcher, dict[str, bool | Path | Sequence[str]]]:
        """Construct a Fetcher from given command line arguments.

        Arguments:
            argv: Command line arguments (optional). Default is to use args from
                  sys.argv
            skip_dir_check: Boolean identifying whether to check for existing build
                            directory

        Returns:
            Returns a Fetcher object and keyword arguments for extract_build.
        """
        parser = FetcherArgs()
        parser.parser.add_argument(
            "-V",
            "--version",
            action="version",
            version=__version__,
            help="print version and exit",
        )
        args = parser.parse_args(argv)

        # do this default manually so we can error if combined with --build namespace
        # parser.set_defaults(branch='central')
        if not is_namespace(args.build):
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
            args.nyx,
            args.searchfox,
            args.afl,
        )
        obj = cls(
            args.branch,
            args.build,
            flags,
            args.target,
            platform=Platform(args.os, args.cpu),
            simulated=args.sim,
            nearest=args.nearest,
        )

        if args.name is None:
            args.name = obj.get_auto_name()

        final_dir = (args.out / args.name).resolve()
        if not skip_dir_check and os.path.exists(final_dir):
            parser.parser.error(f"Folder exists: {final_dir} .. exiting")

        extract_options = {
            "dry_run": args.dry_run,
            "out": final_dir,
        }

        return obj, extract_options

    @classmethod
    def main(cls) -> int:
        """
        fuzzfetch main entry point

        Run with --help for usage
        """
        log_level = INFO
        log_fmt = "%(message)s"
        if bool(os.getenv("DEBUG")):
            log_level = DEBUG
            log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
        basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)
        getLogger("requests").setLevel(WARNING)

        try:
            obj, extract_args = cls.from_args()

            LOG.info("Identified task: %s", obj.task_url)
            LOG.info("> Task ID: %s", obj.task_id)
            LOG.info("> Rank: %s", obj.rank)
            LOG.info("> Changeset: %s", obj.changeset)
            LOG.info("> Build ID: %s", obj.id)

            if extract_args["dry_run"]:
                return 0

            out = extract_args["out"]
            assert isinstance(out, Path)

            try:
                obj.extract_build(out)
                (out / "download").mkdir(parents=True)
                with (out / "download" / "firefox-temp.txt").open("a") as dl_fd:
                    dl_fd.write(f"buildID={obj.id}{os.linesep}")
            except:
                if out.is_dir():
                    junction_rmtree(out)
                raise
        except FetcherException as exc:
            LOG.error(str(exc))
            return 1
        return 0
