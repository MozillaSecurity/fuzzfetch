# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Code for extracting archives"""

import os
from logging import getLogger
from os.path import abspath, commonpath
from pathlib import Path
from shutil import copyfileobj, copytree, rmtree, which
from stat import S_IREAD
from subprocess import PIPE, run
from tarfile import open as tar_open
from tempfile import mkdtemp, mkstemp
from zipfile import ZipFile, ZipInfo

from .path import PathArg, onerror

LOG = getLogger("fuzzfetch")

HDIUTIL_PATH = which("hdiutil")
LBZIP2_PATH = which("lbzip2")
XZ_PATH = which("xz")
ZSTD_PATH = which("zstd")
EXT_WARNINGS = {"bz2", "xz", "zst"}


def extract_zip(zip_fn: PathArg, path: PathArg = ".") -> None:
    """Download and extract a zip artifact

    Arguments:
        zip_fn: path to zip archive
        path: where to extract zip contents
    """
    dest_path = Path(path)

    def _extract_entry(zip_fp: ZipFile, info: ZipInfo) -> None:
        """Extract entries while explicitly setting the proper permissions"""
        rel_path = Path(info.filename)

        # strip leading "firefox" from path
        if rel_path.parts[0] == ".":
            rel_path = Path(*rel_path.parts[1:])
        if rel_path.parts[0] == "firefox":
            rel_path = Path(*rel_path.parts[1:])

        out_path = dest_path / rel_path

        if info.is_dir():
            out_path.mkdir(parents=True, exist_ok=True)
        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with zip_fp.open(info) as zip_member_fp, out_path.open("wb") as out_fp:
                copyfileobj(zip_member_fp, out_fp)

        perm = info.external_attr >> 16
        perm |= S_IREAD  # make sure we're not accidentally setting this to 0
        out_path.chmod(perm)

    with ZipFile(zip_fn) as zip_fp:
        for info in zip_fp.infolist():
            _extract_entry(zip_fp, info)


def _is_within_directory(directory: PathArg, target: PathArg) -> bool:
    abs_directory = abspath(directory)
    abs_target = abspath(target)

    prefix = commonpath([abs_directory, abs_target])

    return prefix == abs_directory


def extract_tar(tar_fn: PathArg, mode: str = "", path: PathArg = ".") -> None:
    """Extract builds with .tar.(*) extension
    When unpacking a build archive, only extract the firefox directory

    Arguments:
        tar_fn: path to tar archive
        mode: compression type
        path: where to extract tar contents
    """
    tmp_fn = None
    try:

        def _external_decomp(decomp: str) -> None:
            nonlocal mode, tar_fn, tmp_fn
            tmp_fd, tmp_fn = mkstemp(prefix="fuzzfetch-", suffix=".tar")
            args = ["-dc"]
            if mode in {"xz", "zst"}:
                args.append("-T0")
            result = run(  # pylint: disable=subprocess-run-check
                [decomp, *args, tar_fn],
                stdout=tmp_fd,
                stderr=PIPE,
            )
            os.close(tmp_fd)
            if result.returncode == 0:
                mode = ""
                tar_fn = tmp_fn
            else:
                LOG.warning(
                    "%s was found, but returned %d decompressing %r",
                    Path(decomp).name,
                    result.returncode,
                    tar_fn,
                )

        if mode == "bz2":
            if LBZIP2_PATH:
                # lbzip2 is significantly faster than python's bzip2 module
                _external_decomp(LBZIP2_PATH)
            elif "bz2" in EXT_WARNINGS:
                EXT_WARNINGS.remove("bz2")
                LOG.warning("WARNING: Install lbzip2 for much faster extraction.")

        elif mode == "xz":
            if XZ_PATH:
                # xz is significantly faster than python's lzma module
                _external_decomp(XZ_PATH)
            elif "xz" in EXT_WARNINGS:
                EXT_WARNINGS.remove("xz")
                LOG.warning("WARNING: Install xz-utils for much faster extraction.")

        elif mode == "zst":
            if ZSTD_PATH:
                # zstd is significantly faster than python's zstd module
                _external_decomp(ZSTD_PATH)
            elif "zst" in EXT_WARNINGS:
                EXT_WARNINGS.remove("zst")
                LOG.warning("WARNING: Install zstd for much faster extraction.")

        with tar_open(tar_fn, mode=f"r:{mode}") as tar:  # type: ignore
            members = []
            for member in tar.getmembers():
                if not _is_within_directory(path, Path(path) / member.name):
                    raise RuntimeError("Attempted Path Traversal in Tar File")
                if member.name.startswith("firefox/"):
                    member.name = member.name[8:]
                    members.append(member)
                elif member.name != "firefox":
                    # Ignore top-level build directory
                    members.append(member)
            tar.extractall(members=members, path=path)

    finally:
        if tmp_fn is not None:
            os.unlink(tmp_fn)


def extract_dmg(dmg_fn: PathArg, path: PathArg = ".") -> None:
    """Extract builds with .dmg extension

    Will only work if `hdiutil` is available.

    Arguments:
        dmg_fn: path to dmg image
        path: where to extract dmg contents
    """
    assert HDIUTIL_PATH, "Extracting .dmg requires hdiutil"
    out_tmp = Path(mkdtemp(prefix="fuzzfetch-", suffix=".tmp"))
    dest_path = Path(path)
    try:
        run(
            [HDIUTIL_PATH, "attach", "-quiet", "-mountpoint", out_tmp, dmg_fn],
            check=True,
        )
        try:
            apps = [mt for mt in out_tmp.glob("*") if mt.suffix == ".app"]
            assert len(apps) == 1
            copytree(
                out_tmp / apps[0].name,
                dest_path / apps[0].name,
                symlinks=True,
            )
        finally:
            run([HDIUTIL_PATH, "detach", "-quiet", out_tmp], check=True)
    finally:
        rmtree(out_tmp, onerror=onerror)  # pylint: disable=deprecated-argument
