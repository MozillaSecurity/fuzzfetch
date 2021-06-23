# coding=utf-8
"""code for extracting archives"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path
from subprocess import DEVNULL, call, check_call, check_output

from .path import PathArg, onerror

LOG = logging.getLogger("fuzzfetch")


HDIUTIL_PATH = shutil.which("hdiutil")
P7Z_PATH = shutil.which("7z")


def extract_zip(zip_fn: PathArg, path: PathArg = ".") -> None:
    """Download and extract a zip artifact

    Arguments:
        zip_fn: path to zip archive
        path: where to extract zip contents
    """
    dest_path = Path(path)

    def _extract_file(zip_fp: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
        """Extract files while explicitly setting the proper permissions"""
        zip_fp.extract(info.filename, path=dest_path)
        out_path = dest_path / info.filename

        perm = info.external_attr >> 16
        perm |= stat.S_IREAD  # make sure we're not accidentally setting this to 0
        out_path.chmod(perm)

    if P7Z_PATH:
        check_output([P7Z_PATH, "x", "-bd", f"-o{dest_path}", zip_fn])
    else:
        with zipfile.ZipFile(zip_fn) as zip_fp:
            for info in zip_fp.infolist():
                _extract_file(zip_fp, info)


def extract_tar(tar_fn: PathArg, mode: str = "", path: PathArg = ".") -> None:
    """Extract builds with .tar.(*) extension
    When unpacking a build archive, only extract the firefox directory

    Arguments:
        tar_fn: path to tar archive
        mode: compression type
        path: where to extract tar contents
    """
    try:
        if P7Z_PATH and mode in {"7z", "bz2", "gz", "lzma", "xz"}:
            p7z_fd, p7z_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".tar")
            result = call([P7Z_PATH, "e", "-so", tar_fn], stdout=p7z_fd, stderr=DEVNULL)
            os.close(p7z_fd)
            if result == 0:
                mode = ""
                tar_fn = p7z_fn
            else:
                LOG.warning(
                    "7z was found, but returned %d decompressing %r", result, tar_fn
                )
        with tarfile.open(tar_fn, mode=f"r:{mode}") as tar:
            members = []
            for member in tar.getmembers():
                if member.path.startswith("firefox/"):
                    member.path = member.path[8:]
                    members.append(member)
                elif member.path != "firefox":
                    # Ignore top-level build directory
                    members.append(member)
            tar.extractall(members=members, path=path)
    finally:
        if P7Z_PATH:
            os.unlink(p7z_fn)


def extract_dmg(dmg_fn: PathArg, path: PathArg = ".") -> None:
    """Extract builds with .dmg extension

    Will only work if `hdiutil` is available.

    Arguments:
        dmg_fn: path to dmg image
        path: where to extract dmg contents
    """
    assert HDIUTIL_PATH, "Extracting .dmg requires hdiutil"
    out_tmp = Path(tempfile.mkdtemp(prefix="fuzzfetch-", suffix=".tmp"))
    dest_path = Path(path)
    try:
        check_call([HDIUTIL_PATH, "attach", "-quiet", "-mountpoint", out_tmp, dmg_fn])
        try:
            apps = [mt for mt in out_tmp.glob("*") if mt.suffix == ".app"]
            assert len(apps) == 1
            shutil.copytree(
                out_tmp / apps[0].name,
                dest_path / apps[0].name,
                symlinks=True,
            )
        finally:
            check_call([HDIUTIL_PATH, "detach", "-quiet", out_tmp])
    finally:
        shutil.rmtree(out_tmp, onerror=onerror)
