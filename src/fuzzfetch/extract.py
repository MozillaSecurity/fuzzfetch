"""code for extracting archives"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import gzip
import logging
import os
import os.path
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path
from platform import system
from subprocess import DEVNULL, call, check_call

from .path import PathArg, onerror

LOG = logging.getLogger("fuzzfetch")


HDIUTIL_PATH = shutil.which("hdiutil")
TAR_PATH = shutil.which("tar") if system() != "Darwin" else shutil.which("gtar")
LBZIP2_PATH = shutil.which("lbzip2")


def extract_zip(zip_fn: PathArg, path: PathArg = ".") -> None:
    """Download and extract a zip artifact

    Arguments:
        zip_fn: path to zip archive
        path: where to extract zip contents
    """
    dest_path = Path(path)

    def _extract_entry(zip_fp: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
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
                shutil.copyfileobj(zip_member_fp, out_fp)

        perm = info.external_attr >> 16
        perm |= stat.S_IREAD  # make sure we're not accidentally setting this to 0
        out_path.chmod(perm)

    with zipfile.ZipFile(zip_fn) as zip_fp:
        for info in zip_fp.infolist():
            _extract_entry(zip_fp, info)


def _is_within_directory(directory: PathArg, target: PathArg) -> bool:
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)

    prefix = os.path.commonpath([abs_directory, abs_target])

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
        if LBZIP2_PATH and mode == "bz2":
            # fastest bz2 decompressor by far
            tmp_fd, tmp_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".tar")
            result = call([LBZIP2_PATH, "-dc", tar_fn], stdout=tmp_fd, stderr=DEVNULL)
            os.close(tmp_fd)
            if result == 0:
                mode = ""
                tar_fn = tmp_fn
            else:
                LOG.warning(
                    "lbzip2 was found, but returned %d decompressing %r", result, tar_fn
                )

        elif TAR_PATH and mode == "gz":
            # this is faster than gunzip somehow
            tmp_fd, tmp_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".tar")
            with gzip.open(tar_fn) as gz_fp, open(tmp_fd, "wb") as tmp_fp:
                shutil.copyfileobj(gz_fp, tmp_fp)
            mode = ""
            tar_fn = tmp_fn

        if TAR_PATH:
            cmd = [TAR_PATH, r"--transform=s,^firefox/,,", "-C", str(path)]
            if mode:
                cmd.append(
                    {
                        "gz": "-z",
                        "bz2": "-j",
                        "lzma": "--lzma",
                        "xz": "-J",
                    }.get(mode, "--auto-compress")
                )
            cmd.extend(("-xf", str(tar_fn)))
            check_call(cmd)
        else:
            with tarfile.open(tar_fn, mode=f"r:{mode}") as tar:
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
