# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Code for extracting archives"""
from __future__ import annotations

import gzip
import logging
import lzma
import os
import os.path
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path
from platform import system
from subprocess import PIPE, CalledProcessError, Popen, check_call, run

from .path import PathArg, onerror

LOG = logging.getLogger("fuzzfetch")

HDIUTIL_PATH = shutil.which("hdiutil")
TAR_PATH = shutil.which("tar") if system() != "Darwin" else shutil.which("gtar")
LBZIP2_PATH = shutil.which("lbzip2")
XZ_PATH = shutil.which("xz")


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
    tar_args: list[str] = []
    external_decomp: str | None = None
    if mode == "bz2":
        # lbzip2 > bzip2
        if TAR_PATH:
            if LBZIP2_PATH:
                tar_args.extend(("-I", LBZIP2_PATH))
            else:
                tar_args.append("-j")
            mode = ""
        elif LBZIP2_PATH:
            external_decomp = LBZIP2_PATH
            mode = ""

    elif mode == "xz":
        # xz > python
        if TAR_PATH and XZ_PATH:
            tar_args.append("-J")
            mode = ""
        elif XZ_PATH:
            external_decomp = XZ_PATH
            mode = ""

    if TAR_PATH:
        Path(path).mkdir(exist_ok=True)
        cmd = [TAR_PATH, r"--transform=s,^firefox/,,", "-C", str(path), *tar_args, "-x"]
        if mode == "gz":
            # Python gzip is somehow faster than gunzip
            #
            # zcat target.gtest.tests.tar.gz  7.34s user 0.24s system 99% cpu 7.592 tota
            # tar -tv  0.02s user 0.39s system 5% cpu 7.592 total
            #
            # python3 -c   4.63s user 0.37s system 99% cpu 4.998 total
            # tar -tv  0.04s user 0.22s system 5% cpu 4.995 total
            with gzip.open(tar_fn) as gz_fp, Popen(cmd, stdin=PIPE) as tar_proc:
                assert tar_proc.stdin is not None
                shutil.copyfileobj(gz_fp, tar_proc.stdin)
            if rc := tar_proc.wait():
                raise CalledProcessError(returncode=rc, cmd=cmd)

        elif mode == "xz":
            # no external xz, use Python
            with lzma.open(tar_fn) as xz_fp:
                run(cmd, check=True, stdin=xz_fp)
        else:
            cmd.extend(("-f", str(tar_fn)))
            run(cmd, check=True, env={"XZ_DEFAULTS": "-T0"})
    else:

        def _extract_tar(tar: tarfile.TarFile) -> None:
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

        if external_decomp:
            cmd = [external_decomp, "-dc", str(tar_fn)]
            with Popen(
                cmd, env={"XZ_DEFAULTS": "-T0"}, stdout=PIPE
            ) as decomp, tarfile.open(fileobj=decomp.stdout, mode="r|") as tar:
                _extract_tar(tar)
            if rc := decomp.wait():
                raise CalledProcessError(returncode=rc, cmd=cmd)
        else:
            with tarfile.open(tar_fn, mode=f"r:{mode}") as tar:
                _extract_tar(tar)


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
        shutil.rmtree(out_tmp, onerror=onerror)  # pylint: disable=deprecated-argument
