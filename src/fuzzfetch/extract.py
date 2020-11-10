# coding=utf-8
"""code for extracting archives"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=too-many-statements

from __future__ import absolute_import, division, print_function, unicode_literals

import logging
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile

from .path import onerror

LOG = logging.getLogger("fuzzfetch")


HDIUTIL_PATH = None
P7Z_PATH = None


def _extract_file(zip_fp, info, path):
    """Extract files while explicitly setting the proper permissions"""
    zip_fp.extract(info.filename, path=path)
    out_path = os.path.join(path, info.filename)

    perm = info.external_attr >> 16
    perm |= stat.S_IREAD  # make sure we're not accidentally setting this to 0
    os.chmod(out_path, perm)


def extract_zip(zip_fn, path="."):
    """
    Download and extract a zip artifact

    Arguments:
        zip_fn
        path
    """
    global P7Z_PATH  # pylint: disable=global-statement
    if P7Z_PATH is None:
        P7Z_PATH = shutil.which("7z") or ""
    if P7Z_PATH:
        subprocess.check_output([P7Z_PATH, "x", "-bd", "-o" + path, zip_fn])
    else:
        with zipfile.ZipFile(zip_fn) as zip_fp:
            for info in zip_fp.infolist():
                _extract_file(zip_fp, info, path)


def extract_tar(tar_fn, mode="", path="."):
    """
    Extract builds with .tar.(*) extension
    When unpacking a build archive, only extract the firefox directory

    Arguments:
        tar_fn
        mode
        path
    """
    global P7Z_PATH  # pylint: disable=global-statement
    if P7Z_PATH is None:
        P7Z_PATH = shutil.which("7z") or ""
    try:
        if P7Z_PATH and mode in {"7z", "bz2", "gz", "lzma", "xz"}:
            p7z_fd, p7z_fn = tempfile.mkstemp(prefix="fuzzfetch-", suffix=".tar")
            with open(os.devnull, "w") as devnull:
                result = subprocess.call(
                    [P7Z_PATH, "e", "-so", tar_fn], stdout=p7z_fd, stderr=devnull
                )
            os.close(p7z_fd)
            if result == 0:
                mode = ""
                tar_fn = p7z_fn
            else:
                LOG.warning(
                    "7z was found, but returned %d decompressing %r", result, tar_fn
                )
        with tarfile.open(tar_fn, mode="r:%s" % mode) as tar:
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


def extract_dmg(dmg_fn, path="."):
    """
    Extract builds with .dmg extension

    Will only work if `hdiutil` is available.

    Arguments:
        path
    """
    global HDIUTIL_PATH  # pylint: disable=global-statement
    if HDIUTIL_PATH is None:
        HDIUTIL_PATH = shutil.which("hdiutil") or ""
    assert HDIUTIL_PATH, "Extracting .dmg requires hdiutil"
    out_tmp = tempfile.mkdtemp(prefix="fuzzfetch-", suffix=".tmp")
    try:
        subprocess.check_call(
            [HDIUTIL_PATH, "attach", "-quiet", "-mountpoint", out_tmp, dmg_fn]
        )
        try:
            apps = [mt for mt in os.listdir(out_tmp) if mt.endswith("app")]
            assert len(apps) == 1
            shutil.copytree(
                os.path.join(out_tmp, apps[0]),
                os.path.join(path, apps[0]),
                symlinks=True,
            )
        finally:
            subprocess.check_call([HDIUTIL_PATH, "detach", "-quiet", out_tmp])
    finally:
        shutil.rmtree(out_tmp, onerror=onerror)
