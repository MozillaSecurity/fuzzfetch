# coding=utf-8
"""fuzzfetch path functions"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import platform
import stat
import subprocess

if platform.system() == "Windows":
    import _winapi  # pylint: disable=import-error


FILE_ATTRIBUTE_REPARSE_POINT = 1024


def onerror(func, path, _exc_info):
    """
    Error handler for `shutil.rmtree`.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Copyright Michael Foord 2004
    Released subject to the BSD License
    ref: http://www.voidspace.org.uk/python/recipebook.shtml#utils

    Usage : `shutil.rmtree(path, onerror=onerror)`
    """
    if not os.access(path, os.W_OK):
        # Is the error an access error?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        # this should only ever be called from an exception context
        raise  # pylint: disable=misplaced-bare-raise


def rmtree(path):
    """shutil.rmtree() but also handle junction points and access errors on Windows."""
    if islink(path):
        unlink(path)
    elif os.path.isdir(path):
        for sub in os.listdir(path):
            sub = os.path.join(path, sub)
            if os.path.isfile(sub):
                if not os.access(sub, os.W_OK):
                    # Is the error an access error?
                    os.chmod(sub, stat.S_IWUSR)
                os.unlink(sub)
            else:
                rmtree(sub)
        os.rmdir(path)
    else:
        raise RuntimeError("rmtree called on non-link/folder")


def islink(path):
    """os.path.islink() but return True for junction points on Windows."""
    if platform.system() == "Windows":
        try:
            st = os.lstat(path)  # pylint: disable=invalid-name
        except (OSError, AttributeError):
            return False
        # pylint: disable=no-member
        return (
            stat.S_ISLNK(st.st_mode)
            or st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
    return os.path.islink(path)


def unlink(link):
    """os.unlink() but handle junction points on Windows."""
    if islink(link) and platform.system() == "Windows":
        # deleting junction points was added to os.unlink in 3.5
        # https://bugs.python.org/issue18314
        subprocess.check_call(["rmdir", link], shell=True)
    else:
        os.unlink(link)


def symlink(target, link):
    """os.symlink() but use a junction point on Windows."""
    if islink(link):
        unlink(link)
    if platform.system() == "Windows":
        _winapi.CreateJunction(target, link)
    else:
        os.symlink(target, link)  # pylint: disable=no-member
