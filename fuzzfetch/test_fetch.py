#!/usr/bin/env python
# coding=utf-8
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import, division, print_function, unicode_literals

import glob
import itertools
import logging
import os
import shutil
import sys
import tempfile
import unittest

from . import fetch

log = logging.getLogger("fuzzfetch_test")
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)


class PushDir(object): # pylint: disable=too-few-public-methods
    """
    Context manager which changes directory and remembers the original
    directory at time of creation. When exited, it will chdir back to
    the original.
    """
    def __init__(self, chd):
        self.new_dir = chd
        self.old_dir = os.getcwd()
        log.debug("")

    def __enter__(self):
        os.chdir(self.new_dir)
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        os.chdir(self.old_dir)
        return False


class TempCWD(PushDir): # pylint: disable=too-few-public-methods
    """
    Context manager which creates a temp directory, chdirs to it, and when
    the context is exited will chdir back to the cwd at time of creation, and
    delete the temp directory.

    All arguments are passed through to tempfile.mkdtemp.
    """
    def __init__(self, *args, **kwds):
        tmp_dir = tempfile.mkdtemp(*args, **kwds)
        super(TempCWD, self).__init__(tmp_dir)

    def __exit__(self, exc_type, exc_val, exc_tb):
        super(TempCWD, self).__exit__(exc_type, exc_val, exc_tb)
        shutil.rmtree(self.new_dir)
        return False


class FetchTests(unittest.TestCase):

    def inspect_build(self, target):
        binary_path = os.path.join("dist", "bin", target + (".exe" if sys.platform.startswith("win") else ""))
        program_cfg_path = os.path.join("dist", "bin", target + ".fuzzmanagerconf")
        self.assertTrue(os.path.isfile(binary_path))
        self.assertTrue(os.path.isfile(program_cfg_path))
        if sys.platform.startswith("linux"):
            self.assertEqual(os.path.realpath(target), os.path.realpath(os.path.join("dist", "bin", target)))
        elif sys.platform == "darwin":
            if target == "js":
                self.assertEqual(os.path.realpath(target), os.path.realpath(os.path.join("dist", "bin", target)))
            else:
                ff_locs = glob.glob("*.app/Contents/MacOS")
                self.assertEqual(len(ff_locs), 1)
                self.assertEqual(os.path.realpath(os.path.join(ff_locs[0], target)),
                                 os.path.realpath(os.path.join("dist", "bin", target)))
        else:
            raise NotImplementedError()

    #Fetcher(target, branch, build, asan, debug, tests=None, symbols=None)
    def test_nightly(self):
        "Download all combinations of opt/debug, asan/regular, central/inbound, shell/browser"
        for (target, branch, build, asan, debug) in itertools.product(("js", "firefox"), # target
                                                                      ("central", "inbound"), # branch
                                                                      ("latest",), # build
                                                                      (True, False), # asan
                                                                      (True, False)): # debug
            if asan and not sys.platform.startswith("linux"):
                continue
            with TempCWD():
                # download the build
                fetcher = fetch.Fetcher(target, branch, build, (asan, debug, False))
                fetcher.extract_build()
                self.inspect_build(target)
