# coding=utf-8
"""fuzzfetch tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import, division, print_function, unicode_literals

import gzip
import itertools
import logging
import os
import time

import pytest
import requests_mock
import fuzzfetch


log = logging.getLogger("fuzzfetch_test")  # pylint: disable=invalid-name
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("flake8").setLevel(logging.WARNING)

HERE = os.path.dirname(os.path.abspath(__file__))

BUILD_CACHE = False


if BUILD_CACHE:
    if str is bytes:
        from urllib2 import HTTPError, Request, urlopen  # pylint: disable=import-error
    else:
        from urllib.error import HTTPError  # pylint: disable=import-error,no-name-in-module
        from urllib.request import Request, urlopen  # pylint: disable=import-error,no-name-in-module


def get_builds_to_test():
    """Get permutations for testing build branches and flags"""
    possible_flags = (fuzzfetch.BuildFlags(asan=False, debug=False, fuzzing=False, coverage=False),  # opt
                      fuzzfetch.BuildFlags(asan=False, debug=True, fuzzing=False, coverage=False),  # debug
                      fuzzfetch.BuildFlags(asan=False, debug=False, fuzzing=False, coverage=True),  # ccov
                      fuzzfetch.BuildFlags(asan=True, debug=False, fuzzing=False, coverage=False),  # asan-opt
                      fuzzfetch.BuildFlags(asan=True, debug=False, fuzzing=True, coverage=False),  # asan-opt-fuzzing
                      fuzzfetch.BuildFlags(asan=False, debug=True, fuzzing=True, coverage=False),  # debug-fuzzing
                      fuzzfetch.BuildFlags(asan=False, debug=False, fuzzing=True, coverage=True))  # ccov-fuzzing
    possible_branches = ("central", "inbound")
    possible_os = ('Android', 'Darwin', 'Linux', 'Windows')
    possible_cpus = ('x86', 'x64', 'arm', 'arm64')

    for branch, flags, os_, cpu in itertools.product(possible_branches, possible_flags, possible_os, possible_cpus):
        try:
            fuzzfetch.fetch.Platform(os_, cpu)
        except fuzzfetch.FetcherException:
            continue
        if flags.coverage and (os_ != "Linux" or cpu != 'x64' or branch != 'central'):
            # coverage builds not done for android/macos/windows
            # coverage builds are only done on central
            continue
        elif flags.asan and cpu != 'x64':
            continue
        elif flags.debug and flags.fuzzing and os_ == 'Windows' and cpu == 'x64':
            continue
        elif flags.debug and flags.fuzzing and os_ == 'Darwin':
            continue
        elif flags.debug and flags.fuzzing and os_ == 'Linux' and cpu == 'x86':
            continue
        elif os_ == 'Darwin' and flags.asan and not flags.fuzzing:
            continue
        elif os_ == 'Android' and flags.debug and not flags.fuzzing and cpu != 'arm':
            continue
        elif os_ == 'Android' and flags.fuzzing and (cpu != 'x86' or flags.asan or not flags.debug):
            continue
        elif os_ == "Windows" and flags.asan and branch not in {"central", "inbound"}:
            # asan builds for windows are only done for central/inbound
            continue
        elif os_ == "Windows" and flags.asan and (flags.fuzzing or flags.debug):
            # windows only has asan-opt ?
            continue
        else:
            yield pytest.param(branch, flags, os_, cpu)


def callback(request, context):
    """
    request handler for requests.mock
    """
    log.debug('%s %r', request.method, request.url)
    assert request.url.startswith('https://')
    path = os.path.join(HERE, request.url.replace('https://index.taskcluster.net', 'mock-index')
                        .replace('https://queue.taskcluster.net', 'mock-queue').replace('/', os.sep))
    if os.path.isfile(path):
        context.status_code = 200
        with open(path, 'rb') as resp_fp:
            data = resp_fp.read()
        log.debug('-> 200 (%d bytes from %s)', len(data), path)
        return data
    if os.path.isdir(path) and os.path.isfile(os.path.join(path, '.get')):
        path = os.path.join(path, '.get')
        context.status_code = 200
        with open(path, 'rb') as resp_fp:
            data = resp_fp.read()
        log.debug('-> 200 (%d bytes from %s)', len(data), path)
        return data
    # download to cache in mock directories
    if BUILD_CACHE:
        folder = os.path.dirname(path)
        try:
            if not os.path.isdir(folder):
                os.makedirs(folder)
        except OSError:
            # see if any of the leaf folders are actually files
            orig_folder = folder
            while os.path.abspath(folder) != os.path.abspath(HERE):
                if os.path.isfile(folder):
                    # need to rename
                    os.rename(folder, folder + '.tmp')
                    os.makedirs(orig_folder)
                    os.rename(folder + '.tmp', os.path.join(folder, '.get'))
                    break
                folder = os.path.dirname(folder)
        urllib_request = Request(request.url, request.body if request.method == 'POST' else None, request.headers)
        try:
            real_http = urlopen(urllib_request)
        except HTTPError as exc:
            context.status_code = exc.code
            return None
        with open(path, 'wb') as resp_fp:
            data = real_http.read()
            resp_fp.write(data)
        if data[:2] == b'\x1f\x8b':  # gzip magic number
            with gzip.open(path) as zipf:
                data = zipf.read()
            with open(path, 'wb') as resp_fp:
                resp_fp.write(data)
        context.status_code = real_http.getcode()
        log.debug('-> %d (%d bytes from http)', context.status_code, len(data))
        return data
    context.status_code = 404
    log.debug('-> 404 (at %s)', path)
    return None


@pytest.mark.parametrize('branch, build_flags, os_, cpu', get_builds_to_test())
def test_metadata(branch, build_flags, os_, cpu):
    """Instantiate a Fetcher (which downloads metadata from TaskCluster) and check that the build is recent"""
    # BuildFlags(asan, debug, fuzzing, coverage)
    # Fetcher(target, branch, build, flags, arch_32)
    with requests_mock.Mocker() as req_mock:
        req_mock.register_uri(requests_mock.ANY, requests_mock.ANY, content=callback)
        platform_ = fuzzfetch.fetch.Platform(os_, cpu)
        for as_args in (True, False):  # try as API and as command line
            if as_args:
                args = ["--" + name for arg, name in zip(build_flags, fuzzfetch.BuildFlags._fields) if arg]
                fetcher = fuzzfetch.Fetcher.from_args(["--" + branch, '--cpu', cpu, '--os', os_] + args)[0]
            else:
                if branch == "esr":
                    branch = "esr52"
                fetcher = fuzzfetch.Fetcher("firefox", branch, "latest", build_flags, platform_)
            log.debug("succeeded creating Fetcher")

            log.debug("buildid: %s", fetcher.build_id)
            log.debug("hgrev: %s", fetcher.changeset)

            time_obj = time.strptime(fetcher.build_id, "%Y%m%d%H%M%S")

            # yyyy-mm-dd is also accepted as a build input
            date_str = "%d-%02d-%02d" % (time_obj.tm_year, time_obj.tm_mon, time_obj.tm_mday)
            if as_args:
                fuzzfetch.Fetcher.from_args(["--" + branch, '--cpu', cpu, '--os', os_, "--build", date_str] + args)
            else:
                fuzzfetch.Fetcher("firefox", branch, date_str, build_flags, platform_)

            # hg rev is also accepted as a build input
            rev = fetcher.changeset
            if as_args:
                fuzzfetch.Fetcher.from_args(["--" + branch, '--cpu', cpu, '--os', os_, "--build", rev] + args)
            else:
                fuzzfetch.Fetcher("firefox", branch, rev, build_flags, platform_)
            # namespace = fetcher.build

            # TaskCluster namespace is also accepted as a build input
            # namespace = ?
            # fuzzfetch.Fetcher("firefox", branch, namespace, (asan, debug, fuzzing, coverage))
