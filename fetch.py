#!/usr/bin/env python
# coding=utf-8
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import configparser
import glob
import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

import requests

log = logging.getLogger('fuzzfetch')  # pylint: disable=invalid-name


BUG_URL = 'https://github.com/MozillaSecurity/fuzzfetch/issues/'
HTTP_SESSION = requests.Session()


class FetcherException(Exception):
    "Exception raised for any Fetcher errors."


def _get_url(url):
    try:
        data = HTTP_SESSION.get(url, stream=True)
        data.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise FetcherException(exc)

    return data


def _extract_file(zf, info, path):
    """
    Extract files while explicitly setting the proper permissions
    """
    zf.extract(info.filename, path=path)
    out_path = os.path.join(path, info.filename)

    perm = info.external_attr >> 16
    os.chmod(out_path, perm)


class Fetcher(object):
    re_target = re.compile(r'(\.linux-(x86_64|i686)(-asan)?|target|mac(64)?|win(32|64))\.json$')

    def __init__(self, target, branch, build, asan, debug, tests=None, symbols=None):
        self._target = target
        self._branch = branch
        self._build = build
        self._asan = asan
        self._debug = debug
        self._tests = tests
        self._symbols = symbols

        self.task_url = self._task_url()
        task = _get_url(self.task_url).json()
        self.task_id = task['taskId']
        self.rank = task['rank']

        # Download build information of Firefox
        self._artifacts_url = 'https://queue.taskcluster.net/v1/task/{}/artifacts'.format(self.task_id)
        self._artifacts = self._get_artifacts()
        self._artifact_base = self._get_artifact_base()

        self.build_info = _get_url(self.artifact_url('json')).json()
        self.moz_info = _get_url(self.artifact_url('mozinfo.json')).json()

        # if the build string contains the platform, assume it is a TaskCluster namespace
        if self.moz_info["platform_guess"] in self._build:
            # try to set args to match the namespace given
            if self._branch is None:
                branch = re.search(r'\.mozilla-(?P<branch>[a-z]+[0-9]*)\.', self._build)
                self._branch = branch.group('branch') if branch is not None else '?'
            if not self._debug:
                self._debug = '-debug' in self._build or '-dbg' in self._build
            if not self._asan:
                self._asan = '-asan' in self._build

            # '?' is special case used for unknown build types
            if self._branch != '?' and self._branch not in self._build:
                raise FetcherException("'build' and 'branch' arguments do not match. "
                                       "(build={}, branch={})".format(self._build, self._branch))
            if self._asan and '-asan' not in self._build:
                raise FetcherException("'build' is not an asan build, but asan=True given "
                                       "(build={})".format(self._build))
            if self._debug and not ('-dbg' in self._build or '-debug' in self._build):
                raise FetcherException("'build' is not a debug build, but debug=True given "
                                       "(build={})".format(self._build))


    def _get_pushdate_url(self, build_arg, target_platform):
        """
        Multiple entries exist per push date. Iterate over all until a working entry is found
        """
        url_base = 'https://index.taskcluster.net/v1/namespaces/gecko.v2.mozilla-{0}.pushdate.{1}'.format(
            self._branch,
            build_arg)

        # Taskcluster denotes builds in one of two formats - i.e. linux64-asan or linux64-asan-opt - try both
        build_strings = [
            '{0}{1}'.format(
                '-asan' if self._asan else '',
                '-debug' if self._debug else '-opt'),
            '{0}{1}'.format(
                '-asan' if self._asan else '',
                '-debug' if self._debug else '')
        ]

        try:
            base = HTTP_SESSION.post(url_base, json={})
            base.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FetcherException(exc)

        json = base.json()
        for ns in json['namespaces']:
            for build_string in build_strings:
                url = 'https://index.taskcluster.net/v1/task/{0}.firefox.{1}{2}'.format(
                    ns['namespace'],
                    target_platform,
                    build_string)

                try:
                    data = HTTP_SESSION.get(url)
                    data.raise_for_status()
                except requests.exceptions.RequestException:
                    pass
                else:
                    log.debug('Found archive for pushdate %s', build_arg)
                    return url

        raise FetcherException('Unable to find usable archive for pushdate ' + build_arg)

    def _get_revision_url(self, build_arg, target_platform):
        """
        Retrieve the URL for revision based builds

        """
        url_base = 'https://index.taskcluster.net/v1/task/gecko.v2.mozilla-{0}.revision.{1}.firefox'.format(
            self._branch,
            build_arg)

        # Taskcluster denotes builds in one of two formats - i.e. linux64-asan or linux64-asan-opt - try both
        build_strings = [
            '{0}{1}'.format(
                '-asan' if self._asan else '',
                '-debug' if self._debug else '-opt'),
            '{0}{1}'.format(
                '-asan' if self._asan else '',
                '-debug' if self._debug else '')
        ]

        for build_string in build_strings:
            url = '{0}.{1}{2}'.format(
                url_base,
                target_platform,
                build_string)

            try:
                data = HTTP_SESSION.get(url)
                data.raise_for_status()
            except requests.exceptions.RequestException:
                pass
            else:
                log.debug('Found archive for pushdate %s', build_arg)
                return url

        raise FetcherException('Unable to find usable archive for pushdate ' + build_arg)

    def _task_url(self):
        """
        Retrieve the task JSON object
        Requires first generating the task URL based on the specified build type and platform
        """
        # Prepare build type
        url_base = 'https://index.taskcluster.net/v1/task/'
        target_platform = 'macosx64' if sys.platform == 'darwin' else 'linux64'

        if re.match(r'\d{4}-\d{2}-\d{2}$', self._build):
            build_arg = self._build.replace('-', '.')
            task_url = self._get_pushdate_url(build_arg, target_platform)

        elif re.match(r'[0-9A-F]{40}$', self._build, re.IGNORECASE):
            build_arg = self._build.lower()
            task_url = self._get_revision_url(build_arg, target_platform)

        elif self._build == 'latest':
            build_options = '{0}{1}{2}'.format(
                target_platform,
                '-asan' if self._asan else '',
                '-debug' if self._debug else '-opt')

            task_url = '{}gecko.v2.mozilla-{}.latest.firefox.{}'.format(url_base, self._branch, build_options)

        else:
            # try to use build argument directly as a namespace
            if target_platform not in self._build:
                log.warning('Cross-platform fetching is not tested. Please report problems to: %s', BUG_URL)
            task_url = url_base + self._build

        return task_url

    def _get_artifacts(self):
        """
        Retrieve the artifacts json object
        """
        json = _get_url(self._artifacts_url).json()
        return json['artifacts']

    def _get_artifact_base(self):
        """
        Build the artifact basename
        Builds are base.tar.bz2, info is base.json, shell is base.jsshell.zip...
        """
        for artifact in self._artifacts:
            if self.re_target.search(artifact['name']) is not None:
                artifact_base = os.path.splitext(artifact['name'])[0]
                break
        else:
            raise FetcherException('Could not find build info in artifacts')

        return artifact_base

    @property
    def build_id(self):
        return self.build_info['buildid']

    @property
    def changeset(self):
        return self.build_info['moz_source_stamp']

    def artifact_url(self, suffix):
        path = '{}.{}'.format(self._artifact_base, suffix)
        return '{}/{}'.format(self._artifacts_url, path)

    def extract_build(self, path='.'):
        if self._target == 'js':
            self.extract_zip('jsshell.zip', path=os.path.join(path))
        else:
            if sys.platform.startswith('linux'):
                self.extract_tar(path)
            elif sys.platform == 'darwin':
                self.extract_dmg(os.path.join(path))

        if self._tests:
            os.mkdir(os.path.join(path, 'tests'))
            if 'common' in self._tests:
                self.extract_zip('common.tests.zip', path=os.path.join(path, 'tests'))
            if 'reftests' in self._tests:
                self.extract_zip('reftest.tests.zip', path=os.path.join(path, 'tests'))

        if self._debug and not self._asan:
            if self._symbols:
                symbols = 'crashreporter-symbols-full.zip'
            else:
                symbols = 'crashreporter-symbols.zip'
            os.mkdir(os.path.join(path, 'symbols'))
            self.extract_zip(symbols, path=os.path.join(path, 'symbols'))

        # Update directory to work with DOMFuzz
        old_dir = os.getcwd()
        os.chdir(os.path.join(path))
        os.mkdir('dist')
        if sys.platform == 'darwin' and self._target == 'firefox':
            ff_loc = glob.glob('*.app/Contents/MacOS/firefox')
            assert len(ff_loc) == 1
            os.symlink(os.path.join(os.pardir, os.path.dirname(ff_loc[0])), os.path.join('dist', 'bin'))
        else:
            os.symlink(os.pardir, os.path.join('dist', 'bin'))
        os.mkdir('download')
        # Simulates 'touch' to create an empty file
        open(os.path.join('download', 'firefox-.txt'), 'w').close()
        os.chdir(old_dir)

        # Add fuzzmanagerconf
        output = configparser.RawConfigParser()
        output.add_section('Main')
        output.set('Main', 'platform', self.moz_info['processor'].replace('_', '-'))
        output.set('Main', 'product', 'mozilla-' + self._branch)
        output.set('Main', 'product_version', '{:.8}-{:.12}'.format(self.build_info['buildid'],
                                                                    self.build_info['moz_source_stamp']))
        output.set('Main', 'os', self.moz_info['os'])
        output.add_section('Metadata')
        output.set('Metadata', 'pathPrefix', self.moz_info['topsrcdir'])
        output.set('Metadata', 'buildFlags', '')

        fm_name = self._target + '.fuzzmanagerconf'
        with open(os.path.join(path, 'dist', 'bin', fm_name), 'w') as conf_fp:
            output.write(conf_fp)

    def extract_zip(self, suffix, path='.'):
        url = self.artifact_url(suffix)
        log.info('> Downloading and extracting archive: %s ..', url)
        resp = _get_url(self.artifact_url(suffix))
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for info in zf.infolist():
                _extract_file(zf, info, path)

    def extract_tar(self, path='.'):
        """
        Extract builds with .tar.bz2 extension
        Only extracts the top-level directory "firefox"
        """
        url = self.artifact_url('tar.bz2')
        log.info('> Downloading and extracting archive: %s ..', url)
        resp = _get_url(url)
        fd, fn = tempfile.mkstemp(prefix='domfuzz-fetch-', suffix='.tar.bz2')
        os.close(fd)
        try:
            with open(fn, 'wb') as out:
                shutil.copyfileobj(resp.raw, out)

            tar = tarfile.open(fn, mode='r:bz2')
            members = []
            for member in tar.getmembers():
                if member.path.startswith("firefox/"):
                    member.path = member.path[8:]
                    members.append(member)
            tar.extractall(members=members, path=path)
        finally:
            os.unlink(fn)

    def extract_dmg(self, path='.'):
        url = self.artifact_url('dmg')
        log.info('> Downloading and extracting archive: %s ..', url)
        resp = _get_url(url)
        dmg_fd, dmg_fn = tempfile.mkstemp(prefix='domfuzz-fetch-', suffix='.dmg')
        os.close(dmg_fd)
        out_tmp = tempfile.mkdtemp(prefix='domfuzz-fetch-', suffix='.tmp')
        try:
            with open(dmg_fn, 'wb') as out:
                shutil.copyfileobj(resp.raw, out)

            subprocess.check_call(['hdiutil', 'attach', '-quiet', '-mountpoint', out_tmp, dmg_fn])
            try:
                apps = [mt for mt in os.listdir(out_tmp) if mt.endswith('app')]
                assert len(apps) == 1
                shutil.copytree(os.path.join(out_tmp, apps[0]), os.path.join(path, apps[0]), symlinks=True)
            finally:
                subprocess.check_call(['hdiutil', 'detach', '-quiet', out_tmp])
        finally:
            shutil.rmtree(out_tmp)
            os.unlink(dmg_fn)

    def get_auto_name(self):
        if self.moz_info["platform_guess"] in self._build:
            options = self._build.split(self.moz_info["platform_guess"], 1)[1]
        else:
            options = ('-asan' if self._asan else '') + ('-debug' if self._debug else '-opt')

        return '{}-{}{}'.format('m-' + self._branch[0], self.rank, options)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.set_defaults(target='firefox', build='latest', tests=None) # branch default is set after parsing

        target_group = parser.add_argument_group('Target')
        target_group.add_argument('--target', choices=['firefox', 'js'], dest='target',
                                  help='Specify the build target')

        type_group = parser.add_argument_group('Build')
        type_group.add_argument('--build', dest='build', metavar='DATE|REV|NS',
                                help='Specify the build to download, (default: %(default)s)'
                                     ' Accepts values in format YYYY-MM-DD (2017-01-01)'
                                     ' revision (57b37213d81150642f5139764e7044b07b9dccc3)'
                                     ' or TaskCluster namespace (gecko.v2....)')

        branch_group = parser.add_argument_group('Branch')
        branch_args = branch_group.add_mutually_exclusive_group()
        branch_args.add_argument('--inbound', action='store_const', const='inbound', dest='branch',
                                 help='Download from mozilla-inbound')
        branch_args.add_argument('--central', action='store_const', const='central', dest='branch',
                                 help='Download from mozilla-central (default)')
        branch_args.add_argument('--release', action='store_const', const='release', dest='branch',
                                 help='Download from mozilla-release')
        branch_args.add_argument('--beta', action='store_const', const='beta', dest='branch',
                                 help='Download from mozilla-beta')
        branch_args.add_argument('--esr', action='store_const', const='esr52', dest='branch',
                                 help='Download from mozilla-esr52')

        build_group = parser.add_argument_group('Build Arguments')
        build_group.add_argument('-d', '--debug', action='store_true',
                                 help='Get debug builds w/ symbols (default=optimized).')
        build_group.add_argument('-a', '--asan', action='store_true',
                                 help='Download AddressSanitizer builds.')

        test_group = parser.add_argument_group('Test Arguments')
        tests = ['common', 'reftests']
        test_group.add_argument('--tests', nargs='+', metavar='', choices=tests,
                                help='Download tests associated with this build. Acceptable values are: ' + str(tests))
        test_group.add_argument('--full-symbols', dest='symbols', action='store_true',
                                help='Download the full crashreport-symbols.zip archive.')

        misc_group = parser.add_argument_group('Misc. Arguments')
        misc_group.add_argument('-n', '--name',
                                help='Specify a name (default=auto)')
        misc_group.add_argument('-o', '--out', default=os.getcwd(),
                                help='Specify output directory (default=.)')

        args = parser.parse_args()

        if re.match(r'(\d{4}-\d{2}-\d{2}|[0-9A-Fa-f]{40}|latest)$', args.build) is None:
            # this is a custom build
            # ensure conflicting options are not set
            if args.branch is not None:
                parser.error('Cannot specify --build namespace and branch argument: {}'.format(args.branch))
            if args.debug:
                parser.error('Cannot specify --build namespace and --debug')
            if args.asan:
                parser.error('Cannot specify --build namespace and --asan')

        # do this default manually so we can error if combined with --build namespace
        #parser.set_defaults(branch='central')
        elif args.branch is None:
            args.branch = 'central'

        return args

    @classmethod
    def main(cls):
        log_level = logging.INFO
        log_fmt = '[%(asctime)s] %(message)s'
        if bool(os.getenv('DEBUG')):
            log_level = logging.DEBUG
            log_fmt = '%(levelname).1s %(name)s [%(asctime)s] %(message)s'
        logging.basicConfig(format=log_fmt, datefmt='%Y-%m-%d %H:%M:%S', level=log_level)
        logging.getLogger('requests').setLevel(logging.WARNING)

        args = cls.parse_args()
        obj = cls(args.target, args.branch, args.build, args.asan, args.debug, args.tests, args.symbols)

        if args.name is None:
            args.name = obj.get_auto_name()

        final_dir = os.path.normpath(os.path.abspath(os.path.join(args.out, args.name)))
        if os.path.exists(final_dir):
            log.warning('Folder exists: %s .. exiting', final_dir)
            exit(1)

        log.info('Identified task: %s', obj.task_url)
        log.info('> Task ID: %s', obj.task_id)
        log.info('> Rank: %s', obj.rank)
        log.info('> Changeset: %s', obj.changeset)
        log.info('> Build ID: %s', obj.build_id)

        out_tmp = tempfile.mkdtemp(prefix='domfuzz-fetch-', suffix='.tmp')

        try:
            obj.extract_build(out_tmp)
            shutil.move(os.path.join(out_tmp), final_dir)
        finally:
            if os.path.isdir(out_tmp):
                shutil.rmtree(out_tmp)


if __name__ == '__main__':
    if sys.platform not in {'linux', 'linux2', 'darwin'}:
        log.error('Unknown platform: %s', sys.platform)
        exit(1)

    Fetcher.main()
