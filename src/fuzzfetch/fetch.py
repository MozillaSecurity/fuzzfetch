# coding=utf-8
"""Core fuzzfetch implementation"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import collections
import glob
import io
import itertools
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime
from pytz import timezone

import configparser  # pylint: disable=wrong-import-order
import requests

__all__ = ("Fetcher", "FetcherException", "BuildFlags")


log = logging.getLogger('fuzzfetch')  # pylint: disable=invalid-name


BUG_URL = 'https://github.com/MozillaSecurity/fuzzfetch/issues/'
HTTP_SESSION = requests.Session()


class FetcherException(Exception):
    """Exception raised for any Fetcher errors"""


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


def _get_url(url):
    """Retrieve requested URL"""
    try:
        data = HTTP_SESSION.get(url, stream=True)
        data.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise FetcherException(exc)

    return data


def _extract_file(zip_fp, info, path):
    """Extract files while explicitly setting the proper permissions"""
    zip_fp.extract(info.filename, path=path)
    out_path = os.path.join(path, info.filename)

    perm = info.external_attr >> 16
    perm |= stat.S_IREAD  # make sure we're not accidentally setting this to 0
    os.chmod(out_path, perm)


def _create_utc_datetime(datetime_string):
    """Convert build_string to time-zone aware datetime object"""
    dt_obj = datetime.strptime(datetime_string, '%Y%m%d%H%M%S')
    return timezone('UTC').localize(dt_obj)


class BuildFlags(collections.namedtuple('BuildFlagsBase', ('asan', 'debug', 'fuzzing', 'coverage'))):
    """Class for storing TaskCluster build flags"""

    def build_string(self):
        """
        Taskcluster denotes builds in one of two formats - i.e. linux64-asan or linux64-asan-opt
        The latter is generated. If it fails, the caller should try the former.
        """
        return (('-fuzzing' if self.fuzzing else '') +
                ('-asan' if self.asan else '') +
                ('-ccov' if self.coverage else '') +
                ('-debug' if self.debug else '-opt'))


class BuildTask(object):
    """Class for storing TaskCluster build information"""
    URL_BASE = 'https://index.taskcluster.net/v1/'
    RE_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    RE_REV = re.compile(r'^[0-9A-F]{40}$', re.IGNORECASE)

    def __init__(self, build, branch, flags, arch_32=False, _blank=False):
        """
        Retrieve the task JSON object
        Requires first generating the task URL based on the specified build type and platform
        """
        if _blank:
            self.url = None
            self._data = {}
            return
        for obj in self.iterall(build, branch, flags, arch_32):
            self.url = obj.url
            self._data = obj._data  # pylint: disable=protected-access
            break
        else:
            raise FetcherException('Unable to find usable archive for %s' % self._debug_str(build))

    @classmethod
    def _debug_str(cls, build):
        if cls.RE_DATE.match(build):
            return 'pushdate ' + build
        elif cls.RE_REV.match(build):
            return 'revision ' + build
        return build

    @classmethod
    def iterall(cls, build, branch, flags, arch_32=False):
        """Generator for all possible BuildTasks with these parameters"""
        # Prepare build type
        supported_platforms = {'Darwin': {'x86_64': 'macosx64'},
                               'Linux': {'x86_64': 'linux64', 'i686': 'linux'},
                               'Windows': {'AMD64': 'win64'}}

        if arch_32:
            if platform.system() == 'Windows':
                target_platform = 'win32'
            elif platform.system() == 'Linux':
                target_platform = 'linux'
        else:
            target_platform = supported_platforms[platform.system()][platform.machine()]

        is_namespace = False
        if cls.RE_DATE.match(build):
            task_urls = map(''.join,
                            itertools.product(cls._pushdate_urls(build.replace('-', '.'), branch, target_platform),
                                              (flags.build_string(),)))

        elif cls.RE_REV.match(build):
            task_urls = (cls._revision_url(build.lower(), branch, target_platform) + flags.build_string(),)

        elif build == 'latest':
            namespace = 'gecko.v2.mozilla-' + branch + '.latest'
            task_urls = (cls.URL_BASE + '/task/' + namespace + '.firefox.' + target_platform + flags.build_string(),)

        else:
            # try to use build argument directly as a namespace
            if target_platform not in build:
                log.warning('Cross-platform fetching is not tested. Please report problems to: %s', BUG_URL)
            task_urls = (cls.URL_BASE + '/task/' + build,)
            is_namespace = True

        for (url, try_wo_opt) in itertools.product(task_urls, (False, True)):

            if try_wo_opt:
                if '-opt' not in url or is_namespace:
                    continue
                url = url.replace('-opt', '')

            try:
                data = HTTP_SESSION.get(url)
                data.raise_for_status()
            except requests.exceptions.RequestException:
                continue

            obj = cls(None, None, None, _blank=True)
            obj.url = url
            obj._data = data.json()  # pylint: disable=protected-access

            log.debug('Found archive for %s', cls._debug_str(build))
            yield obj

    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))

    @classmethod
    def _pushdate_urls(cls, pushdate, branch, target_platform):
        """Multiple entries exist per push date. Iterate over all until a working entry is found"""
        url_base = cls.URL_BASE + '/namespaces/gecko.v2.mozilla-' + branch + '.pushdate.' + pushdate

        try:
            base = HTTP_SESSION.post(url_base, json={})
            base.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FetcherException(exc)

        json = base.json()
        for namespace in sorted(json['namespaces'], key=lambda x: x['name']):
            yield cls.URL_BASE + '/task/' + namespace['namespace'] + '.firefox.' + target_platform

    @classmethod
    def _revision_url(cls, rev, branch, target_platform):
        """Retrieve the URL for revision based builds"""
        namespace = 'gecko.v2.mozilla-' + branch + '.revision.' + rev
        return cls.URL_BASE + '/task/' + namespace + '.firefox.' + target_platform


class Fetcher(object):
    """Fetcher fetches build artifacts from TaskCluster and unpacks them"""
    TARGET_CHOICES = {'js', 'firefox'}
    TEST_CHOICES = {'common', 'reftests', 'gtest'}
    re_target = re.compile(r'(\.linux-(x86_64|i686)(-asan)?|target|mac(64)?|win(32|64))\.json$')

    def __init__(self, target, branch, build, flags, arch_32=False):
        """
        @type target: string
        @param target: the download target, eg. 'js', 'firefox'

        @type branch: string
        @param branch: a valid gecko branch, eg. 'central', 'inbound', 'beta', 'release', 'esr52', etc.

        @type build: string
        @param build: build identifier. acceptable identifers are: TaskCluster namespace, hg changeset, date, 'latest'

        @type flags: BuildFlags or sequence of booleans
        @param flags: ('asan', 'debug', 'fuzzing', 'coverage'), each a bool, not all combinations exist in TaskCluster

        @type arch_32: boolean
        @param arch_32: force 32-bit download on 64-bit platform
        """
        if target not in self.TARGET_CHOICES:
            raise FetcherException("'%s' is not a supported target" % target)

        self._memo = {'_target': target}
        "memorized values for @properties"
        self._branch = branch
        self._flags = BuildFlags(*flags)

        if isinstance(build, BuildTask):
            self._task = build

        else:
            self._task = BuildTask(build, branch, self._flags, arch_32)

            now = datetime.now(timezone('UTC'))
            if build == 'latest' and (now - self.build_datetime).total_seconds() > 86400:
                log.warning('Latest available build is older than 1 day: %s', self.build_id)

            # if the build string contains the platform, assume it is a TaskCluster namespace
            if self.moz_info["platform_guess"] in build:
                # try to set args to match the namespace given
                if self._branch is None:
                    branch = re.search(r'\.mozilla-(?P<branch>[a-z]+[0-9]*)\.', build)
                    self._branch = branch.group('branch') if branch is not None else '?'
                asan, debug, fuzzing, coverage = self._flags
                if not debug:
                    debug = '-debug' in build or '-dbg' in build
                if not asan:
                    asan = '-asan' in build
                if not fuzzing:
                    fuzzing = '-fuzzing' in build
                if not coverage:
                    coverage = '-coverage' in build
                self._flags = BuildFlags(asan, debug, fuzzing, coverage)

                # '?' is special case used for unknown build types
                if self._branch != '?' and self._branch not in build:
                    raise FetcherException("'build' and 'branch' arguments do not match. "
                                           "(build=%s, branch=%s)" % (build, self._branch))
                if self._flags.asan and '-asan' not in build:
                    raise FetcherException("'build' is not an asan build, but asan=True given "
                                           "(build=%s)" % build)
                if self._flags.debug and not ('-dbg' in build or '-debug' in build):
                    raise FetcherException("'build' is not a debug build, but debug=True given "
                                           "(build=%s)" % build)
                if self._flags.fuzzing and '-fuzzing' not in build:
                    raise FetcherException("'build' is not a fuzzing build, but fuzzing=True given "
                                           "(build=%s)" % build)
                if self._flags.coverage and '-ccov' not in build:
                    raise FetcherException("'build' is not a coverage build, but coverage=True given "
                                           "(build=%s)" % build)

        # build the automatic name
        if not isinstance(build, BuildTask) and self.moz_info["platform_guess"] in build:
            options = build.split(self.moz_info["platform_guess"], 1)[1]
        else:
            options = self._flags.build_string()
        self._auto_name = 'm-%s-%s%s' % (self._branch[0], self.build_id, options)

    @classmethod
    def iterall(cls, target, branch, build, flags, arch_32=False):
        """Return an iterable for all available builds matching a particular build type"""
        flags = BuildFlags(*flags)
        for task in BuildTask.iterall(build, branch, flags, arch_32):
            yield cls(target, branch, task, flags, arch_32)

    @property
    def _artifacts(self):
        """Retrieve the artifacts json object"""
        if '_artifacts' not in self._memo:
            json = _get_url(self._artifacts_url).json()
            self._memo['_artifacts'] = json['artifacts']
        return self._memo['_artifacts']

    @property
    def _artifact_base(self):
        """
        Build the artifact basename
        Builds are base.tar.bz2, info is base.json, shell is base.jsshell.zip...
        """
        if '_artifact_base' not in self._memo:
            for artifact in self._artifacts:
                if self.re_target.search(artifact['name']) is not None:
                    artifact_base = os.path.splitext(artifact['name'])[0]
                    break
            else:
                raise FetcherException('Could not find build info in artifacts')
            self._memo['_artifact_base'] = artifact_base
        return self._memo['_artifact_base']

    @property
    def _artifacts_url(self):
        """Build the artifacts url"""
        return 'https://queue.taskcluster.net/v1/task/%s/artifacts' % self.task_id

    @property
    def build_id(self):
        """Return the build's id (date stamp)"""
        return self.build_info['buildid']

    @property
    def build_datetime(self):
        """Return a datetime representation of the build's id"""
        return _create_utc_datetime(self.build_id)

    @property
    def build_info(self):
        """Return the build's info"""
        if 'build_info' not in self._memo:
            self._memo['build_info'] = _get_url(self.artifact_url('json')).json()
        return self._memo['build_info']

    @property
    def changeset(self):
        """Return the build's revision"""
        return self.build_info['moz_source_stamp']

    @property
    def moz_info(self):
        """Return the build's mozinfo"""
        if 'moz_info' not in self._memo:
            self._memo['moz_info'] = _get_url(self.artifact_url('mozinfo.json')).json()
        return self._memo['moz_info']

    @property
    def rank(self):
        """Return the build's rank"""
        return self._task.rank

    @property
    def _target(self):
        """Return the target type"""
        if '_target' not in self._memo:
            raise FetcherException('_target not set')
        return self._memo['_target']

    @property
    def task_id(self):
        """Return the build's TaskCluster ID"""
        return self._task.taskId

    @property
    def task_url(self):
        """Return the TaskCluster base url"""
        return self._task.url

    def artifact_url(self, suffix):
        """
        Get the Taskcluster artifact url

        @type suffix:
        @param suffix:
        """
        return '%s/%s.%s' % (self._artifacts_url, self._artifact_base, suffix)

    def get_auto_name(self):
        """Get the automatic directory name"""
        return self._auto_name

    def extract_build(self, path='.', tests=None, full_symbols=False):
        """
        Download and extract the build and requested extra artifacts

        @type path:
        @param path:

        @type tests:
        @param tests:

        @type full_symbols:
        @param full_symbols:
        """
        if self._target == 'js':
            self.extract_zip('jsshell.zip', path=os.path.join(path))
        else:
            if platform.system() == 'Linux':
                self.extract_tar(path)
            elif platform.system() == 'Darwin':
                self.extract_dmg(path)
            elif platform.system() == 'Windows':
                self.extract_zip('zip', path)
                # windows builds are extracted under 'firefox/'
                # move everything under firefox/ up a level to the destination path
                firefox = os.path.join(path, 'firefox')
                for root, dirs, files in os.walk(firefox):
                    newroot = root.replace(firefox, path)
                    for dirname in dirs:
                        os.mkdir(os.path.join(newroot, dirname))
                    for filename in files:
                        os.rename(os.path.join(root, filename), os.path.join(newroot, filename))
                shutil.rmtree(firefox, onerror=onerror)
            else:
                raise FetcherException("'%s' is not a supported platform" % platform.system())

        if tests:
            # validate tests
            tests = set(tests or [])
            if not tests.issubset(self.TEST_CHOICES):
                invalid_test = tuple(tests - self.TEST_CHOICES)[0]
                raise FetcherException("'%s' is not a supported test type" % invalid_test)

            os.mkdir(os.path.join(path, 'tests'))
            if 'common' in tests:
                self.extract_zip('common.tests.zip', path=os.path.join(path, 'tests'))
            if 'reftests' in tests:
                self.extract_zip('reftest.tests.zip', path=os.path.join(path, 'tests'))
            if 'gtest' in tests:
                self.extract_zip('gtest.tests.zip', path=path)
                libxul = 'libxul.dll' if platform.system() == "Windows" else 'libxul.so'
                os.rename(os.path.join(path, 'gtest', 'gtest_bin', 'gtest', libxul),
                          os.path.join(path, 'gtest', libxul))
                shutil.copy(os.path.join(path, 'gtest', 'dependentlibs.list.gtest'),
                            os.path.join(path, 'dependentlibs.list.gtest'))
        if self._flags.coverage:
            self.extract_zip('code-coverage-gcno.zip', path=path)

        if not (self._flags.asan or self._flags.coverage):
            if full_symbols:
                symbols = 'crashreporter-symbols-full.zip'
            else:
                symbols = 'crashreporter-symbols.zip'
            os.mkdir(os.path.join(path, 'symbols'))
            self.extract_zip(symbols, path=os.path.join(path, 'symbols'))

        self._layout_for_domfuzz(path)
        self._write_fuzzmanagerconf(path)

    def _layout_for_domfuzz(self, path):
        """
        Update directory to work with DOMFuzz

        @type path: str
        @param path: A string representation of the fuzzmanger config path
        """
        old_dir = os.getcwd()
        os.chdir(os.path.join(path))
        try:
            os.mkdir('dist')
            if platform.system() == 'Darwin' and self._target == 'firefox':
                ff_loc = glob.glob('*.app/Contents/MacOS/firefox')
                assert len(ff_loc) == 1
                os.symlink(os.path.join(os.pardir, os.path.dirname(ff_loc[0])),  # pylint: disable=no-member
                           os.path.join('dist', 'bin'))
            elif platform.system() == 'Linux':
                os.symlink(os.pardir, os.path.join('dist', 'bin'))  # pylint: disable=no-member
            elif platform.system() == 'Windows':
                os.mkdir(os.path.join('dist', 'bin'))
                # recursive copy of the contents of the original only
                entries = os.listdir('.')
                while entries:
                    entry = entries.pop()
                    if os.path.isdir(entry):
                        if entry not in {'dist', 'symbols', 'tests', 'gtest'}:
                            os.mkdir(os.path.join('dist', 'bin', entry))
                            entries.extend(os.path.join(entry, sub) for sub in os.listdir(entry))
                    else:
                        shutil.copy(entry, os.path.join('dist', 'bin', entry))
        finally:
            os.chdir(old_dir)

    def _write_fuzzmanagerconf(self, path):
        """
        Write fuzzmanager config file for selected build

        @type path: basestring
        @param path: A string representation of the fuzzmanger config path
        """
        output = configparser.RawConfigParser()
        output.add_section('Main')
        output.set('Main', 'platform', self.moz_info['processor'].replace('_', '-'))
        output.set('Main', 'product', 'mozilla-' + self._branch)
        output.set('Main', 'product_version', '%.8s-%.12s' % (self.build_id, self.changeset))
        output.set('Main', 'os', self.moz_info['os'])
        output.add_section('Metadata')
        output.set('Metadata', 'pathPrefix', self.moz_info['topsrcdir'])
        output.set('Metadata', 'buildFlags', '')

        if platform.system() == "Windows":
            fm_name = self._target + '.exe.fuzzmanagerconf'
        else:
            fm_name = self._target + '.fuzzmanagerconf'
        with open(os.path.join(path, 'dist', 'bin', fm_name), 'w') as conf_fp:
            output.write(conf_fp)
        if platform.system() == 'Windows':
            shutil.copy(os.path.join(path, 'dist', 'bin', fm_name), os.path.join(path, fm_name))

    def extract_zip(self, suffix, path='.'):
        """
        Download and extract a zip artifact

        @type suffix:
        @param suffix:

        @type path:
        @param path:
        """
        url = self.artifact_url(suffix)
        log.info('> Downloading and extracting archive: %s ..', url)
        resp = _get_url(self.artifact_url(suffix))
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zip_fp:
            for info in zip_fp.infolist():
                _extract_file(zip_fp, info, path)

    def extract_tar(self, path='.'):
        """
        Extract builds with .tar.bz2 extension
        Only extracts the top-level directory "firefox"

        @type path:
        @param path:
        """
        url = self.artifact_url('tar.bz2')
        log.info('> Downloading and extracting archive: %s ..', url)
        resp = _get_url(url)
        tar_fd, tar_fn = tempfile.mkstemp(prefix='domfuzz-fetch-', suffix='.tar.bz2')
        os.close(tar_fd)
        try:
            with open(tar_fn, 'wb') as out:
                shutil.copyfileobj(resp.raw, out)

            tar = tarfile.open(tar_fn, mode='r:bz2')
            members = []
            for member in tar.getmembers():
                if member.path.startswith("firefox/"):
                    member.path = member.path[8:]
                    members.append(member)
            tar.extractall(members=members, path=path)
        finally:
            os.unlink(tar_fn)

    def extract_dmg(self, path='.'):
        """
        Extract builds with .dmg extension

        Will only work if `hdiutil` is available.

        @type path:
        @param path:
        """
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
            shutil.rmtree(out_tmp, onerror=onerror)
            os.unlink(dmg_fn)

    @classmethod
    def from_args(cls, args=None, skip_dir_check=False):
        """
        Construct a Fetcher from given command line arguments.

        @type args: list(str)
        @param args: Command line arguments (optional). Default is to use args from sys.argv

        @type skip_dir_check: bool
        @param skip_dir_check: Boolean identifying whether to check for existing build directory

        @rtype: tuple(Fetcher, output path)
        @return: Returns a Fetcher object and keyword arguments for extract_build.
        """
        parser = argparse.ArgumentParser()
        parser.set_defaults(target='firefox', build='latest', tests=None)  # branch default is set after parsing

        target_group = parser.add_argument_group('Target')
        target_group.add_argument('--target', choices=cls.TARGET_CHOICES,
                                  help=('Specify the build target. Acceptable values are: ' +
                                        ', '.join(cls.TARGET_CHOICES)))
        target_group.add_argument('--32', dest='arch_32', action='store_true',
                                  help='Download 32 bit version of browser on 64 bit system.')

        type_group = parser.add_argument_group('Build')
        type_group.add_argument('--build', metavar='DATE|REV|NS',
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
        build_group.add_argument('--fuzzing', action='store_true',
                                 help='Download --enable-fuzzing builds.')
        build_group.add_argument('--coverage', action='store_true',
                                 help='Download --coverage builds. This also pulls down the *.gcno files')

        test_group = parser.add_argument_group('Test Arguments')
        test_group.add_argument('--tests', nargs='+', metavar='', choices=cls.TEST_CHOICES,
                                help=('Download tests associated with this build. Acceptable values are: ' +
                                      ', '.join(cls.TEST_CHOICES)))
        test_group.add_argument('--full-symbols', action='store_true',
                                help='Download the full crashreport-symbols.zip archive.')

        misc_group = parser.add_argument_group('Misc. Arguments')
        misc_group.add_argument('-n', '--name',
                                help='Specify a name (default=auto)')
        misc_group.add_argument('-o', '--out', default=os.getcwd(),
                                help='Specify output directory (default=.)')

        args = parser.parse_args(args=args)

        if re.match(r'(\d{4}-\d{2}-\d{2}|[0-9A-Fa-f]{40}|latest)$', args.build) is None:
            # this is a custom build
            # ensure conflicting options are not set
            if args.branch is not None:
                parser.error('Cannot specify --build namespace and branch argument: %s' % args.branch)
            if args.debug:
                parser.error('Cannot specify --build namespace and --debug')
            if args.asan:
                parser.error('Cannot specify --build namespace and --asan')
            if args.fuzzing:
                parser.error('Cannot specify --build namespace and --fuzzing')
            if args.coverage:
                parser.error('Cannot specify --build namespace and --coverage')

        # do this default manually so we can error if combined with --build namespace
        # parser.set_defaults(branch='central')
        elif args.branch is None:
            args.branch = 'central'

        flags = BuildFlags(args.asan, args.debug, args.fuzzing, args.coverage)
        obj = cls(args.target, args.branch, args.build, flags, args.arch_32)

        if args.name is None:
            args.name = obj.get_auto_name()

        final_dir = os.path.realpath(os.path.join(args.out, args.name))
        if not skip_dir_check and os.path.exists(final_dir):
            parser.error('Folder exists: %s .. exiting' % final_dir)

        extract_options = {
            'out': final_dir,
            'full_symbols': args.full_symbols,
            'tests': args.tests
        }

        return obj, extract_options

    @classmethod
    def main(cls):
        """
        fuzzfetch main entry point

        Run with --help for usage
        """
        log_level = logging.INFO
        log_fmt = '[%(asctime)s] %(message)s'
        if bool(os.getenv('DEBUG')):
            log_level = logging.DEBUG
            log_fmt = '%(levelname).1s %(name)s [%(asctime)s] %(message)s'
        logging.basicConfig(format=log_fmt, datefmt='%Y-%m-%d %H:%M:%S', level=log_level)
        logging.getLogger('requests').setLevel(logging.WARNING)

        obj, extract_args = cls.from_args()

        log.info('Identified task: %s', obj.task_url)
        log.info('> Task ID: %s', obj.task_id)
        log.info('> Rank: %s', obj.rank)
        log.info('> Changeset: %s', obj.changeset)
        log.info('> Build ID: %s', obj.build_id)

        out_tmp = tempfile.mkdtemp(prefix='fuzz-fetch-', suffix='.tmp')

        try:
            obj.extract_build(out_tmp, tests=extract_args['tests'], full_symbols=extract_args['full_symbols'])
            os.makedirs(os.path.join(out_tmp, 'download'))
            with open(os.path.join(out_tmp, 'download', 'firefox-temp.txt'), 'a') as dl_fd:
                dl_fd.write('buildID=' + obj.build_id + os.linesep)

            shutil.move(os.path.join(out_tmp), extract_args['out'])
        finally:
            if os.path.isdir(out_tmp):
                shutil.rmtree(out_tmp, onerror=onerror)
