# coding=utf-8
"""Core fuzzfetch implementation"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=too-many-statements

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import collections
import glob
import itertools
import logging
import os
import platform as std_platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime
from pytz import timezone

import configparser  # pylint: disable=wrong-import-order
import requests

from . import path as junction_path


__all__ = ("Fetcher", "FetcherException", "BuildFlags")


LOG = logging.getLogger('fuzzfetch')


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


def _si(number):
    """Format a number using base-2 SI prefixes"""
    prefixes = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
    while number > 1024:
        number /= 1024.0
        prefixes.pop(0)
    return '%0.2f%s' % (number, prefixes.pop(0))


def _get_url(url):
    """Retrieve requested URL"""
    try:
        data = HTTP_SESSION.get(url, stream=True)
        data.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise FetcherException(exc)

    return data


def _download_url(url, outfile):
    downloaded = 0
    start_time = report_time = time.time()
    resp = _get_url(url)
    total_size = int(resp.headers['Content-Length'])
    LOG.info('> Downloading: %s (%sB total)', url, _si(total_size))
    with open(outfile, 'wb') as build_zip:
        for chunk in resp.iter_content(1024 * 1024):
            build_zip.write(chunk)
            downloaded += len(chunk)
            now = time.time()
            if (now - report_time) > 30 and downloaded != total_size:
                LOG.info('.. still downloading (%0.1f%%, %sB/s)',
                         100.0 * downloaded / total_size, _si(float(downloaded) / (now - start_time)))
                report_time = now
    LOG.info('.. downloaded (%sB/s)', _si(float(downloaded) / (time.time() - start_time)))


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
        return (('-ccov' if self.coverage else '') +
                ('-fuzzing' if self.fuzzing else '') +
                ('-asan' if self.asan else '') +
                ('-debug' if self.debug else '-opt'))


class Platform(object):
    """Class representing target OS and CPU, and how it maps to a Gecko mozconfig"""
    SUPPORTED = {
        'Darwin': {'x86_64': 'macosx64'},
        'Linux': {'x86_64': 'linux64', 'x86': 'linux'},
        'Windows': {'x86_64': 'win64'},
        'Android': {'x86': 'android-x86', 'arm': 'android-api-16', 'arm64': 'android-aarch64'},
    }
    CPU_ALIASES = {
        'AMD64': 'x86_64',
        'aarch64': 'arm64',
        'i686': 'x86',
        'x64': 'x86_64',
    }

    def __init__(self, system=None, machine=None):
        if system is None:
            system = std_platform.system()
        if machine is None:
            machine = std_platform.machine()
        if system not in self.SUPPORTED:
            raise FetcherException('Unknown system: %s' % (system,))
        fixed_machine = self.CPU_ALIASES.get(machine, machine)
        if fixed_machine not in self.SUPPORTED[system]:
            raise FetcherException('Unknown machine for %s: %s' % (system, machine))
        self.system = system
        self.machine = fixed_machine
        self.gecko_platform = self.SUPPORTED[system][fixed_machine]


class BuildTask(object):
    """Class for storing TaskCluster build information"""
    URL_BASE = 'https://index.taskcluster.net/v1'
    RE_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    RE_REV = re.compile(r'^[0-9A-F]{40}$', re.IGNORECASE)

    def __init__(self, build, branch, flags, platform=None, _blank=False):
        """
        Retrieve the task JSON object
        Requires first generating the task URL based on the specified build type and platform
        """
        if _blank:
            self.url = None
            self._data = {}
            return
        for obj in self.iterall(build, branch, flags, platform=platform):
            self.url = obj.url
            self._data = obj._data  # pylint: disable=protected-access
            break
        else:
            raise FetcherException('Unable to find usable archive for %s' % self._debug_str(build))

    @classmethod
    def _debug_str(cls, build):
        if cls.RE_DATE.match(build):
            return 'pushdate ' + build
        if cls.RE_REV.match(build):
            return 'revision ' + build
        return build

    @classmethod
    def iterall(cls, build, branch, flags, platform=None):
        """Generator for all possible BuildTasks with these parameters"""
        # Prepare build type
        if platform is None:
            platform = Platform()
        target_platform = platform.gecko_platform

        is_namespace = False
        if cls.RE_DATE.match(build):
            task_urls = map(''.join,
                            itertools.product(cls._pushdate_urls(build.replace('-', '.'), branch, target_platform),
                                              (flags.build_string(),)))

        elif cls.RE_REV.match(build):
            task_urls = (cls._revision_url(build.lower(), branch, target_platform) + flags.build_string(),)

        elif build == 'latest':
            namespace = 'gecko.v2.mozilla-' + branch + '.latest'
            product = 'mobile' if 'android' in target_platform else 'firefox'
            task_urls = (cls.URL_BASE + '/task/' + namespace + '.' + product + '.' + target_platform +
                         flags.build_string(),)

        else:
            # try to use build argument directly as a namespace
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

            LOG.debug('Found archive for %s', cls._debug_str(build))
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

        product = 'mobile' if 'android' in target_platform else 'firefox'
        json = base.json()
        for namespace in sorted(json['namespaces'], key=lambda x: x['name']):
            yield cls.URL_BASE + '/task/' + namespace['namespace'] + '.' + product + '.' + target_platform

    @classmethod
    def _revision_url(cls, rev, branch, target_platform):
        """Retrieve the URL for revision based builds"""
        namespace = 'gecko.v2.mozilla-' + branch + '.revision.' + rev
        product = 'mobile' if 'android' in target_platform else 'firefox'
        return cls.URL_BASE + '/task/' + namespace + '.' + product + '.' + target_platform


class Fetcher(object):
    """Fetcher fetches build artifacts from TaskCluster and unpacks them"""
    TARGET_CHOICES = {'js', 'firefox'}
    TEST_CHOICES = {'common', 'reftests', 'gtest'}
    re_target = re.compile(r'(\.linux-(x86_64|i686)(-asan)?|target|mac(64)?|win(32|64))\.json$')

    def __init__(self, target, branch, build, flags, platform=None):
        """
        @type target: string
        @param target: the download target, eg. 'js', 'firefox'

        @type branch: string
        @param branch: a valid gecko branch, eg. 'central', 'inbound', 'beta', 'release', 'esr52', etc.

        @type build: string
        @param build: build identifier. acceptable identifers are: TaskCluster namespace, hg changeset, date, 'latest'

        @type flags: BuildFlags or sequence of booleans
        @param flags: ('asan', 'debug', 'fuzzing', 'coverage'), each a bool, not all combinations exist in TaskCluster

        @type platform: Platform
        @param platform: force platform if different than current system
        """
        if target not in self.TARGET_CHOICES:
            raise FetcherException("'%s' is not a supported target" % target)

        self._memo = {'_target': target}
        "memorized values for @properties"
        self._branch = branch
        self._flags = BuildFlags(*flags)
        self._platform = platform or Platform()

        if isinstance(build, BuildTask):
            self._task = build

        else:
            self._task = BuildTask(build, branch, self._flags, self._platform)

            now = datetime.now(timezone('UTC'))
            if build == 'latest' and (now - self.build_datetime).total_seconds() > 86400:
                LOG.warning('Latest available build is older than 1 day: %s', self.build_id)

            # if the build string contains the platform, assume it is a TaskCluster namespace
            if re.search(self.moz_info["platform_guess"].replace('-', '.*'), build) is not None:
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
                    coverage = '-ccov' in build
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
    def iterall(cls, target, branch, build, flags, platform=None):
        """Return an iterable for all available builds matching a particular build type"""
        flags = BuildFlags(*flags)
        for task in BuildTask.iterall(build, branch, flags, platform):
            yield cls(target, branch, task, flags, platform)

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
            if self._platform.system == 'Linux':
                self.extract_tar('tar.bz2', path)
            elif self._platform.system == 'Darwin':
                self.extract_dmg(path)
            elif self._platform.system == 'Windows':
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
            elif self._platform.system == 'Android':
                self.download_apk(path)
            else:
                raise FetcherException("'%s' is not a supported platform" % self._platform.system)

        if tests:
            # validate tests
            tests = set(tests or [])
            if not tests.issubset(self.TEST_CHOICES):
                invalid_test = tuple(tests - self.TEST_CHOICES)[0]
                raise FetcherException("'%s' is not a supported test type" % invalid_test)

            os.mkdir(os.path.join(path, 'tests'))
            if 'common' in tests:
                try:
                    self.extract_tar('common.tests.tar.gz', path=os.path.join(path, 'tests'))
                except FetcherException:
                    self.extract_zip('common.tests.zip', path=os.path.join(path, 'tests'))
            if 'reftests' in tests:
                try:
                    self.extract_tar('reftest.tests.tar.gz', path=os.path.join(path, 'tests'))
                except FetcherException:
                    self.extract_zip('reftest.tests.zip', path=os.path.join(path, 'tests'))
            if 'gtest' in tests:
                try:
                    self.extract_tar('gtest.tests.tar.gz', path=path)
                except FetcherException:
                    self.extract_zip('gtest.tests.zip', path=path)
                if self._platform.system == 'Windows':
                    libxul = 'xul.dll'
                elif self._platform.system == 'Linux':
                    libxul = 'libxul.so'
                elif self._platform.system == 'Darwin':
                    libxul = 'XUL'
                else:
                    raise FetcherException("'%s' is not a supported platform for gtest" % self._platform.system)
                os.rename(os.path.join(path, 'gtest', 'gtest_bin', 'gtest', libxul),
                          os.path.join(path, 'gtest', libxul))
                shutil.copy(os.path.join(path, 'gtest', 'dependentlibs.list.gtest'),
                            os.path.join(path, 'dependentlibs.list.gtest'))
        if self._flags.coverage:
            self.extract_zip('code-coverage-gcno.zip', path=path)

        if not self._flags.asan:
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
        @param path: A string representation of the fuzzmanager config path
        """
        old_dir = os.getcwd()
        os.chdir(os.path.join(path))
        try:
            os.mkdir('dist')
            link_name = os.path.join('dist', 'bin')
            if self._platform.system == 'Darwin' and self._target == 'firefox':
                ff_loc = glob.glob('*.app/Contents/MacOS/firefox')
                assert len(ff_loc) == 1
                os.symlink(os.path.join(os.pardir, os.path.dirname(ff_loc[0])),  # pylint: disable=no-member
                           link_name)
                os.symlink(os.path.join(os.pardir, os.pardir, os.pardir, 'symbols'),  # pylint: disable=no-member
                           os.path.join(os.path.dirname(ff_loc[0]), 'symbols'))
            elif self._platform.system == 'Linux':
                os.symlink(os.pardir, link_name)  # pylint: disable=no-member
            elif self._platform.system == 'Windows':
                # create a junction point at dist\bin pointing to the firefox.exe path
                junction_path.symlink(os.curdir, link_name)
        finally:
            os.chdir(old_dir)

    def _write_fuzzmanagerconf(self, path):
        """
        Write fuzzmanager config file for selected build

        @type path: basestring
        @param path: A string representation of the fuzzmanager config path
        """
        output = configparser.RawConfigParser()
        output.add_section('Main')
        output.set('Main', 'platform', self.moz_info['processor'].replace('_', '-'))
        output.set('Main', 'product', 'mozilla-' + self._branch)
        output.set('Main', 'product_version', '%.8s-%.12s' % (self.build_id, self.changeset))
        # make sure 'os' match what FM expects
        os_name = self.moz_info['os'].lower()
        if os_name.startswith('android'):
            output.set('Main', 'os', 'android')
        elif os_name.startswith('lin'):
            output.set('Main', 'os', 'linux')
        elif os_name.startswith('mac'):
            output.set('Main', 'os', 'macosx')
        elif os_name.startswith('win'):
            output.set('Main', 'os', 'windows')
        else:
            output.set('Main', 'os', self.moz_info['os'])
        output.add_section('Metadata')
        output.set('Metadata', 'pathPrefix', self.moz_info['topsrcdir'])
        output.set('Metadata', 'buildFlags', self._flags.build_string().lstrip('-'))

        if self._platform.system == "Windows":
            fm_name = self._target + '.exe.fuzzmanagerconf'
            conf_path = os.path.join(path, 'dist', 'bin', fm_name)
        elif self._platform.system == "Android":
            conf_path = os.path.join(path, 'target.apk.fuzzmanagerconf')
        else:
            fm_name = self._target + '.fuzzmanagerconf'
            conf_path = os.path.join(path, 'dist', 'bin', fm_name)
        with open(conf_path, 'w') as conf_fp:
            output.write(conf_fp)

    def extract_zip(self, suffix, path='.'):
        """
        Download and extract a zip artifact

        @type suffix:
        @param suffix:

        @type path:
        @param path:
        """
        zip_fd, zip_fn = tempfile.mkstemp(prefix='fuzzfetch-', suffix='.zip')
        os.close(zip_fd)
        try:
            _download_url(self.artifact_url(suffix), zip_fn)
            LOG.info('.. extracting')
            with zipfile.ZipFile(zip_fn) as zip_fp:
                for info in zip_fp.infolist():
                    _extract_file(zip_fp, info, path)
        finally:
            os.unlink(zip_fn)

    def extract_tar(self, suffix, path='.'):
        """
        Extract builds with .tar.(*) extension
        When unpacking a build archive, only extract the firefox directory

        @type suffix:
        @param suffix:

        @type path:
        @param path:
        """
        mode = suffix.split('.')[-1]
        tar_fd, tar_fn = tempfile.mkstemp(prefix='fuzzfetch-', suffix='.tar.%s' % mode)
        os.close(tar_fd)
        try:
            _download_url(self.artifact_url(suffix), tar_fn)
            LOG.info('.. extracting')
            with tarfile.open(tar_fn, mode='r:%s' % mode) as tar:
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
            os.unlink(tar_fn)

    def download_apk(self, path='.'):
        """
        Download Android .apk

        @type path:
        @param path:
        """
        apk_fd, apk_fn = tempfile.mkstemp(prefix='fuzzfetch-', suffix='.apk')
        os.close(apk_fd)
        try:
            _download_url(self.artifact_url('apk'), apk_fn)
            shutil.copy(apk_fn, os.path.join(path, 'target.apk'))
        finally:
            os.unlink(apk_fn)

    def extract_dmg(self, path='.'):
        """
        Extract builds with .dmg extension

        Will only work if `hdiutil` is available.

        @type path:
        @param path:
        """
        dmg_fd, dmg_fn = tempfile.mkstemp(prefix='fuzzfetch-', suffix='.dmg')
        os.close(dmg_fd)
        out_tmp = tempfile.mkdtemp(prefix='fuzzfetch-', suffix='.tmp')
        try:
            _download_url(self.artifact_url('dmg'), dmg_fn)
            if std_platform.system() == 'Darwin':
                LOG.info('.. extracting')
                subprocess.check_call(['hdiutil', 'attach', '-quiet', '-mountpoint', out_tmp, dmg_fn])
                try:
                    apps = [mt for mt in os.listdir(out_tmp) if mt.endswith('app')]
                    assert len(apps) == 1
                    shutil.copytree(os.path.join(out_tmp, apps[0]), os.path.join(path, apps[0]), symlinks=True)
                finally:
                    subprocess.check_call(['hdiutil', 'detach', '-quiet', out_tmp])
            else:
                LOG.warning('.. can\'t extract target.dmg on %s', std_platform.system())
                shutil.copy(dmg_fn, os.path.join(path, 'target.dmg'))
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
        target_group.add_argument('--target', choices=sorted(cls.TARGET_CHOICES),
                                  help=('Specify the build target. (default: %(default)s)'))
        target_group.add_argument('--os', choices=sorted(Platform.SUPPORTED),
                                  help=('Specify the target system. (default: ' + std_platform.system() + ')'))
        cpu_choices = sorted(set(itertools.chain(itertools.chain.from_iterable(Platform.SUPPORTED.values()),
                                                 Platform.CPU_ALIASES)))
        target_group.add_argument('--cpu', choices=cpu_choices,
                                  help=('Specify the target CPU. (default: ' + std_platform.machine() + ')'))

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
        branch_args.add_argument('--esr52', action='store_const', const='esr52', dest='branch',
                                 help='Download from mozilla-esr52')
        branch_args.add_argument('--esr', action='store_const', const='esr60', dest='branch',
                                 help='Download from mozilla-esr60')

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
        misc_group.add_argument('--dry-run', action='store_true',
                                help="Search for build and output metadata only, don't download anything.")

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
        obj = cls(args.target, args.branch, args.build, flags, Platform(args.os, args.cpu))

        if args.name is None:
            args.name = obj.get_auto_name()

        final_dir = os.path.realpath(os.path.join(args.out, args.name))
        if not skip_dir_check and os.path.exists(final_dir):
            parser.error('Folder exists: %s .. exiting' % final_dir)

        extract_options = {
            'dry_run': args.dry_run,
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

        LOG.info('Identified task: %s', obj.task_url)
        LOG.info('> Task ID: %s', obj.task_id)
        LOG.info('> Rank: %s', obj.rank)
        LOG.info('> Changeset: %s', obj.changeset)
        LOG.info('> Build ID: %s', obj.build_id)

        if extract_args['dry_run']:
            return

        out = extract_args['out']
        os.mkdir(out)

        try:
            obj.extract_build(out, tests=extract_args['tests'], full_symbols=extract_args['full_symbols'])
            os.makedirs(os.path.join(out, 'download'))
            with open(os.path.join(out, 'download', 'firefox-temp.txt'), 'a') as dl_fd:
                dl_fd.write('buildID=' + obj.build_id + os.linesep)
        except:  # noqa
            if os.path.isdir(out):
                junction_path.rmtree(out)
            raise
