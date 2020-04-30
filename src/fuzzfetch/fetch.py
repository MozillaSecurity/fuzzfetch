# coding=utf-8
"""Core fuzzfetch implementation"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=too-many-statements

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
from collections import namedtuple
import glob
import itertools
import logging
import os
import platform as std_platform
import re
import shutil
import tempfile
import time
from datetime import datetime, timedelta
from pytz import timezone

import configparser  # pylint: disable=wrong-import-order
import requests

from .extract import extract_dmg, extract_tar, extract_zip
from .path import rmtree as junction_rmtree, onerror


__all__ = ("BuildFlags", "BuildTask", "Fetcher", "FetcherArgs", "FetcherException", "Platform")


LOG = logging.getLogger('fuzzfetch')


BUG_URL = 'https://github.com/MozillaSecurity/fuzzfetch/issues/'
HTTP_SESSION = requests.Session()


class FetcherException(Exception):
    """Exception raised for any Fetcher errors"""


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


class HgRevision(object):
    """Class representing a Mercurial revision."""

    def __init__(self, revision, branch):
        """Create a Mercurial revision object.

        @type revision: str
        @param revision: revision hash (short or long)

        @type branch: str
        @param branch: branch where revision is located
        """
        if branch is None or branch == '?':
            raise FetcherException("Can't lookup revision date for branch: %r" % (branch,))
        if branch in {'autoland', 'inbound'}:
            branch = 'integration/' + branch
        elif branch != 'try':
            branch = 'mozilla-' + branch
        self._data = _get_url('https://hg.mozilla.org/%s/json-rev/%s' % (branch, revision)).json()

    @property
    def pushdate(self):
        """Get datetime object representing pushdate of the revision."""
        push_date = datetime.fromtimestamp(self._data['pushdate'][0])
        # For some reason this timestamp is always EST despite saying it has an UTC offset of 0.
        return timezone('EST').localize(push_date)

    @property
    def hash(self):
        """Get the long hash of the revision."""
        return self._data['node']


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


def _create_utc_datetime(datetime_string):
    """Convert build_string to time-zone aware datetime object"""
    dt_obj = datetime.strptime(datetime_string, '%Y%m%d%H%M%S')
    return timezone('UTC').localize(dt_obj)


class BuildFlags(namedtuple('BuildFlagsBase', ('asan', 'tsan', 'debug', 'fuzzing', 'coverage', 'valgrind'))):
    """Class for storing TaskCluster build flags"""

    def build_string(self):
        """
        Taskcluster denotes builds in one of two formats - i.e. linux64-asan or linux64-asan-opt
        The latter is generated. If it fails, the caller should try the former.
        """
        return (('-ccov' if self.coverage else '') +
                ('-fuzzing' if self.fuzzing else '') +
                ('-asan' if self.asan else '') +
                ('-tsan' if self.tsan else '') +
                ('-valgrind' if self.valgrind else '') +
                ('-debug' if self.debug else '-opt'))


class Platform(object):
    """Class representing target OS and CPU, and how it maps to a Gecko mozconfig"""
    SUPPORTED = {
        'Darwin': {'x86_64': 'macosx64'},
        'Linux': {'x86_64': 'linux64', 'x86': 'linux'},
        'Windows': {'x86_64': 'win64', 'arm64': 'win64-aarch64'},
        'Android': {'x86_64': 'android-x86_64', 'x86': 'android-x86',
                    'arm': 'android-api-16', 'arm64': 'android-aarch64'},
    }
    CPU_ALIASES = {
        'ARM64': 'arm64',
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

    @classmethod
    def from_platform_guess(cls, build_string):
        """
        Create a platform object from a namespace build string
        """
        for system, platform in cls.SUPPORTED.items():
            for machine, platform_guess in platform.items():
                if platform_guess in build_string:
                    return cls(system, machine)
        raise FetcherException('Could not extract platform from %s' % (build_string,))

    def auto_name_prefix(self):
        """
        Generate platform prefix for cross-platform downloads.
        """
        # if the platform is not native, auto_name would clobber native downloads.
        # make a prefix to avoid this
        native_system = std_platform.system()
        native_machine = self.CPU_ALIASES.get(std_platform.machine(), std_platform.machine())
        if native_system == self.system and native_machine == self.machine:
            return ''
        platform = {
            'linux': 'linux32',
            'android-api-16': 'android-arm',
            'android-aarch64': 'android-arm64',
        }.get(self.gecko_platform, self.gecko_platform)
        return platform + '-'


class BuildTask(object):
    """Class for storing TaskCluster build information"""
    TASKCLUSTER_APIS = ('https://firefox-ci-tc.services.mozilla.com/api/%s/v1',
                        'https://%s.taskcluster.net/v1',)
    RE_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    RE_REV = re.compile(r'^([0-9A-F]{12}|[0-9A-F]{40})$', re.IGNORECASE)

    def __init__(self, build, branch, flags, platform=None, _blank=False):
        """
        Retrieve the task JSON object
        Requires first generating the task URL based on the specified build type and platform
        """
        if _blank:
            self.url = None
            self.queue_server = None
            self._data = {}
            return
        for obj in self.iterall(build, branch, flags, platform=platform):
            self.url = obj.url
            self.queue_server = obj.queue_server
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
            flag_str = flags.build_string()
            task_template_paths = tuple(
                (template, path + flag_str)
                for (template, path) in cls._pushdate_template_paths(build.replace('-', '.'), branch, target_platform)
            )

        elif cls.RE_REV.match(build):
            # If a short hash was supplied, resolve it to a long one.
            if len(build) == 12:
                build = HgRevision(build, branch).hash
            flag_str = flags.build_string()
            task_paths = tuple(path + flag_str for path in cls._revision_paths(build.lower(), branch, target_platform))
            task_template_paths = itertools.product(cls.TASKCLUSTER_APIS, task_paths)

        elif build == 'latest':
            if branch in {'autoland', 'try'}:
                namespace = 'gecko.v2.' + branch + '.latest'
            else:
                namespace = 'gecko.v2.mozilla-' + branch + '.latest'
            product = 'mobile' if 'android' in target_platform else 'firefox'
            task_path = '/task/%s.%s.%s%s' % (namespace, product, target_platform, flags.build_string())
            task_template_paths = ((cls.TASKCLUSTER_APIS[0], task_path),)

        else:
            # try to use build argument directly as a namespace
            task_path = '/task/' + build
            is_namespace = True
            if '.latest' in build:
                task_template_paths = ((cls.TASKCLUSTER_APIS[0], task_path),)
            else:
                task_template_paths = itertools.product(cls.TASKCLUSTER_APIS, (task_path,))

        for (template_path, try_wo_opt) in itertools.product(task_template_paths, (False, True)):

            template, path = template_path

            if try_wo_opt:
                if '-opt' not in path or is_namespace:
                    continue
                path = path.replace('-opt', '')

            try:
                url = (template % ('index',)) + path
                data = HTTP_SESSION.get(url)
                data.raise_for_status()
            except requests.exceptions.RequestException:
                continue

            obj = cls(None, None, None, _blank=True)
            obj.url = url
            obj.queue_server = template % ('queue',)
            obj._data = data.json()  # pylint: disable=protected-access

            LOG.debug('Found archive for %s', cls._debug_str(build))
            yield obj

    def __getattr__(self, name):
        if name in self._data:
            return self._data[name]
        raise AttributeError("'%s' object has no attribute '%s'" % (type(self).__name__, name))

    @classmethod
    def _pushdate_template_paths(cls, pushdate, branch, target_platform):
        """Multiple entries exist per push date. Iterate over all until a working entry is found"""
        if branch not in {'autoland', 'try'}:
            branch = 'mozilla-' + branch
        path = '/namespaces/gecko.v2.' + branch + '.pushdate.' + pushdate
        date_found = False
        last_exc = None

        for template in cls.TASKCLUSTER_APIS:
            index_base = template % ('index',)
            url = index_base + path
            try:
                base = HTTP_SESSION.post(url, json={})
                base.raise_for_status()
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                continue

            date_found = True
            product = 'mobile' if 'android' in target_platform else 'firefox'
            json = base.json()
            for namespace in sorted(json['namespaces'], key=lambda x: x['name']):
                yield (template, '/task/' + namespace['namespace'] + '.' + product + '.' + target_platform)

        if not date_found:
            raise FetcherException(last_exc)

    @classmethod
    def _revision_paths(cls, rev, branch, target_platform):
        """Retrieve the API path for revision based builds"""
        if branch != 'try':
            branch = 'mozilla-' + branch
        namespace = 'gecko.v2.' + branch + '.revision.' + rev
        product = 'mobile' if 'android' in target_platform else 'firefox'
        yield '/task/' + namespace + '.' + product + '.' + target_platform


class FetcherArgs(object):
    """Class for parsing and recording Fetcher arguments"""
    def __init__(self):
        """
        Instantiate a new FetcherArgs instance
        """
        super(FetcherArgs, self).__init__()
        if not hasattr(self, "parser"):
            self.parser = argparse.ArgumentParser(conflict_handler='resolve')

        self.parser.set_defaults(target='firefox', build='latest', tests=None)  # branch default is set after parsing

        target_group = self.parser.add_argument_group('Target')
        target_group.add_argument('--target', choices=sorted(Fetcher.TARGET_CHOICES),
                                  help='Specify the build target. (default: %(default)s)')
        target_group.add_argument('--os', choices=sorted(Platform.SUPPORTED),
                                  help='Specify the target system. (default: ' + std_platform.system() + ')')
        cpu_choices = sorted(set(itertools.chain(itertools.chain.from_iterable(Platform.SUPPORTED.values()),
                                                 Platform.CPU_ALIASES)))
        target_group.add_argument('--cpu', choices=cpu_choices,
                                  help='Specify the target CPU. (default: ' + std_platform.machine() + ')')

        type_group = self.parser.add_argument_group('Build')
        type_group.add_argument('--build', metavar='DATE|REV|NS',
                                help='Specify the build to download, (default: %(default)s)'
                                     ' Accepts values in format YYYY-MM-DD (2017-01-01)'
                                     ' revision (57b37213d81150642f5139764e7044b07b9dccc3)'
                                     ' or TaskCluster namespace (gecko.v2....)')

        branch_group = self.parser.add_argument_group('Branch')
        branch_args = branch_group.add_mutually_exclusive_group()
        branch_args.add_argument('--inbound', action='store_const', const='inbound', dest='branch',
                                 help='Download from mozilla-inbound')
        branch_args.add_argument('--central', action='store_const', const='central', dest='branch',
                                 help='Download from mozilla-central (default)')
        branch_args.add_argument('--release', action='store_const', const='release', dest='branch',
                                 help='Download from mozilla-release')
        branch_args.add_argument('--beta', action='store_const', const='beta', dest='branch',
                                 help='Download from mozilla-beta')
        branch_args.add_argument('--esr-stable', action='store_const', const='esr-stable', dest='branch',
                                 help='Download from esr-stable')
        branch_args.add_argument('--esr-next', action='store_const', const='esr-next', dest='branch',
                                 help='Download from esr-next')
        branch_args.add_argument('--try', action='store_const', const='try', dest='branch',
                                 help='Download from try')
        branch_args.add_argument('--autoland', action='store_const', const='autoland', dest='branch',
                                 help='Download from try')

        build_group = self.parser.add_argument_group('Build Arguments')
        build_group.add_argument('-d', '--debug', action='store_true',
                                 help='Get debug builds w/ symbols (default=optimized).')
        build_group.add_argument('-a', '--asan', action='store_true',
                                 help='Download AddressSanitizer builds.')
        build_group.add_argument('-t', '--tsan', action='store_true',
                                 help='Download ThreadSanitizer builds.')
        build_group.add_argument('--fuzzing', action='store_true',
                                 help='Download --enable-fuzzing builds.')
        build_group.add_argument('--coverage', action='store_true',
                                 help='Download --coverage builds. This also pulls down the *.gcno files')
        build_group.add_argument('--valgrind', action='store_true',
                                 help='Download Valgrind builds.')

        test_group = self.parser.add_argument_group('Test Arguments')
        test_group.add_argument('--tests', nargs='+', metavar='', choices=Fetcher.TEST_CHOICES,
                                help=('Download tests associated with this build. Acceptable values are: ' +
                                      ', '.join(Fetcher.TEST_CHOICES)))
        test_group.add_argument('--full-symbols', action='store_true',
                                help='Download the full crashreport-symbols.zip archive.')

        misc_group = self.parser.add_argument_group('Misc. Arguments')
        misc_group.add_argument('-n', '--name',
                                help='Specify a name (default=auto)')
        misc_group.add_argument('-o', '--out', default=os.getcwd(),
                                help='Specify output directory (default=.)')
        misc_group.add_argument('--dry-run', action='store_true',
                                help="Search for build and output metadata only, don't download anything.")

        near_group = self.parser.add_argument_group('Near Arguments',
                                                    "If the specified build isn't found, iterate over " +
                                                    "builds in the specified direction")
        near_args = near_group.add_mutually_exclusive_group()
        near_args.add_argument('--nearest-newer', action='store_const', const=Fetcher.BUILD_ORDER_ASC, dest='nearest',
                               help="Search from specified build in ascending order")
        near_args.add_argument('--nearest-older', action='store_const', const=Fetcher.BUILD_ORDER_DESC, dest='nearest',
                               help="Search from the specified build in descending order")

    @staticmethod
    def is_build_ns(build_id):
        """
        Check if supplied build_id is a namespace
        :param build_id: Build identifier to check
        """
        return re.match(r'(\d{4}-\d{2}-\d{2}|[0-9A-Fa-f]{12}|[0-9A-Fa-f]{40}|latest)$', build_id) is None

    def sanity_check(self, args):
        """
        Perform parser checks

        @type args: list
        @param args: a list of arguments
        """
        if hasattr(super(FetcherArgs, self), 'sanity_check'):
            super(FetcherArgs, self).sanity_check(args)  # pylint: disable=no-member

        if self.is_build_ns(args.build):
            # this is a custom build
            # ensure conflicting options are not set
            if args.branch is not None:
                self.parser.error('Cannot specify --build namespace and branch argument: %s' % args.branch)
            if args.debug:
                self.parser.error('Cannot specify --build namespace and --debug')
            if args.asan:
                self.parser.error('Cannot specify --build namespace and --asan')
            if args.tsan:
                self.parser.error('Cannot specify --build namespace and --tsan')
            if args.fuzzing:
                self.parser.error('Cannot specify --build namespace and --fuzzing')
            if args.coverage:
                self.parser.error('Cannot specify --build namespace and --coverage')
            if args.valgrind:
                self.parser.error('Cannot specify --build namespace and --valgrind')

    def parse_args(self, argv=None):
        """
        Parse and validate args

        @type argv: list
        @param argv: a list of arguments
        """
        args = self.parser.parse_args(argv)
        self.sanity_check(args)
        return args


class Fetcher(object):
    """Fetcher fetches build artifacts from TaskCluster and unpacks them"""
    TARGET_CHOICES = {'js', 'firefox'}
    TEST_CHOICES = {'common', 'reftests', 'gtest'}
    BUILD_ORDER_ASC = 1
    BUILD_ORDER_DESC = 2
    re_target = re.compile(r'(\.linux-(x86_64|i686)(-asan)?|target|mac(64)?|win(32|64))\.json$')

    def __init__(self, target, branch, build, flags, platform=None, nearest=None):
        """
        @type target: string
        @param target: the download target, eg. 'js', 'firefox'

        @type branch: string
        @param branch: a valid gecko branch, eg. 'central', 'inbound', 'beta', 'release', 'esr52', etc.

        @type build: string
        @param build: build identifier. acceptable identifers are: TaskCluster namespace, hg changeset, date, 'latest'

        @type flags: BuildFlags or sequence of booleans
        @param flags: ('asan', 'debug', 'fuzzing', 'coverage', 'valgrind', 'tsan'),
                      each a bool, not all combinations exist in TaskCluster

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

        if not isinstance(build, BuildTask):
            # If build doesn't match the following, assume it's a namespace
            if not BuildTask.RE_DATE.match(build) and not BuildTask.RE_REV.match(build) and build != 'latest':
                # platform in namespace may not match the current platform
                self._platform = Platform.from_platform_guess(build)

                # If branch wasn't set, try and retrieve it from the build string
                if self._branch is None:
                    branch = re.search(r'\.(try|mozilla-(?P<branch>[a-z]+[0-9]*))\.', build)
                    self._branch = branch.group('branch') if branch is not None else '?'
                    if self._branch is None:
                        self._branch = branch.group(1)

                # '?' is special case used for unknown build types
                if self._branch != '?' and self._branch not in build:
                    raise FetcherException("'build' and 'branch' arguments do not match. "
                                           "(build=%s, branch=%s)" % (build, self._branch))

                # If flags weren't set, try and retrieve it from the build string
                asan, debug, fuzzing, coverage, valgrind, tsan = self._flags
                if not debug:
                    debug = '-debug' in build or '-dbg' in build
                if not asan:
                    asan = '-asan' in build
                if not tsan:
                    tsan = '-tsan' in build
                if not fuzzing:
                    fuzzing = '-fuzzing' in build
                if not coverage:
                    coverage = '-ccov' in build
                if not valgrind:
                    valgrind = '-valgrind' in build

                self._flags = BuildFlags(asan, tsan, debug, fuzzing, coverage, valgrind)

                # Validate flags
                if self._flags.asan and '-asan' not in build:
                    raise FetcherException("'build' is not an asan build, but asan=True given "
                                           "(build=%s)" % build)
                if self._flags.tsan and '-tsan' not in build:
                    raise FetcherException("'build' is not an tsan build, but tsan=True given "
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
                if self._flags.valgrind and '-valgrind' not in build:
                    raise FetcherException("'build' is not a valgrind build, but valgrind=True given "
                                           "(build=%s)" % build)

            # Attempt to fetch the build.  If it fails and nearest is set, try and find the nearest build that matches
            now = datetime.now(timezone('UTC'))

            try:
                self._task = BuildTask(build, branch, self._flags, self._platform)
            except FetcherException:
                if not nearest:
                    raise

                start = None
                asc = nearest == Fetcher.BUILD_ORDER_ASC
                if 'latest' in build:
                    start = now + timedelta(days=1) if asc else now - timedelta(days=1)
                elif BuildTask.RE_DATE.match(build) is not None:
                    date = datetime.strptime(build, '%Y-%m-%d')
                    localized = timezone('UTC').localize(date)
                    start = localized + timedelta(days=1) if asc else localized - timedelta(days=1)
                elif BuildTask.RE_REV.match(build) is not None:
                    start = HgRevision(build, branch).pushdate
                else:
                    # If no match, assume it's a TaskCluster namespace
                    if re.match(r'.*[0-9]{4}\.[0-9]{2}\.[0-9]{2}.*', build) is not None:
                        match = re.search(r'[0-9]{4}\.[0-9]{2}\.[0-9]{2}', build)
                        date = datetime.strptime(match.group(0), '%Y.%m.%d')
                        start = timezone('UTC').localize(date)
                    elif re.match(r'.*revision.*[0-9[a-f]{40}', build):
                        match = re.search(r'[0-9[a-f]{40}', build)
                        start = HgRevision(match.group(0), branch).pushdate

                # If start date is outside the range of the newest/oldest available build, adjust it
                if asc:
                    start = min(max(start, now - timedelta(days=364)), now)
                    end = now
                else:
                    end = now - timedelta(days=364)
                    start = max(min(start, now), end)

                while start <= end if asc else start >= end:
                    try:
                        self._task = BuildTask(start.strftime('%Y-%m-%d'), branch, self._flags, self._platform)
                        break
                    except FetcherException:
                        LOG.warning('Unable to find build for %s', start.strftime('%Y-%m-%d'))
                        start = start + timedelta(days=1) if asc else start - timedelta(days=1)
                else:
                    raise FetcherException('Failed to find build near %s' % build)

            if build == 'latest' and (now - self.datetime).total_seconds() > 86400:
                LOG.warning('Latest available build is older than 1 day: %s', self.id)

        else:
            self._task = build

        # build the automatic name
        if not isinstance(build, BuildTask) and self.moz_info["platform_guess"] in build:
            options = build.split(self.moz_info["platform_guess"], 1)[1]
        else:
            options = self._flags.build_string()
        if self._branch == "try":
            branch = "try"
        else:
            branch = "m-%s" % (self._branch[0],)
        self._auto_name = '%s%s-%s%s' % (self._platform.auto_name_prefix(), branch, self.id, options)

    @staticmethod
    def resolve_esr(branch):
        """Retrieve esr version based on keyword"""
        if branch not in {'esr-stable', 'esr-next'}:
            raise FetcherException('Invalid ESR branch specified: %s' % branch)

        resp = _get_url('https://product-details.mozilla.org/1.0/firefox_versions.json')
        key = 'FIREFOX_ESR' if branch == 'esr-stable' else 'FIREFOX_ESR_NEXT'
        match = re.search(r'^\d+', resp.json()[key])
        if match is None:
            raise FetcherException('Unable to identify ESR version for %s' % branch)

        return 'esr%s' % match.group(0)

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
        return self._task.queue_server + ('/task/%s/artifacts' % (self.task_id,))

    @property
    def id(self):
        """Return the build's id (date stamp)"""
        # pylint: disable=invalid-name
        return self.build_info['buildid']

    @property
    def datetime(self):
        """Return a datetime representation of the build's id"""
        return _create_utc_datetime(self.id)

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
            self.extract_zip('jsshell.zip', path=os.path.join(path, 'dist', 'bin'))
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

        if not self._flags.asan and not self._flags.tsan and not self._flags.valgrind:
            if full_symbols:
                symbols = 'crashreporter-symbols-full.zip'
            else:
                symbols = 'crashreporter-symbols.zip'
            os.mkdir(os.path.join(path, 'symbols'))
            self.extract_zip(symbols, path=os.path.join(path, 'symbols'))

        self._write_fuzzmanagerconf(path)

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
        output.set('Main', 'product_version', '%.8s-%.12s' % (self.id, self.changeset))
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
        output.set('Metadata', 'buildType', self._flags.build_string().lstrip('-'))

        if self._platform.system == "Windows":
            fm_name = self._target + '.exe.fuzzmanagerconf'
        elif self._platform.system == "Android":
            fm_name = 'target.apk.fuzzmanagerconf'
        elif self._platform.system == 'Darwin' and self._target == 'firefox':
            ff_loc = glob.glob('%s/*.app/Contents/MacOS/firefox' % (path,))
            assert len(ff_loc) == 1
            fm_name = self._target + '.fuzzmanagerconf'
            path = os.path.dirname(ff_loc[0])
        elif self._platform.system in {'Darwin', 'Linux'}:
            fm_name = self._target + '.fuzzmanagerconf'
        else:
            raise FetcherException('Unknown platform/target: %s/%s' % (self._platform.system, self._target))
        if self._target == 'js':
            conf_path = os.path.join(path, 'dist', 'bin', fm_name)
        else:
            conf_path = os.path.join(path, fm_name)
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
            extract_zip(zip_fn, path)
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
            extract_tar(tar_fn, mode, path)
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
            # _artifact_base is like 'path/to/target' .. but geckoview doesn't
            # use target as a basename, so we need to extract just the path
            artifact_path = '/'.join(self._artifact_base.split('/')[:-1])
            url = self._artifacts_url + '/' + artifact_path + '/geckoview-androidTest.apk'
            _download_url(url, apk_fn)
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
        try:
            _download_url(self.artifact_url('dmg'), dmg_fn)
            if std_platform.system() == 'Darwin':
                LOG.info('.. extracting')
                extract_dmg(dmg_fn, path)
            else:
                LOG.warning('.. can\'t extract target.dmg on %s', std_platform.system())
                shutil.copy(dmg_fn, os.path.join(path, 'target.dmg'))
        finally:
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
        parser = FetcherArgs()
        args = parser.parse_args(args)

        # do this default manually so we can error if combined with --build namespace
        # parser.set_defaults(branch='central')
        if not parser.is_build_ns(args.build) and args.branch is None:
            args.branch = 'central'

        if args.branch.startswith('esr'):
            args.branch = Fetcher.resolve_esr(args.branch)

        flags = BuildFlags(args.asan, args.tsan, args.debug, args.fuzzing, args.coverage, args.valgrind)
        obj = cls(args.target, args.branch, args.build, flags, Platform(args.os, args.cpu), args.nearest)

        if args.name is None:
            args.name = obj.get_auto_name()

        final_dir = os.path.realpath(os.path.join(args.out, args.name))
        if not skip_dir_check and os.path.exists(final_dir):
            parser.parser.error('Folder exists: %s .. exiting' % final_dir)

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
        LOG.info('> Build ID: %s', obj.id)

        if extract_args['dry_run']:
            return

        out = extract_args['out']
        os.mkdir(out)

        try:
            obj.extract_build(out, tests=extract_args['tests'], full_symbols=extract_args['full_symbols'])
            os.makedirs(os.path.join(out, 'download'))
            with open(os.path.join(out, 'download', 'firefox-temp.txt'), 'a') as dl_fd:
                dl_fd.write('buildID=' + obj.id + os.linesep)
        except:  # noqa
            if os.path.isdir(out):
                junction_rmtree(out)
            raise
