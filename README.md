[![Python CI](https://github.com/MozillaSecurity/fuzzfetch/actions/workflows/ci.yml/badge.svg)](https://github.com/MozillaSecurity/fuzzfetch/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/MozillaSecurity/fuzzfetch/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/fuzzfetch)
[![Matrix](https://img.shields.io/badge/chat-%23fuzzing-green?logo=matrix)](https://matrix.to/#/#fuzzing:mozilla.org)
[![PyPI](https://img.shields.io/pypi/v/fuzzfetch)](https://pypi.org/project/fuzzfetch)

Fuzzfetch is a python tool for retrieving builds from the [Firefox-CI](https://firefox-ci-tc.services.mozilla.com/) Taskcluster instance.

Overview
--------

Fuzzfetch can be used to retrieve nearly any build type indexed by Firefox-CI.  This includes AddressSanitizer, ThreadSanitizer, Valgrind, debug, and Fuzzing builds for both Firefox and Spidermonkey.

Installation
------------
```
pip install fuzzfetch
```

Usage
-----
Fuzzfetch supports the following arguments:

```
usage: fuzzfetch [-h] [--target [TARGET ...]]
                 [--os {Android,Darwin,Linux,Windows}]
                 [--cpu {AMD64,ARM64,aarch64,arm,arm64,i686,x64,x86,x86_64}]
                 [--sim {arm,arm64}] [--build DATE|REV|NS]
                 [--branch {central,release,beta,esr-stable,esr-next,try,autoland}]
                 [--asan] [--debug] [--tsan] [--fuzzing] [--coverage]
                 [--no-opt] [--valgrind] [--afl] [--fuzzilli] [--nyx]
                 [--searchfox] [-n NAME] [-o OUT] [--dry-run]
                 [--nearest-newer | --nearest-older] [-V]

options:
  -h, --help            show this help message and exit
  -V, --version         print version and exit

Target:
  --target [TARGET ...]
                        Specify the build artifacts to download. Valid
                        options: firefox js common gtest mozharness searchfox
                        (default: firefox)
  --os {Android,Darwin,Linux,Windows}
                        Specify the target system. (default: Linux)
  --cpu {AMD64,ARM64,aarch64,arm,arm64,i686,x64,x86,x86_64}
                        Specify the target CPU. (default: x86_64)
  --sim {arm,arm64}     Specify the simulated architecture

Build:
  --build DATE|REV|NS   Specify the build to download, (default: latest)
                        Accepts values in format YYYY-MM-DD (2017-01-01),
                        BuildID (20170101120101), revision
                        (57b37213d81150642f5139764e7044b07b9dccc3), or
                        TaskCluster namespace (gecko.v2....)

Branch:
  --branch {central,release,beta,esr-stable,esr-next,try,autoland}
                        Specify the branch to download from (default: mozilla-
                        central unless namespace build is supplied)

Build Arguments:
  --asan, -a            Download AddressSanitizer builds
  --debug, -d           Download debug builds
  --tsan, -t            Download ThreadSanitizer builds
  --fuzzing             Download fuzzing builds
  --coverage            Download coverage builds
  --no-opt              Download non-optimized builds
  --valgrind            Download Valgrind builds
  --afl                 Download AFL++ builds
  --fuzzilli            Download JS Fuzzilli builds
  --nyx                 Download Nyx builds
  --searchfox           Download Searchfox data

Misc. Arguments:
  -n NAME, --name NAME  Specify a name (default=auto)
  -o OUT, --out OUT     Specify output directory (default=.)
  --dry-run             Search for build and output metadata only, don't
                        download anything.

Near Arguments:
  If the specified build isn't found, iterate over builds in the specified
  direction

  --nearest-newer       Search from specified build in ascending order
  --nearest-older       Search from the specified build in descending order
```

Simple Build Retrieval
----------------------
To retrieve the latest build from mozilla-central built with `--enable-address-sanitizer` and `--enable-fuzzing`, you can use the following:
```
fuzzfetch -a --fuzzing
```

To retrieve the latest build from mozilla-central built with `--enable-debug`, you can use the following:
```
fuzzfetch --target js -d
```

To retrieve a specific revision from mozilla-central, you can use the following:
```
fuzzfetch --build 08471023c834
```
