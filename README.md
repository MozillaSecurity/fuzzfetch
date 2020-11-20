[![Task Status](https://community-tc.services.mozilla.com/api/github/v1/repository/MozillaSecurity/fuzzfetch/master/badge.svg)](https://community-tc.services.mozilla.com/api/github/v1/repository/MozillaSecurity/fuzzfetch/master/latest)
[![codecov](https://codecov.io/gh/MozillaSecurity/fuzzfetch/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/fuzzfetch)
[![Matrix](https://img.shields.io/badge/dynamic/json?color=green&label=chat&query=%24.chunk[%3F(%40.canonical_alias%3D%3D%22%23fuzzing%3Amozilla.org%22)].num_joined_members&suffix=%20users&url=https%3A%2F%2Fmozilla.modular.im%2F_matrix%2Fclient%2Fr0%2FpublicRooms&style=flat&logo=matrix)](https://riot.im/app/#/room/#fuzzing:mozilla.org)

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
usage: fuzzfetch [-h] [--target {firefox,js}]
                   [--os {Android,Darwin,Linux,Windows}]
                   [--cpu {AMD64,ARM64,aarch64,arm,arm64,i686,x64,x86,x86_64}]
                   [--build DATE|REV|NS]
                   [--central | --release | --beta | --esr-stable | --esr-next | --try | --autoland]
                   [-d] [-a] [-t] [--fuzzing] [--coverage] [--valgrind]
                   [--gtest] [-n NAME] [-o OUT] [--dry-run]
                   [--nearest-newer | --nearest-older]

optional arguments:
  -h, --help            show this help message and exit

Target:
  --target {firefox,js}
                        Specify the build target. (default: firefox)
  --os {Android,Darwin,Linux,Windows}
                        Specify the target system. (default: Linux)
  --cpu {AMD64,ARM64,aarch64,arm,arm64,i686,x64,x86,x86_64}
                        Specify the target CPU. (default: x86_64)

Build:
  --build DATE|REV|NS   Specify the build to download, (default: latest)
                        Accepts values in format YYYY-MM-DD (2017-01-01)
                        revision (57b37213d81150642f5139764e7044b07b9dccc3) or
                        TaskCluster namespace (gecko.v2....)

Branch:
  --central             Download from mozilla-central (default)
  --release             Download from mozilla-release
  --beta                Download from mozilla-beta
  --esr-stable          Download from esr-stable
  --esr-next            Download from esr-next
  --try                 Download from try
  --autoland            Download from autoland

Build Arguments:
  -d, --debug           Get debug builds w/ symbols (default=optimized).
  -a, --asan            Download AddressSanitizer builds.
  -t, --tsan            Download ThreadSanitizer builds.
  --fuzzing             Download --enable-fuzzing builds.
  --coverage            Download --coverage builds.
  --valgrind            Download Valgrind builds.

Test Arguments:
  --gtest               Download gtests associated with this build

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
