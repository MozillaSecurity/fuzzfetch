#!/usr/bin/env python
# coding=utf-8
"""setuptools install script"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from setuptools import setup


if __name__ == "__main__":
    setup(
        # package_dir needed here for 2.7 only.
        # see https://github.com/pypa/setuptools/issues/1136
        package_dir={"": "src"},
        setup_requires=["setuptools_scm"],
        use_scm_version=True,
    )
