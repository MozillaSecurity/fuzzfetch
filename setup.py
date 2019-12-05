#!/usr/bin/env python
# coding=utf-8
"""setuptools install script"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from setuptools import setup


if __name__ == "__main__":
    setup(
        use_scm_version=True,
        setup_requires=['setuptools_scm'],
    )
