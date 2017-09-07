#!/usr/bin/env python
"setuptools install script"
from setuptools import setup

setup(
    name='fuzzfetch',
    version='0.5.4',
    packages=['fuzzfetch'],
    license='MPL 2.0',
    url='https://github.com/MozillaSecurity/fuzzfetch',
    install_requires=open('requirements.txt').read().strip().splitlines(),
    author='Jesse Schwartzentruber, Jason Kratzer',
    description='Downloader for firefox/jsshell builds',
    entry_points={"console_scripts": ["fuzzfetch = fuzzfetch:Fetcher.main"]},
    package_dir={"": "src"}
)
