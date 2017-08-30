#!/usr/bin/env python
"setuptools install script"
from setuptools import setup


def main():
    "setuptools main"
    with open('requirements.txt') as req_fp:
        requires = req_fp.read().strip().splitlines()
    setup(
        name='fuzzfetch',
        version='0.5.2',
        packages=['fuzzfetch'],
        install_requires=requires,
        url='https://github.com/MozillaSecurity/fuzzfetch',
        license='MPL 2.0',
        author='Jesse Schwartzentruber, Jason Kratzer',
        description='Downloader for firefox/jsshell builds',
        entry_points={"console_scripts": ["fuzzfetch = fuzzfetch:Fetcher.main"]},
        package_dir={"": "src"}
    )


if __name__ == "__main__":
    main()
