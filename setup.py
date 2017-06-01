from setuptools import setup

setup(
    name='fuzzfetch',
    version='0.1',
    packages=['fuzzfetch'],
    package_dir={'fuzzfetch': ''},
    url='https://github.com/MozillaSecurity/fuzzfetch',
    license='',
    author='Jesse Schwartzentruber, Jason Kratzer',
    author_email='',
    description='Downloader for firefox/jsshell builds',
    entry_points={"console_scripts": ["fuzzfetch = fuzzfetch:Fetcher.main"]},
)
