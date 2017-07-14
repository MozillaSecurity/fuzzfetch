from setuptools import setup

if __name__ == '__main__':
    with open('requirements.txt') as f:
        requires = f.read().strip().splitlines()
    setup(
        name='fuzzfetch',
        version='0.4.0',
        packages=['fuzzfetch'],
        package_dir={'fuzzfetch': ''},
        install_requires=requires,
        url='https://github.com/MozillaSecurity/fuzzfetch',
        license='MPL 2.0',
        author='Jesse Schwartzentruber, Jason Kratzer',
        description='Downloader for firefox/jsshell builds',
        entry_points={"console_scripts": ["fuzzfetch = fuzzfetch:Fetcher.main"]},
    )
