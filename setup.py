#!/usr/bin/env python

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

with open("CHANGELOG.md") as history_file:
    history = history_file.read()

requirements = ["Click>=6.0", "r2pipe"]

setup_requirements = ["pytest-runner"]

test_requirements = ["pytest"]

setup(
    author="Jonathan Wrightsell",
    author_email="jonathan.wrightsell@carvesystems.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    description="gostrings-r2 extracts strings from a Go binary using radare2",
    entry_points={"console_scripts": ["gostringsr2=gostringsr2.cli:main"]},
    install_requires=requirements,
    license="MIT license",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="gostringsr2",
    name="gostringsr2",
    packages=find_packages(include=["gostringsr2"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/carvesystems/gostringsr2",
    version="1.0.0",
    zip_safe=False,
)
