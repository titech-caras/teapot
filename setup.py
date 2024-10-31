#!/usr/bin/env python
from setuptools import setup, find_packages

REQUIREMENTS = [i.strip() for i in open("requirements.txt").readlines()]

setup(
    name='teapot',
    version='0.0.1',
    python_requires='>=3.8,<=3.10',
    packages=find_packages(),
    platforms='any',
    install_requires=REQUIREMENTS,
    entry_points={
        'console_scripts': ['teapot=teapot.cmdline:main'],
    }
)
