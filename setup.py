#!/usr/bin/env python
from setuptools import setup, find_packages

# Requirement lines only: requirements.txt also holds comments and blank lines.
with open("requirements.txt") as requirements:
    REQUIREMENTS = [line.strip() for line in requirements
                    if line.strip() and not line.lstrip().startswith("#")]

setup(
    name='teapot',
    version='0.1.0',
    # llvmlite 0.49 (LLVM 22) needs Python 3.10.
    python_requires='>=3.10',
    packages=find_packages(),
    platforms='any',
    install_requires=REQUIREMENTS,
    entry_points={
        'console_scripts': ['teapot=teapot.cmdline:main'],
    }
)
