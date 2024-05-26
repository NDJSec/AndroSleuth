#!/usr/bin/env python
import os
import sys
import configparser
from setuptools import setup
from setuptools import find_packages

if sys.version_info[0] < 3:
    raise Exception(
        'You are tying to install AndroSleuth on Python version {}.\n'
        'Please install AndroSleuth in Python 3 instead.'.format(
            platform.python_version()
        )
    )

config = configparser.ConfigParser()

current_directory = os.path.dirname(os.path.abspath(__file__))
config_file_path = os.path.join(current_directory, 'andro_sleuth_development/setup.cfg')
requirements_file_path = os.path.join(current_directory, 'andro_sleuth_development/requirements.txt')

config.read(config_file_path)

VERSION = config['androsleuth']['version']
AUTHOR = config['androsleuth']['author']
AUTHOR_EMAIL = config['androsleuth']['email']
URL = config['androsleuth']['url']

REQUIREMENTS = []

with open(requirements_file_path) as requirements:
    for requirement in requirements.readlines():
        REQUIREMENTS.append(requirement)


setup(
    name='andro_sleuth',
    version=VERSION,
    url=URL,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    packages=find_packages(),
    include_package_data=True,
    install_requires=REQUIREMENTS,
    entry_points={"console_scripts": ["AndroSleuth=andro_sleuth_core.main:main"]}
)