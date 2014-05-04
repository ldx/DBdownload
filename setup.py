#!/usr/bin/env python

'''DBdownload setup.py'''

import os
from setuptools import setup, find_packages

# Utility function to read the README file.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='dbdownload',
    version='0.2',
    description='Simple Dropbox client written in Python',
    keywords="dropbox tools dbdownload",
    long_description=read('README.md'),
    author='Nilvec',
    author_email='ldx@nilvec.com',
    url='http://nilvec.com/',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'License :: OSI Approved :: Apache License, Version 2.0',
        'Natural Language :: English',
        'Topic :: Networking',
    ],
    license='Apache License, Version 2.0',
    install_requires = ['dropbox>=2.0.0','python-dateutil>=2.0'],
    entry_points = {
        'console_scripts': [
            'dbdownload = dbdownload:main',
        ],
    },
)
