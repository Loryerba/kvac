# -*- coding: utf-8 -*-
import kvac
from setuptools import find_packages, setup

setup(
    name='kvac',
    version=kvac.__version__,
    packages=find_packages(exclude=['tests']),
    install_requires=[],
    tests_require=['pytest'],
    license='GNU Affero General Public License v3.0',
    author='',
    author_email='',
    description='',
    long_description='',
    platforms='any',
    classifiers=['Development Status :: 1 - Planning',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: GNU Affero General Public License v3.0',
                 'Natural Language :: English',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 3.3',
                 'Programming Language :: Python :: 3.4',
                 'Programming Language :: Python :: 3.5',
                 'Programming Language :: Python :: 3.6',
                 'Programming Language :: Python :: 3.7',
                 'Programming Language :: Python :: 3.8',
                 'Programming Language :: Python :: 3.9',
                 'Programming Language :: Python :: 3.10',
                 'Programming Language :: Python :: 3.11',
                 'Operating System :: MacOS :: MacOS X',
                 'Operating System :: Microsoft :: Windows',
                 'Operating System :: POSIX :: Linux',
                 'Topic :: Security :: Cryptography',
                 'Topic :: Software Development :: Libraries :: Python Modules']
)
