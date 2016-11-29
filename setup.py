#!/usr/bin/python3


from setuptools import setup
from setuptools import Extension


setup(
    name='wayround_i2p_socks',
    version='0.1',
    description='SOCKS5 realisation for Python 3.4',
    author='Alexey Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_i2p_socks',
    packages=[
        'wayround_i2p.socks'
        ],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX',
        ]
    )
