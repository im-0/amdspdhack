# SPDX-License-Identifier: AGPL-3.0-or-later
import setuptools


setuptools.setup(
    name='amdspdhack',
    version='0.0.0',
    url='https://github.com/im-0/amdspdhack',
    author='Ivan Mironov',
    author_email='mironov.ivan@gmail.com',
    license='AGPL-3.0-or-later',
    description='Tool for modifying DDR4 SPD inside AMD BIOS images',
    packages=('amdspdhack', ),
    python_requires='~=3.9',
    install_requires=(
        'click',
    ),
    entry_points={
        'console_scripts': [
            'amdspdhack=amdspdhack.main:cli_main',
        ],
    },
)
