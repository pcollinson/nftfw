from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='nftfw',
    version='0.9.14',
    packages=find_packages(),
    include_package_data=True,

    license='MIT',
    description="Nftfw - nftables firewall generator for Debian",
    keywords="firewall nftables symbiosis sympl",
    url='https://github.com/pcollinson/nftfw',
    long_description=long_description,
    long_description_content_type="text/markdown",

    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: System :: Systems Administration',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
    ],
    python_requires='>=3.6',

    entry_points={
        'console_scripts': [
            'nftfw=nftfw.__main__:main',
            'nftfwls=nftfw.nftfwls:main',
            'nftfwedit=nftfw.nftfwedit:main',
            'nftfwadm=nftfw.nftfwadm:main'
        ],
    },

)
