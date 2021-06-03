""" Setup the configuration file for the tests

    Using sys/config.ini

    But running using installed module
"""
from pathlib import Path
from shutil import copytree
import pytest
from nftfw import config

def config_init(config_file='sys/config.ini'):
    """ Open config

    give it the test config file
    finalise setup and return
    """

    # safety check
    syspath = Path('sys')
    if not syspath.exists():
        datapath = Path('data')
        if not datapath.exists():
            pytest.fail('Cannot find data directory - run from in the tests directory')
        else:
            copytree(datapath, syspath)

    if not syspath.exists():
        pytest.fail('Cannot find create sys directory')

    # don't catch the AssertError used in the scripts
    # it shouldn't happen here - and if it does the source
    # data needs fixing
    cf = config.Config(dosetup=False)
    cf.set_ini_value_with_section('Locations', 'ini_file', config_file)
    cf.readini()
    cf.setup()

    # insert testing flag
    cf.TESTING = True

    sysvar = cf.get_ini_value_from_section('Locations', 'sysvar')
    if sysvar != 'sys':
        pytest.fail('Incorrect config setup')
    return cf
