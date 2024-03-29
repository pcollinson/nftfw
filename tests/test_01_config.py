""" Pytest config test """

from pathlib import Path
import pytest
from tests.configsetup import config_init
from nftfw.fwdb import FwDb

@pytest.fixture
def cf():         # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    sysvar = _cf.get_ini_value_from_section('Locations', 'sysvar')
    assert sysvar == 'sys'
    if sysvar != 'sys':
        pytest.fail('Incorrect config setup')
    return _cf

@pytest.fixture
def fwdb_handle(cf):
    """ get handle to database """

    # see if the file exists and delete it
    dbfile = cf.varfilepath('firewall')
    assert str(dbfile) == 'sys/firewall.db'
    if dbfile.exists():
        dbfile.unlink()
    # should create the file

    fwdb = FwDb(cf)
    assert dbfile.exists()
    return fwdb


def test_setup(cf):
    """ Check config settings - and make sure
    our test setup has directories
    """

    assert str(cf.nftfw_init) == 'sys/nftfw_init.nft'
    assert str(cf.nftables_conf) == 'sys/nftables.conf'
    sysvar = cf.get_ini_value_from_section('Locations', 'sysvar')
    assert sysvar == 'sys'

    for name, dirname in cf.etc_dir.items():
        path = cf.etcpath(name)
        assert path.exists(), f'{dirname} doesn\'t exist'
    for name, dirname in cf.var_dir.items():
        path = cf.varpath(name)
        assert path.exists(), f'{dirname} doesn\'t exist'

    # see if things have been initialised
    datadir = Path('srcdata')
    reference = ('build_files.json',
                 'firewallreader.pickle',
                 'listreader-records.json',
                 'logreader.json',
                 'patternreader.pickle',
                 'rulesreader.json',
                 'srcdict.json',
                 'step1_files.json')
    for rf in reference:
        rfp = datadir / rf
        if not rfp.exists():
            pytest.fail("Run 'make init' to set up reference files")

def test_fwdb(cf, fwdb_handle):
    """ Check firewall database """

    # The basic empty file should have been created
    dbfile = cf.varfilepath('firewall')
    assert dbfile.exists(), f'{str(dbfile)} hasn\'t been created'
    fwdb = fwdb_handle

    tnow = fwdb.db_timestamp()
    # insert a record
    ip = '192.0.2.1'
    current = {'ip': '192.0.2.1',
               'pattern': 'testing',
               'incidents': 1,
               'matchcount': 10,
               'first': tnow,
               'last': tnow,
               'ports': '22',
               'useall': False,
               'multiple': False,
               'isdnsbl':False}
    fwdb.insert_ip(current)

    # Get it back
    vals = fwdb.lookup_by_ip(ip)[0]
    assert any(vals)
    for k in current:
        assert current[k] == vals[k]

    # test replace
    update = {'incidents': 5,
              'matchcount' : 20}

    fwdb.update_ip(update, ip)

    # Get it back
    vals = fwdb.lookup_by_ip(ip)[0]
    assert any(vals)
    for k in current:
        if k in update.keys():
            assert update[k] == vals[k]
        else:
            assert current[k] == vals[k]
    # probably should test other functions

    # see if the file exists and delete it
    # make script re-entrant
    dbfile = cf.varfilepath('firewall')
    assert str(dbfile) == 'sys/firewall.db'
    if dbfile.exists():
        dbfile.unlink()
