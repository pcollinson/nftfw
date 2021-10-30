""" Test Log reader """

import time
from pathlib import Path
import pytest
from nftfw.blacklist import BlackList
from nftfw.nf_edit_dbfns import DbFns
from nftfw.fwdb import FwDb
from .configsetup import config_init

@pytest.fixture
def cf():          # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    _cf.TESTING = True
    _cf.selected_pattern_file = 'testlive'

    # check we are not going to zap any current filepos.db
    filepos = _cf.varfilepath('filepos')
    assert str(filepos) == 'sys/filepos.db'
    return _cf

def test_blacklist(cf):
    """ Read and scan logs """

    filepos = cf.varfilepath('filepos')
    if filepos.exists():
        filepos.unlink()

    firewall = cf.varfilepath('firewall')
    if firewall.exists():
        firewall.unlink()

    # in case of failure
    newfile = Path('sys/blacklist.d/198.51.100.32.auto')
    if newfile.exists():
        newfile.unlink()

    db = readfwdb(cf)
    assert not any(db)

    bl = BlackList(cf)
    changes = bl.blacklist()
    # expecting 198.51.100.32 to appear in blacklist.d
    # so changes should be 1
    assert changes == 1

    db = readfwdb(cf)
    assert len(db) == 6
    assert '198.51.100.32' in db.keys()
    tdb = db['198.51.100.32']
    assert tdb['matchcount'] == 20
    assert tdb['pattern'] == 'testlive'
    assert tdb['ports'] == '1000,1002,1003'

    filemtime = newfile.stat().st_mtime

    time.sleep(2)
    # run things again to check on updating
    filepos = cf.varfilepath('filepos')
    if filepos.exists():
        filepos.unlink()

    bl = BlackList(cf)
    changes = bl.blacklist()
    # no new files
    assert changes == 0
    # but the file should have been touched
    newfilemtime = newfile.stat().st_mtime
    assert newfilemtime > filemtime

    newdb = readfwdb(cf)
    for ip, val in newdb.items():
        assert val['incidents'] == 2
        assert val['first'] != val['last']
        assert val['first'] == db[ip]['first']
        assert val['matchcount'] == db[ip]['matchcount']*2

    # make things re-entrant
    # delete file and firewall.db in next test
    if filepos.exists():
        filepos.unlink()

def test_adm_delete(cf):
    """ Test delete in nf_edit_dbfns

    Delete the entry just added in previous test
    """

    iplist = ['198.51.100.32']

    firewall = cf.varfilepath('firewall')
    assert firewall.exists()

    newfile = Path('sys/blacklist.d/198.51.100.32.auto')
    assert newfile.exists()

    db = readfwdb(cf)
    assert '198.51.100.32' in db.keys()

    dbfns = DbFns(cf)
    deleted = dbfns.delete(iplist)
    assert deleted == 1
    db = readfwdb(cf)
    assert '198.51.100.32' not in db.keys()

    if firewall.exists():
        firewall.unlink()

def readfwdb(cf):
    """ Read current fwdb contents
    and return dict indexed by key
    """

    fw = FwDb(cf, createdb=False)
    contents = fw.lookup('blacklist')
    out = {}
    if any(contents):
        out = {c['ip']:c for c in contents}
    fw.close()
    return out
