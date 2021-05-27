""" Test Log reader """

import json
from pathlib import Path
import pytest
from configsetup import config_init
from logreader import log_reader
from fileposdb import FileposDb

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

def test_logreader(cf):
    """ Read and scan logs """

    filepos = cf.varfilepath('filepos')
    if filepos.exists():
        filepos.unlink()

    ret = log_reader(cf)

    # create reference data
    newpath = Path('newdata/logreader.json')
    wr = json.dumps(ret)
    newpath.write_text(wr)

    path = Path('srcdata/logreader.json')
    re = path.read_text()
    reference = json.loads(re)

    for key, val in reference.items():
        assert key in ret.keys()
        for vkey in ('pattern', 'matchcount', 'incidents'):
            assert vkey in ret[key].keys()
            assert val[vkey] == reference[key][vkey]
        assert 'ports' in reference[key].keys()
        assert 'ports' in val.keys()
        assert set(reference[key]['ports']) == set(val['ports'])

    # check that filepos is the same as the length of the logfile
    fwdb = FileposDb(cf, createdb=False)
    posn, _ = fwdb.getfileinfo('sys/testlogfile.log')
    assert posn == 390
    fileposfile = Path('sys/testlogfile.log')
    assert posn == fileposfile.stat().st_size

    # remove filepos file for reentrancy
    if filepos.exists():
        filepos.unlink()
