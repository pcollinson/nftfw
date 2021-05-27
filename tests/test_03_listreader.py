""" Pytest list reader test

Uses IP addresses in blacklist.d
"""

import json
from pathlib import Path
import pytest
from configsetup import config_init
from listreader import ListReader, SetName


@pytest.fixture
def cf():         # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    return _cf

@pytest.fixture
def listrdr(cf):
    """ Read data from blacklist.d """

    _list = ListReader(cf, 'blacklist')
    return _list

@pytest.fixture
def setname():
    """ SetName class """

    _sn = SetName('blacklist')
    return _sn

def test_ix(listrdr):
    """ Check that we have created the basic index correctly """

    # check that file created by test_08 isn't there
    newfile = Path('sys/blacklist.d/198.51.100.32.auto')
    if newfile.exists():
        newfile.unlink()

    srcdict = listrdr.srcdict
    assert len(srcdict) == 5, "Should be 5 addresses"

    newpath = Path('newdata/srcdict.json')
    wr = json.dumps(srcdict)
    newpath.write_text(wr)

    # get reference
    path = Path('srcdata/srcdict.json')
    contents = path.read_text()
    reference = json.loads(contents)
    for k, val in reference.items():
        assert k in srcdict.keys(), f'Key {k} missing from srcdata, could be software/or data error'
        assert val == srcdict[k], f'Key {k} - data mismatch'

    for k, val in srcdict.items():
        assert k in reference.keys(), f'Key {k} not in reference set'

def test_records(listrdr):
    """ Check that we have created the records correctly """

    records = listrdr.records
    assert len(records) == 3, 'Should be 3 set of ports'

    newpath = Path('newdata/listreader-records.json')
    wr = json.dumps(records)
    newpath.write_text(wr)

    path = Path('srcdata/listreader-records.json')
    contents = path.read_text()
    reference = json.loads(contents)

    for k, val in reference.items():
        assert k in records.keys(), f'Key {k} missing from data, could be software/or data error'
        if 'ip' in val:
            assert set(val['ip']) == set(records[k]['ip']), f'Key {k} ips differ'
        else:
            assert set(val['ip6']) == set(records[k]['ip6']), f'Key {k} ips differ'
        assert val['name'] == records[k]['name'], f'Key {k} names differ'

    for k, val in records.items():
        assert k in reference.keys(), f'Key {k} not in reference set'

def test_portchk(listrdr):
    """ Unit check test the port reader code """

    src = "1"
    v = listrdr.portcheck(src)
    assert v == "1"
    src = "100\n100\n100\n100\n50\n"
    v = listrdr.portcheck(src)
    assert v == '50,100'
    src = "100\n100\nall\n100\n50\n"
    v = listrdr.portcheck(src)
    assert v == 'all'
    src = "20, 100 \n36\n100\n50\n"
    v = listrdr.portcheck(src)
    assert v == '20,36,50,100'

def test_validateip(listrdr):
    """ Validate IP addresses """

    valip = listrdr.validateip
    ip = '192.0.2.4'
    v = valip(ip)
    assert str(v) == ip

    ip = '192.0.2.4/24'
    v = valip(ip)
    assert ip == '192.0.2.4/24'

    ip = '2001:db8::1/64'
    v = valip(ip)
    assert str(v) == '2001:db8::/64'

    ip = '192.0.2.500'
    v = valip(ip)
    assert v is None

    ip = '2001:db8:ffff:fff:fff:fff:fff'
    v = valip(ip)
    assert v is None

def test_setname(setname):
    """ Test setname """

    # ports are more constrained than this
    v = setname.name('25,465')
    assert v == 'b_25_465'
    v = setname.name('25,465,587')
    assert v == 'b_25_465_587'
    v = setname.name('25,465,587,110')
    assert v == 'b_25_465_587_110'
    v = setname.name('25,465,587,110,995')
    assert v == 'b1_25_465_587_11'
    v = setname.name('25,465,587,110,995,54')
    assert v == 'b2_25_465_587_11'
