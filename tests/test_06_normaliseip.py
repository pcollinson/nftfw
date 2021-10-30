""" Test normalise address function """

from pathlib import Path
import pytest
from nftfw.normaliseaddress import NormaliseAddress
from nftfw.whitelistcheck import WhiteListCheck
from .configsetup import config_init

@pytest.fixture
def cf():          # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    return _cf

@pytest.fixture
def norm(cf):
    """ Get Normalise address class """

    _na = NormaliseAddress(cf, 'test package')
    return _na

@pytest.fixture
def normwhite(cf):
    """ Get Normalise address class with the iswhite hook enabled """

    _na = NormaliseAddress(cf, 'test package')
    _wh = WhiteListCheck(cf)
    cf.is_white_fn = _wh.is_white
    return _na

def test_basic(norm):
    """ Test basic normalisation """

    iplist = ('192.0.2.5', '198.51.100.128',
              '198.51.100.5', '2001:db8:fab::/64',
              '203.0.113.7')
    for ip in iplist:
        res = norm.normal(ip)
        assert res == ip

def test_white(cf, normwhite):
    """ Test whitelist option """

    path = Path('data/whitelist.d/198.51.100.254')
    assert path.exists()
    res = normwhite.normal('198.51.100.254', cf.is_white_fn)
    assert res is None

def test_networknorm(norm):
    """ Test IP normalisation """

    ip = '2001:db8:fab::677'
    res = norm.normal(ip)
    assert res == '2001:db8:fab::/64'

    ip = '198.51.100.30/24'
    res = norm.normal(ip)
    assert res == '198.51.100.0/24'

def test_bad(norm):
    """ Test bad addresses """

    iplist = ('192.0.2', '192.0.2-255', '2001:db8:fab')

    for ip in iplist:
        res = norm.normal(ip)
        assert res is None
