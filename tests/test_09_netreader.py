""" Test Netreader """

from pathlib import Path
import time
import pytest
from configsetup import config_init
from netreader import NetReader

@pytest.fixture
def cf():     # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    return _cf

def test_netreader(cf):
    """ Create a sample file in blacknets.d
    Look at stored output
    """

    samplefile = """
# should collapse these two

192.0.2.0/23
192.0.2.0/24
2001:db8:fab::/32
# fails
203.0
203.0.117.1-203.0.117.254
# ipv6
2001:DB8:af67::/32
# iplocation uses this format for ipv4
::FFFF:203.13.18.0/120
# should become ipv4 203.0.113.0/24
::ffff:cb00:7100/120
"""


    # remove cache
    cachefile = Path('sys/blacknets_cache.json')
    testfile = Path('sys/blacknets.d/te.nets')
    if cachefile.exists():
        cachefile.unlink()
    if testfile.exists():
        testfile.unlink()

    # no file so nr.records should be empty
    nr = NetReader(cf, 'blacknets')
    assert not any(nr.records)

    # now create the file

    testfile.write_text(samplefile)

    nr = NetReader(cf, 'blacknets')
    # should have some results
    assert 'all' in nr.records
    assert 'ip' in nr.records['all']
    assert 'ip6' in nr.records['all']
    assert len(nr.records['all']['ip']) == 3
    assert len(nr.records['all']['ip6']) == 1
    assert '192.0.2.0/23' in nr.records['all']['ip']
    assert '203.0.113.0/24' in nr.records['all']['ip']
    assert '203.13.18.0/24' in nr.records['all']['ip']
    assert cachefile.exists()

    # check for updates of cache
    mtime = cachefile.stat().st_mtime
    time.sleep(1)
    testfile.touch()
    nr = NetReader(cf, 'blacknets')
    assert mtime != cachefile.stat().st_mtime

    # removing the testfile - should delete the cache too
    if testfile.exists():
        testfile.unlink()
    nr = NetReader(cf, 'blacknets')
    assert not cachefile.exists()
