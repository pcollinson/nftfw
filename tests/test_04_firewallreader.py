""" Pytest firewallreader

"""

import pickle
import pytest
from nftfw.rulesreader import RulesReader
from nftfw.ruleserr import RulesReaderError
from nftfw.firewallreader import FirewallReader
from .configsetup import config_init

@pytest.fixture
def cf():          # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    try:
        _rules = RulesReader(_cf)
        # this is an internal convention
        _cf.rulesreader = _rules
    except RulesReaderError as e:
        assert e is not None, 'RulesReaderError - str(e)'
    return _cf

@pytest.fixture
def firewallreader(cf):
    """ Firewall reader """

    _fr = FirewallReader(cf, 'incoming')
    return _fr

def test_reader(firewallreader):
    """ Validate information from firewall reader """

    records = firewallreader.records
    assert len(records) == 16, "Should be 16 records"

    file = open('newdata/firewallreader.pickle', 'wb')
    pickle.dump(records, file)
    file.close()

    file = open('srcdata/firewallreader.pickle', 'rb')
    reference = pickle.load(file)
    file.close()

    for i in range(len(reference)):   # pylint: disable=consider-using-enumerate
        ref = reference[i]
        rec = records[i]
        for ix in ['baseaction', 'action', 'ports', 'content', 'ip', 'ip6']:
            if ix in ref:
                assert rec[ix] == ref[ix]
