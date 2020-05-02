""" Pytest rules reader test

Uses standard set of rules in sys/rules.d
"""

from pathlib import Path
import json
import pytest
from configsetup import config_init
from rulesreader import RulesReader
from ruleserr import RulesReaderError

@pytest.fixture
def cf():     # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    return _cf

@pytest.fixture
def rulesrdr(cf):
    """ Get rulesreader loaded """

    try:
        _rules = RulesReader(cf)
        # this is an internal convention
        cf.rulesreader = _rules
    except RulesReaderError as e:
        assert e is not None, 'RulesReaderError - str(e)'
    return _rules

def test_rules(rulesrdr):
    """ Validate rules that are installed
    against a reference set in data/rulesreader.json
    """

    rdr = rulesrdr
    rules = rdr.rules
    rulestotal = len(rules)
    # should be 13
    assert rulestotal == 13, f'Should be 13 rules'

    # create reference text
    newpath = Path('newdata/rulesreader.json')
    wr = json.dumps(rules)
    newpath.write_text(wr)

    # Get reference text
    path = Path('data/rulesreader.json')
    contents = path.read_text()
    reference = json.loads(contents)
    for k, val in reference.items():
        assert rdr.exists(k), f'Key {k} missing from data, could be software/or data error'
        assert val == rdr.contents(k), f'Key {k} - data mismatch'

    for k, val in rules.items():
        assert k in reference.keys(), f'Key {k} not in reference set'

def test_errors(rulesrdr):
    """ Test failure of execution """

    rdr = rulesrdr

    bads = {'bad1' : '(echo fail to stderr 1>&2) \n\n',
            'bad2' : 'V=6\nif $V = 6; then \n echo missing fi ; \n\n',
            'bad3' : 'exit(127)'

            }
    for k, v in bads.items():
        rdr.rules_store[k] = v

    env = {}
    for k in bads:
        try:
            rdr.execute(k, env)
            pytest.fail('Should fail')
        except RulesReaderError as e:
            assert e is not None, 'RulesReaderError - str(e)'
