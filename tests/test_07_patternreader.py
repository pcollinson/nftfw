""" Test normalise address function """

import pickle
import pytest
from configsetup import config_init
from patternreader import pattern_reader
from patternreader import parsefile

@pytest.fixture
def cf():          # pylint: disable=invalid-name
    """ Get config from configsetup """

    _cf = config_init()
    return _cf


def test_patternreader(cf):
    """ Read all patterns """

    patterns = pattern_reader(cf)

    # can't use json because of the compiled re's
    # save reference
    file = open('newdata/patternreader.pickle', 'wb')
    pickle.dump(patterns, file)
    file.close()

    file = open('data/patternreader.pickle', 'rb')
    reference = pickle.load(file)
    file.close()

    for key, val in reference.items():
        assert key in patterns.keys()
        for i in range(len(val)):           # pylint: disable=consider-using-enumerate
            refval = val[i]
            patval = patterns[key][i]
            for vkey in ('pattern', 'ports', 'file'):
                if vkey in refval:
                    assert vkey in patval.keys()
                    assert refval[vkey] == patval[vkey]
            if 'regex' in refval:
                assert 'regex' in patval
                for reix in range(len(refval['regex'])):
                    assert refval['regex'][reix] == patval['regex'][reix]
    for key, val in patterns.items():
        assert key in reference.keys()

def test_parsefile(cf):
    """ Test file parsing """

    assert parsefile(cf, 'testname', []) is None

    testdata = ['file = sys/testlogfile.log',
                'ports = 300,100,200,300',
                '__IP__']

    ret = parsefile(cf, 'testlive', "\n".join(testdata))
    assert ret is not None
    assert ret['file'] == 'sys/testlogfile.log'
    assert ret['ports'] == '300,100,200,300'
    assert ret['file'] == 'sys/testlogfile.log'
    assert 'regex' in ret.keys()
    for re in ret['regex']:
        assert re.match('198.51.100.128')
        assert re.match('2001:db8:fab::8')

    # check that we are ignoring patterns if selected file is selected
    cf.selected_pattern_file = 'apache2'
    ret = parsefile(cf, 'testlive', "\n".join(testdata))
    assert ret is None

    cf.selected_pattern_file = None
    ret = parsefile(cf, 'testlive', "\n".join(testdata))
    assert ret is not None

    # check for missing port line
    # no port line - default to all
    td = [testdata[0], testdata[2]]
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret['ports'] == 'all'

    # check for missing file line
    # no port line - default to all
    td = [testdata[1], testdata[2]]
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is None

    # check for no regexs
    td = [testdata[0], testdata[1]]
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is None

    # check for bad regex
    td = [testdata[0], testdata[1], r'__IP__ [a-z']
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is None
