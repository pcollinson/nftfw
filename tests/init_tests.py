""" Initialise static files used for comparison with running data """
import sys
import json
import pickle
import hashlib
from pathlib import Path
from configsetup import config_init
from rulesreader import RulesReader
from listreader import ListReader
from firewallreader import FirewallReader
from nftfw import fwmanage
from patternreader import pattern_reader
from logreader import log_reader

def init_tests():
    """ Initialise data used to compare test values """

    cf = config_init()
    cf.TESTING = True

    try:
        buildpath = cf.varpath('build')
        assert str(buildpath) == 'sys/build.d'
        filepos = cf.varfilepath('filepos')
        assert str(filepos) == 'sys/filepos.db'
    except AssertionError as e:
        print(f'Not set up correctly: {str(e)}')
        sys.exit(1)

    # Blacklist will expire time elapsed files
    # and this may happen when they are downloaded
    # from github
    checkbasicfiles(cf)

    # test_02
    rdr = RulesReader(cf)

    # test_04
    cf.rulesreader = rdr
    write_json('rulesreader.json', rdr.rules)

    # test_03
    ldr = ListReader(cf, 'blacklist')
    write_json('srcdict.json', ldr.srcdict)
    write_json('listreader-records.json', ldr.records)

    # test_04
    fwr = FirewallReader(cf, 'incoming')
    write_pickle('firewallreader.pickle', fwr.records)

    # test_05
    files = fwmanage.step1(cf)
    write_json('step1_files.json', files)

    buildpath = cf.varpath('build')
    assert str(buildpath) == 'sys/build.d'
    fwmanage.step2(cf, files, buildpath)
    hashdict = {}
    for f in files:
        p = buildpath / f
        assert p.exists()
        c = p.read_text()
        h = hashlib.sha256(c.encode())
        hashdict[f] = h.hexdigest()
    write_json('build_files.json', hashdict)

    # test_07
    patterns = pattern_reader(cf)
    write_pickle('patternreader.pickle', patterns)

    # test_08
    filepos = cf.varfilepath('filepos')
    assert str(filepos) == 'sys/filepos.db'
    if filepos.exists():
        filepos.unlink()

    cf.selected_pattern_file = 'testlive'
    ret = log_reader(cf)
    write_json('logreader.json', ret)

    if filepos.exists():
        filepos.unlink()

def checkbasicfiles(cf):
    """ check that the basic files exist and update them """

    # check that the blacklist.d directory is setup
    # as we want it - and touch the files so they
    # don't get expired
    basefiles = {'192.0.2.5.auto': '',
                 '198.51.100.128.auto': '22\n',
                 '198.51.100.5':'',
                 '2001:db8:fab::|64.auto': '80\n443\n',
                 '203.0.113.7.auto': ''
                 }
    try:
        blacklist = cf.nftfwpath('blacklist')
        assert str(blacklist) == 'sys/blacklist.d'
        assert blacklist.exists()
    except AssertionError as e:
        print(f'Not set up correctly: {str(e)}')
        sys.exit(1)

    for bfile, contents in basefiles.items():
        bpath = blacklist / bfile
        if bpath.exists():
            bpath.touch()
        elif contents != '':
            bpath.write_text(contents)
        else:
            bpath.touch()

    # 198.51.100.32 should be deleted
    dfile = blacklist / '198.51.100.32'
    if dfile.exists():
        dfile.unlink()


def write_json(file, obj):
    """ Write the object to newdata and data """
    wr = json.dumps(obj)

    newpath = Path('data')
    file = newpath / file
    if not file.exists():
        file.write_text(wr)

def write_pickle(file, obj):
    """ Write a pickled object """
    newpath = Path('data')
    file = newpath / file
    fd = open(str(file), 'wb')
    pickle.dump(obj, fd)
    fd.close()

if __name__ == '__main__':
    init_tests()
