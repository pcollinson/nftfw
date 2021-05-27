
""" Pytest fwmanage - can't do nft steps """
import json
import hashlib
from pathlib import Path
import pytest
from nftfw import fwmanage

@pytest.fixture
def cf():          # pylint: disable=invalid-name
    """ Get config from configsetup """
    from configsetup import config_init

    _cf = config_init()
    return _cf

def test_step1(cf):
    """ Step 1 - load info """

    files = fwmanage.step1(cf)

    # create reference data
    newpath = Path('newdata/step1_files.json')
    wr = json.dumps(files)
    newpath.write_text(wr)

    path = Path('srcdata/step1_files.json')
    contents = path.read_text()
    reference = json.loads(contents)
    for k, val in reference.items():
        assert k in files.keys(), f'Key {k} missing from srcdata, could be software/or data error'
        assert val == files[k], f'Key {k} - data mismatch'
    for k in files:
        assert k in reference.keys()

def test_step2(cf):
    """ Step 2 - install in build """

    path = Path('srcdata/step1_files.json')
    contents = path.read_text()
    files = json.loads(contents)

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

    newpath = Path('newdata/build_files.json')
    wr = json.dumps(hashdict)
    newpath.write_text(wr)

    path = Path('srcdata/build_files.json')
    co = path.read_text()
    hashdict = json.loads(co)
    for f in files:
        p = buildpath / f
        c = p.read_text()
        h = hashlib.sha256(c.encode())
        assert h.hexdigest() == hashdict[f]


def test_step4(cf):
    """ Step 4 - Test installation logic """

    buildpath = cf.varpath('build')
    assert str(buildpath) == 'sys/build.d'
    installpath = cf.varpath('install')
    assert str(installpath) == 'sys/install.d'

    path = Path('srcdata/build_files.json')
    co = path.read_text()
    hashdict = json.loads(co)
    files = hashdict.keys()

    # if we don't have the files in build
    # this means we can run this test standalone
    # run step2 again
    if not have_files(files, buildpath):
        test_step2(cf)

    assert have_files(files, buildpath)

    remove_files(files, installpath)

    # now run fwmanage.step4
    # should be a full install
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result == 'full'
    assert have_files(files, installpath)

    # now run fwmanage.step4
    # Nothing should be needed
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None

    # Now make some changes to get a set install
    # add a comment to the blacklist_sets.nft file in install.d
    append_comment(installpath, 'blacklist_sets.nft')
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert isinstance(result, list)
    assert any(result)
    assert len(result) == 1
    assert result[0] == 'blacklist'

    # but it will have re-written the file that was changed
    # so we should now get a None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None

    # Do the same for incoming.nft
    # Now make some changes to get a set install
    # add a comment to the blacklist_sets.nft file in install.d
    append_comment(installpath, 'incoming.nft')
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result == 'full'
    assert have_files(files, installpath)

    # but it will have re-written the file that was changed
    # so we should now get a None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None

    # Do the same for outgoing.nft
    # Now make some changes to get a set install
    # add a comment to the blacklist_sets.nft file in install.d
    append_comment(installpath, 'outgoing.nft')
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result == 'full'
    assert have_files(files, installpath)

    # but it will have re-written the file that was changed
    # so we should now get a None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None

    # tidy up
    remove_files(files, installpath)
    remove_files(files, buildpath)

def have_files(files, path):
    """ See if the files are in path """

    for f in files:
        fpath = path / f
        if not fpath.exists():
            return False
    fpath = path / 'nftfw_init.nft'
    if not fpath.exists():
        return False
    return True

def remove_files(files, path):
    """ Remove files from a directory """

    for f in files:
        fpath = path / f
        if fpath.exists():
            fpath.unlink()
    fpath = path / 'nftfw_init.nft'
    if fpath.exists():
        fpath.unlink()

def append_comment(path, file):
    """ Append a comment to a file to fake set only changes """

    pa = path / file
    contents = pa.read_text()
    contents += '\n# Comment added\n'
    pa.write_text(contents)
