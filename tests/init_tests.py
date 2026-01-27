"""Initialize static reference files for test comparisons.

This module generates reference data files used by the test suite to verify
that nftfw components produce correct output. The reference files are stored
in srcdata/ and compared against fresh output generated during test runs.

Purpose:
    When tests run, they generate fresh output (e.g., firewall rules, database
    queries, log parsing results). This output is compared against static
    reference files to ensure correctness. This module creates those reference
    files by running the nftfw components once with known test data.

Reference Files Created:
    JSON files (in srcdata/):
    - rulesreader.json - Expected rule definitions
    - srcdict.json - Expected list reader source dict
    - listreader-records.json - Expected list reader compiled records
    - step1_files.json - Expected firewall management step 1 output
    - build_files.json - SHA256 hashes of expected build files
    - logreader.json - Expected log scanning results

    Pickle files (in srcdata/):
    - firewallreader.pickle - Expected firewall reader records
    - patternreader.pickle - Expected pattern definitions

When to Run:
    Run this script when:
    - Setting up the test suite for the first time
    - After making changes to core nftfw code
    - After updating test data in data/ directory
    - When test comparisons start failing due to intentional changes

Usage:
    From command line:
        $ cd tests
        $ python3 init_tests.py

    From Makefile:
        $ cd tests
        $ make init

    From Python:
        from tests.init_tests import init_tests
        init_tests()

Important:
    The reference files in srcdata/ are the "source of truth" for tests.
    If you intentionally change nftfw behavior, you must regenerate these
    files or tests will fail.

See Also:
    configsetup.py - Configuration helper for test environment
    __init__.py - Package initialization that calls this module
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
import sys
import json
import pickle
import hashlib
from pathlib import Path

from nftfw.rulesreader import RulesReader
from nftfw.listreader import ListReader
from nftfw.firewallreader import FirewallReader
from nftfw import fwmanage
from nftfw.patternreader import pattern_reader
from nftfw.logreader import log_reader
from .configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config

def init_tests() -> None:
    """Initialize reference data files for test comparisons.

    This function generates all static reference files used by the test suite
    by running nftfw components with known test data and saving their output.
    The generated files are stored in srcdata/ and used by individual tests
    to verify correct behavior.

    Process:
        1. Initialize test config and validate paths
        2. Create srcdata/ and newdata/ directories
        3. Update blacklist test files (prevent expiry)
        4. Generate reference files for each test module:
           - test_02: RulesReader output
           - test_03: ListReader output (srcdict and records)
           - test_04: FirewallReader output
           - test_05: Firewall management workflow output
           - test_07: Pattern reader output
           - test_08: Log reader output

    Side Effects:
        Creates/updates files in srcdata/:
        - rulesreader.json
        - srcdict.json
        - listreader-records.json
        - firewallreader.pickle
        - step1_files.json
        - build_files.json (SHA256 hashes)
        - patternreader.pickle
        - logreader.json

    Raises:
        SystemExit: If Config setup produces incorrect paths
        AssertionError: If expected paths don't exist during validation

    Note:
        This function has many local variables due to generating multiple
        reference files. This is acceptable for initialization code.
    """
    # pylint: disable=too-many-locals

    # Initialize config and validate test environment
    cf = config_init()
    cf.TESTING = True   # type: ignore[attr-defined]

    # Validate That config is set up correctly for test environment
    try:
        buildpath = cf.varpath('build')
        assert str(buildpath) == 'sys/build.d'
        filepos = cf.varfilepath('filepos')
        assert str(filepos) == 'sys/filepos.db'
    except AssertionError as e:
        print(f'Not set up correctly: {str(e)}')
        sys.exit(1)

    # Create srcdata and newdata directories for test artifacts
    for name in ['srcdata', 'newdata']:
        path = Path(name)
        if not path.exists():
            path.mkdir()
        assert path.is_dir()

    # Update blacklist test files to prevent expiry
    # Files may have old timestamps if downloaded from GitHub
    checkbasicfiles(cf)

    # Generate reference file for test_02 (RulesReader)
    rdr = RulesReader(cf)

    # Generate reference files for test_03 (ListReader)
    # Store RulesReader in config for FirewallReader to use
    cf.rulesreader = rdr
    write_json('rulesreader.json', rdr.rules)

    # Generate reference files for test_03 (ListReader blacklist)
    ldr = ListReader(cf, 'blacklist')
    write_json('srcdict.json', ldr.srcdict)
    write_json('listreader-records.json', ldr.records)

    # Generate reference file for test_04 (FirewallReader)
    fwr = FirewallReader(cf, 'incoming')
    write_pickle('firewallreader.pickle', fwr.records)

    # Generate reference files for test_05 (Firewall management)
    # Step 1: Collect firewall files
    files = fwmanage.step1(cf)
    write_json('step1_files.json', files)

    # Step 2: Build firewall rules and generate SHA256 hashes
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

    # Generate reference file for test_07 (PatternReader)
    patterns = pattern_reader(cf)
    write_pickle('patternreader.pickle', patterns)

    # Generate reference file for test_08 (LogReader)
    # Clean up any existing filepos.db first
    filepos = cf.varfilepath('filepos')
    assert str(filepos) == 'sys/filepos.db'
    if filepos.exists():
        filepos.unlink()

    # Run log reader with test pattern
    cf.selected_pattern_file = 'testlive'
    ret = log_reader(cf)
    write_json('logreader.json', ret)

    # Clean up filepos.db after generating reference
    if filepos.exists():
        filepos.unlink()

def checkbasicfiles(cf: Config) -> None:
    """Check and update blacklist test files to prevent expiry.

    This function ensures the blacklist.d test files exist and have current
    timestamps. This is necessary because blacklist files may be expired
    based on their modification time, and files downloaded from GitHub may
    have old timestamps that would cause them to be expired during tests.

    Args:
        cf: Config instance for accessing blacklist directory path.

    Side Effects:
        - Touches (updates mtime) existing blacklist test files
        - Creates missing blacklist test files with appropriate content
        - Deletes 198.51.100.32 file if it exists (used for delete tests)

    Raises:
        SystemExit: If blacklist.d directory doesn't exist or has wrong path

    Note:
        Uses TEST-NET IP addresses from RFC 5737 and documentation IPv6
        addresses from RFC 3849 to avoid conflicts with real addresses.
    """
    # Define expected test files and their contents
    # Empty string means touch file with no content
    basefiles = {'192.0.2.5.auto': '',
                 '198.51.100.128.auto': '22\n',
                 '198.51.100.5': '',
                 '2001:db8:fab::|64.auto': '80\n443\n',
                 '203.0.113.7.auto': ''
                 }

    # Validate blacklist directory setup
    try:
        blacklist = cf.etcpath('blacklist')
        assert str(blacklist) == 'sys/blacklist.d'
        assert blacklist.exists()
    except AssertionError as e:
        print(f'Not set up correctly: {str(e)}')
        sys.exit(1)

    # Update or create each blacklist test file
    for bfile, contents in basefiles.items():
        bpath = blacklist / bfile
        if bpath.exists():
            # Touch to update mtime (prevent expiry)
            bpath.touch()
        elif contents != '':
            # Create with specified content
            bpath.write_text(contents)
        else:
            # Create empty file
            bpath.touch()

    # Delete test file used for deletion testing
    # 198.51.100.32 should be deleted (tests verify it gets removed)
    dfile = blacklist / '198.51.100.32'
    if dfile.exists():
        dfile.unlink()


def write_json(file: str, obj: Any) -> None:
    """Write object as JSON to srcdata directory if file doesn't exist.

    Args:
        file: Filename (without path) to write in srcdata/ directory.
        obj: Python object to serialize as JSON (must be JSON-serializable).

    Side Effects:
        Creates file in srcdata/ with JSON representation of obj, but only
        if the file doesn't already exist. Existing files are preserved.

    Example:
        >>> write_json('test.json', {'key': 'value'})
        # Creates srcdata/test.json if it doesn't exist
    """
    wr = json.dumps(obj)

    newpath = Path('srcdata')
    file_path = newpath / file
    if not file_path.exists():
        file_path.write_text(wr)


def write_pickle(file: str, obj: Any) -> None:
    """Write object as pickle to srcdata directory if file doesn't exist.

    Args:
        file: Filename (without path) to write in srcdata/ directory.
        obj: Python object to pickle (must be pickle-able).

    Side Effects:
        Creates file in srcdata/ with pickled representation of obj, but only
        if the file doesn't already exist. Existing files are preserved.

    Example:
        >>> write_pickle('test.pickle', ['data', 'structure'])
        # Creates srcdata/test.pickle if it doesn't exist
    """
    newpath = Path('srcdata')
    file_path = newpath / file
    if not file_path.exists():
        with open(str(file_path), 'wb') as fd:
            pickle.dump(obj, fd)

if __name__ == '__main__':
    init_tests()
