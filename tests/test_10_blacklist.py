"""Tests for blacklist management system.

This module tests the BlackList class and database editing functionality,
which provide the core IP blacklisting system. The tests verify:
- Log scanning and IP extraction using pattern files
- Database storage of matched IPs with match counts and timestamps
- Blacklist file creation in blacklist.d directory (.auto files)
- File modification time tracking on re-scans
- Incident counting and match count accumulation
- Database editing operations (delete functionality)

The tests use a test log file with the 'testlive' pattern to verify that
the blacklist system correctly identifies, stores, and manages blacklisted
IP addresses across multiple scan cycles.

See Also:
    - nftfw.blacklist: Blacklist management implementation
    - nftfw.nf_edit_dbfns: Database editing functions
    - nftfw.fwdb: Firewall database
    - nftfw.logreader: Log scanning
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
import time
from pathlib import Path
import pytest
from nftfw.blacklist import BlackList
from nftfw.nf_edit_dbfns import DbFns
from nftfw.fwdb import FwDb
from .configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config


@pytest.fixture
def cf() -> Config:  # pylint: disable=invalid-name
    """Get config from configsetup with test pattern.

    Creates a test configuration with the 'testlive' pattern file
    selected for log scanning. Verifies that the filepos.db path
    is in the test directory to avoid affecting production data.

    Returns:
        Config instance configured for blacklist testing with
        selected_pattern_file='testlive' and TESTING=True.

    Raises:
        AssertionError: If filepos.db path is not in test directory.
    """
    # Initialize test configuration
    _cf = config_init()
    _cf.TESTING = True  # type: ignore[attr-defined]
    # Select test pattern file for log scanning
    _cf.selected_pattern_file = 'testlive'

    # Verify we are not going to overwrite any production filepos.db
    filepos = _cf.varfilepath('filepos')
    assert str(filepos) == 'sys/filepos.db', \
        f"Unexpected filepos path: {filepos}"
    return _cf


def test_blacklist(cf: Config) -> None:
    """Test blacklist workflow with log scanning and database updates.

    This test verifies the complete blacklist workflow across two scan cycles:

    Cycle 1 (Initial scan):
    - Scans test log file for matching IPs
    - Creates database entries with match counts
    - Creates .auto blacklist files for IPs exceeding threshold
    - Records first and last seen timestamps

    Cycle 2 (Re-scan):
    - Rescans same log file
    - Updates existing database entries (no new files)
    - Increments incident count
    - Doubles match count (same matches seen again)
    - Updates last seen timestamp
    - Touches existing .auto files to update mtime

    The test validates:
    - Initial database is empty
    - First scan creates 1 new blacklist file
    - Database contains 6 IPs after first scan
    - IP 198.51.100.32 has correct match count, pattern, and ports
    - Second scan creates no new files (changes=0)
    - File mtime is updated on second scan
    - Incident count increments to 2 for all IPs
    - Match counts double on second scan
    - First seen timestamp remains unchanged

    Args:
        cf: Config instance from fixture with test pattern selected.
    """
    # Clean up any existing state from previous runs
    filepos = cf.varfilepath('filepos')
    if filepos.exists():
        filepos.unlink()

    firewall = cf.varfilepath('firewall')
    if firewall.exists():
        firewall.unlink()

    # Clean up test blacklist file in case of previous failure
    newfile = Path('sys/blacklist.d/198.51.100.32.auto')
    if newfile.exists():
        newfile.unlink()

    # Verify database starts empty
    db = readfwdb(cf)
    assert not db, \
        "Expected empty database before first blacklist scan"

    # First blacklist scan - should find IPs and create files
    bl = BlackList(cf)
    changes = bl.blacklist()
    # Expecting 198.51.100.32 to appear in blacklist.d
    # Only 1 IP exceeds the threshold (block_after)
    assert changes == 1, \
        f"Expected 1 new blacklist file, got {changes}"

    # Verify database contents after first scan
    db = readfwdb(cf)
    assert len(db) == 6, \
        f"Expected 6 IPs in database, got {len(db)}"
    assert '198.51.100.32' in db, \
        "Expected IP 198.51.100.32 in database"

    # Verify specific IP details
    tdb = db['198.51.100.32']
    assert tdb['matchcount'] == 20, \
        f"Expected matchcount 20, got {tdb['matchcount']}"
    assert tdb['pattern'] == 'testlive', \
        f"Expected pattern 'testlive', got {tdb['pattern']}"
    assert tdb['ports'] == '1000,1002,1003', \
        f"Expected ports '1000,1002,1003', got {tdb['ports']}"

    # Record file mtime for comparison after second scan
    filemtime = newfile.stat().st_mtime

    # Sleep to ensure mtime will be different
    time.sleep(2)

    # Second blacklist scan - same log file, should update existing entries
    # Remove filepos so we re-scan the entire log
    filepos = cf.varfilepath('filepos')
    if filepos.exists():
        filepos.unlink()

    bl = BlackList(cf)
    changes = bl.blacklist()
    # No new files should be created (IPs already blacklisted)
    assert changes == 0, \
        f"Expected no new blacklist files, got {changes}"

    # Verify file was touched (mtime updated)
    newfilemtime = newfile.stat().st_mtime
    assert newfilemtime > filemtime, \
        "Expected blacklist file mtime to be updated on rescan"

    # Verify database updates after second scan
    newdb = readfwdb(cf)
    for ip, val in newdb.items():
        # Incident count should increment (seen in 2 separate scans)
        assert val['incidents'] == 2, \
            f"Expected 2 incidents for {ip}, got {val['incidents']}"
        # First and last seen should be different
        assert val['first'] != val['last'], \
            f"Expected different first/last timestamps for {ip}"
        # First seen should not change
        assert val['first'] == db[ip]['first'], \
            f"Expected first seen to remain unchanged for {ip}"
        # Match count should double (same matches seen again)
        assert val['matchcount'] == db[ip]['matchcount'] * 2, \
            f"Expected matchcount to double for {ip}"

    # Clean up for re-entrancy
    # Database and files will be deleted in next test
    if filepos.exists():
        filepos.unlink()


def test_adm_delete(cf: Config) -> None:
    """Test database delete operation via nf_edit_dbfns.

    This test verifies that the DbFns.delete() method correctly removes
    blacklist entries from both the database and the filesystem.

    The test:
    - Verifies entry exists in database (from previous test)
    - Verifies .auto file exists in blacklist.d
    - Calls DbFns.delete() to remove the entry
    - Verifies entry is removed from database
    - Cleans up database file

    Args:
        cf: Config instance from fixture.
    """
    # IP to delete (created in previous test)
    iplist = ['198.51.100.32']

    # Verify database exists (from previous test)
    firewall = cf.varfilepath('firewall')
    assert firewall.exists(), \
        "Expected firewall database to exist from previous test"

    # Verify blacklist file exists
    newfile = Path('sys/blacklist.d/198.51.100.32.auto')
    assert newfile.exists(), \
        "Expected blacklist file to exist from previous test"

    # Verify IP is in database
    db = readfwdb(cf)
    assert '198.51.100.32' in db, \
        "Expected IP 198.51.100.32 in database before delete"

    # Delete the IP using DbFns
    dbfns = DbFns(cf)
    deleted = dbfns.delete(iplist)
    assert deleted == 1, \
        f"Expected to delete 1 entry, deleted {deleted}"

    # Verify IP is removed from database
    db = readfwdb(cf)
    assert '198.51.100.32' not in db, \
        "Expected IP 198.51.100.32 to be removed from database"

    # Clean up database file for re-entrancy
    if firewall.exists():
        firewall.unlink()


def readfwdb(cf: Config) -> dict[str, dict[str, Any]]:
    """Read current fwdb contents and return dict indexed by IP.

    Helper function to read the firewall database and return its
    contents as a dictionary mapping IP addresses to their records.

    Args:
        cf: Config instance for database access.

    Returns:
        Dictionary mapping IP addresses to their database records.
        Returns empty dict if no entries exist.
        Each record contains: ip, matchcount, incidents, pattern, ports,
        first (timestamp), last (timestamp).
    """
    # Open database (don't create if it doesn't exist)
    fw = FwDb(cf, createdb=False)
    # Get all blacklist entries
    contents = fw.lookup('blacklist')
    out = {}
    # Convert list of records to dict indexed by IP
    if contents:
        out = {c['ip']: c for c in contents}
    fw.close()
    return out
