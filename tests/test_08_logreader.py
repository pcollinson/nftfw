"""Tests for log reading and pattern matching.

This module tests the logreader module, which provides incremental log
file scanning with pattern matching. The tests verify:
- Log file reading and pattern matching
- Incremental scanning with file position tracking
- IP address extraction from log files using regex patterns
- Port and pattern association with matched IPs
- File position database (filepos.db) functionality

The test uses a test log file and pattern file to verify that the
log_reader() function correctly identifies IP addresses matching
specified patterns and tracks file positions for incremental reading.

See Also:
    - nftfw.logreader: Log file scanning implementation
    - nftfw.fileposdb: File position tracking database
    - nftfw.patternreader: Pattern file parsing
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import json
from pathlib import Path
import pytest

from nftfw.logreader import log_reader
from nftfw.fileposdb import FileposDb
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
        Config instance configured for log reader testing with
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


def test_logreader(cf: Config) -> None:
    """Test log file reading and pattern matching.

    This test verifies the complete log scanning workflow:
    - Reads test log file (sys/testlogfile.log)
    - Applies pattern matching from testlive pattern file
    - Extracts IP addresses, ports, and patterns
    - Tracks file position in filepos.db for incremental scanning
    - Compares results against reference data

    The test validates:
    - All expected IPs are found with correct patterns
    - Match counts and incident counts are accurate
    - Port associations are correct
    - File position equals log file size after complete read

    Args:
        cf: Config instance from fixture with test pattern selected.
    """
    # Remove any existing file position database for clean test
    filepos = cf.varfilepath('filepos')
    if filepos.exists():
        filepos.unlink()

    # Run log reader with test pattern
    ret = log_reader(cf)

    # Write current results to newdata/ for comparison
    newpath = Path('newdata/logreader.json')
    wr = json.dumps(ret)
    newpath.write_text(wr, encoding='utf-8')

    # Load reference data for validation
    path = Path('srcdata/logreader.json')
    re = path.read_text(encoding='utf-8')
    reference = json.loads(re)

    # Verify all expected IPs are present with correct data
    for key, val in reference.items():
        assert key in ret, \
            f"Expected IP {key} not found in results"
        # Check pattern, matchcount, and incidents fields
        for vkey in ('pattern', 'matchcount', 'incidents'):
            assert vkey in ret[key], \
                f"Field {vkey} missing from IP {key}"
            assert val[vkey] == reference[key][vkey], \
                f"Mismatch in {vkey} for IP {key}: " \
                f"expected {reference[key][vkey]}, got {val[vkey]}"
        # Check ports field (order-independent comparison)
        assert 'ports' in reference[key], \
            f"Field ports missing from reference IP {key}"
        assert 'ports' in val, \
            f"Field ports missing from result IP {key}"
        assert set(reference[key]['ports']) == set(val['ports']), \
            f"Port mismatch for IP {key}: " \
            f"expected {reference[key]['ports']}, got {val['ports']}"

    # Verify file position tracking
    # File position should equal file size after complete read
    fwdb = FileposDb(cf, createdb=False)
    posn, _ = fwdb.getfileinfo('sys/testlogfile.log')
    assert posn == 390, \
        f"Expected file position 390, got {posn}"
    fileposfile = Path('sys/testlogfile.log')
    assert posn == fileposfile.stat().st_size, \
        f"File position {posn} does not match file size " \
        f"{fileposfile.stat().st_size}"

    # Clean up file position database for re-entrancy
    if filepos.exists():
        filepos.unlink()
