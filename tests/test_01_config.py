"""Test config initialization and firewall database operations.

This module tests the core configuration system and firewall database (FwDb)
functionality. It verifies that the test environment is set up correctly and
that database operations (insert, lookup, update) work as expected.

Tests:
    test_setup - Validates config paths and reference file initialization
    test_fwdb - Tests firewall database CRUD operations

Fixtures:
    cf - Provides configured Config instance for tests
    fwdb_handle - Provides fresh FwDb instance with clean database

The tests are re-entrant, cleaning up the database file after execution.
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from pathlib import Path

import pytest

from tests.configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config
    from nftfw.fwdb import FwDb

# Import at runtime for instantiation
from nftfw.fwdb import FwDb  # pylint: disable=wrong-import-position


@pytest.fixture
def cf() -> Config:  # pylint: disable=invalid-name
    """Get configured Config instance for testing.

    Creates a Config instance using config_init() and validates that
    it's properly configured for the test environment (sysvar='sys').

    Returns:
        Config instance configured for test environment.

    Raises:
        pytest.fail: If Config is not set up correctly.
    """
    _cf = config_init()
    sysvar = _cf.get_ini_value_from_section('Locations', 'sysvar')
    assert sysvar == 'sys'
    if sysvar != 'sys':
        pytest.fail('Incorrect config setup')
    return _cf


@pytest.fixture
def fwdb_handle(cf: Config) -> FwDb:
    """Get fresh FwDb instance with clean database.

    Deletes any existing firewall.db file and creates a new FwDb instance,
    ensuring tests start with a clean database state.

    Args:
        cf: Config instance from cf fixture.

    Returns:
        Fresh FwDb instance with newly created database.
    """
    # Delete existing database file if present
    dbfile = cf.varfilepath('firewall')
    assert str(dbfile) == 'sys/firewall.db'
    if dbfile.exists():
        dbfile.unlink()

    # Create new database (should create the file)
    fwdb = FwDb(cf)
    assert dbfile.exists()
    return fwdb


def test_setup(cf: Config) -> None:
    """Validate config settings and test environment setup.

    Verifies that:
    - Config paths point to test directories (sys/)
    - All expected etc and var directories exist
    - Reference files have been initialized in srcdata/

    This test ensures the test environment is properly set up before
    running other tests.

    Args:
        cf: Config instance from cf fixture.
    """
    # Verify core config paths point to test environment
    assert str(cf.nftfw_init) == 'sys/nftfw_init.nft'
    assert str(cf.nftables_conf) == 'sys/nftables.conf'
    sysvar = cf.get_ini_value_from_section('Locations', 'sysvar')
    assert sysvar == 'sys'

    # Verify all etc directories exist (incoming.d, outgoing.d, etc.)
    for name, dirname in cf.etc_dir.items():
        path = cf.etcpath(name)
        assert path.exists(), f'{dirname} doesn\'t exist'

    # Verify all var directories exist (build.d, install.d, etc.)
    for name, dirname in cf.var_dir.items():
        path = cf.varpath(name)
        assert path.exists(), f'{dirname} doesn\'t exist'

    # Verify reference files have been initialized
    # These files are created by init_tests.py and used for test comparisons
    datadir = Path('srcdata')
    reference = ('build_files.json',
                 'firewallreader.pickle',
                 'listreader-records.json',
                 'logreader.json',
                 'patternreader.pickle',
                 'rulesreader.json',
                 'srcdict.json',
                 'step1_files.json')
    for rf in reference:
        rfp = datadir / rf
        if not rfp.exists():
            pytest.fail("Run 'make init' to set up reference files")


def test_fwdb(cf: Config, fwdb_handle: FwDb) -> None:
    """Test firewall database CRUD operations.

    Verifies that the FwDb class correctly:
    - Creates database file
    - Inserts IP records with all required fields
    - Looks up records by IP address
    - Updates existing records

    The test uses TEST-NET IP address 192.0.2.1 (RFC 5737) and cleans
    up the database file after execution for re-entrancy.

    Args:
        cf: Config instance from cf fixture.
        fwdb_handle: Fresh FwDb instance from fwdb_handle fixture.
    """
    # Verify database file was created
    dbfile = cf.varfilepath('firewall')
    assert dbfile.exists(), f'{str(dbfile)} hasn\'t been created'
    fwdb = fwdb_handle

    # Insert a test record
    tnow = fwdb.db_timestamp()
    ip = '192.0.2.1'  # TEST-NET address from RFC 5737
    current = {'ip': '192.0.2.1',
               'pattern': 'testing',
               'incidents': 1,
               'matchcount': 10,
               'first': tnow,
               'last': tnow,
               'ports': '22',
               'useall': False,
               'multiple': False,
               'isdnsbl': False}
    fwdb.insert_ip(current)

    # Verify inserted record can be retrieved
    vals = fwdb.lookup_by_ip(ip)[0]
    assert any(vals)
    for k, v in current.items():
        assert v == vals[k]

    # Test record update
    update = {'incidents': 5,
              'matchcount': 20}

    fwdb.update_ip(update, ip)

    # Verify updated values and unchanged values
    vals = fwdb.lookup_by_ip(ip)[0]
    assert any(vals)
    for k, v in current.items():
        if k in update:
            assert update[k] == vals[k]
        else:
            assert v == vals[k]

    # Clean up database file (make test re-entrant)
    dbfile = cf.varfilepath('firewall')
    assert str(dbfile) == 'sys/firewall.db'
    if dbfile.exists():
        dbfile.unlink()
