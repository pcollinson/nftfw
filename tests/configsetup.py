"""Configuration helper for nftfw test suite.

This module provides the config_init() function that sets up a Config
instance configured for the test environment. The test environment operates
within the tests/ directory using a simulated system setup.

Test Environment Setup:
    - Creates sys/ directory from data/ if needed (simulated system)
    - Moves srcdata/ from sys/ to tests/ for reference comparisons
    - Configures Config instance with localroot='.' (tests directory)
    - Sets sysvar='sys' to use test directories instead of system paths
    - Enables TESTING flag on Config instance

Directory Structure:
    data/           - Template configuration and test data (read-only)
    sys/            - Simulated system directories (created from data/)
    srcdata/        - Reference data for test comparisons
    newdata/        - Generated output during test runs

Configuration:
    The Config instance is configured to use sys/ as the system directory,
    allowing tests to run without touching actual system files or requiring
    root privileges.

Usage:
    from tests.configsetup import config_init

    def test_something():
        cf = config_init()
        # cf is now configured for testing
        assert cf.get_ini_value_from_section('Locations', 'sysvar') == 'sys'

See Also:
    __init__.py - Package initialization
    init_tests.py - Reference file generation
    nftfw.config - Main Config class
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from pathlib import Path
from shutil import copytree

import pytest

if TYPE_CHECKING:
    from nftfw.config import Config

# Import at runtime (not just for TYPE_CHECKING) since we need to instantiate
# pylint: disable=wrong-import-position
from nftfw import config


def config_init(config_file: str = 'data/config.ini') -> Config:
    """Initialize and return a Config instance configured for testing.

    This function sets up the test environment by:
    1. Creating sys/ directory from data/ if needed
    2. Moving srcdata/ for reference comparisons
    3. Creating a Config instance with test-specific settings
    4. Enabling the TESTING flag

    Args:
        config_file: Path to configuration file relative to tests directory.
            Defaults to 'data/config.ini'.

    Returns:
        Configured Config instance with TESTING=True and sysvar='sys'.

    Raises:
        pytest.fail: If data directory doesn't exist (not in tests directory)
        pytest.fail: If sys directory cannot be created
        pytest.fail: If Config setup results in incorrect sysvar

    Example:
        >>> cf = config_init()
        >>> cf.TESTING
        True
        >>> cf.get_ini_value_from_section('Locations', 'sysvar')
        'sys'
    """
    # Safety check: create sys/ from data/ if needed
    syspath = Path('sys')
    if not syspath.exists():
        datapath = Path('data')
        if not datapath.exists():
            pytest.fail('Cannot find data directory - run from in the tests directory')
        else:
            copytree(datapath, syspath)

    if not syspath.exists():
        pytest.fail('Cannot create sys directory')

    # Move reference results from sys/srcdata to tests/srcdata if needed
    # This preserves test comparison data outside the sys/ directory
    srcdatapath = Path('srcdata')
    if not srcdatapath.exists():
        frompath = syspath / 'srcdata'
        if frompath.exists():
            frompath.rename(srcdatapath)

    # Create Config instance with test-specific settings
    # dosetup=False: don't run setup() yet (need to set ini_file first)
    # localroot='.': use current directory (tests/) as root
    cf = config.Config(dosetup=False, localroot='.')
    cf.set_ini_value_with_section('Locations', 'ini_file', config_file)
    cf.readini()
    cf.setup()

    # Enable testing flag for test-specific behavior
    cf.TESTING = True   # type: ignore[attr-defined]

    # Validation: ensure sysvar is correctly set to 'sys'
    sysvar = cf.get_ini_value_from_section('Locations', 'sysvar')
    if sysvar != 'sys':
        pytest.fail('Incorrect config setup')

    return cf
