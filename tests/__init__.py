"""nftfw test suite package initialization.

This module sets up the test environment for the nftfw test suite by:
- Changing to the test directory (tests run from this location)
- Adding the test directory to Python path for local imports
- Adding the nftfw package directory to Python path for package imports
- Enforcing Python version requirement (3.9+)
- Initializing test reference files via init_tests module

Directory Structure Created:
    sys/        - Simulated system directories (config, working files)
    srcdata/    - Reference data for test comparisons
    newdata/    - Generated output during test runs

Test Environment:
    The test suite operates entirely within the tests/ directory using
    test data from tests/data/ to create a working environment in sys/.
    Individual tests are designed to be re-entrant, cleaning up after
    themselves to maintain consistent state.

Python Version:
    Requires Python 3.9+ for modern type hint syntax and features.

Usage:
    Tests are run via pytest from the tests/ directory:
        $ cd tests
        $ make                    # Run all tests
        $ make init              # Initialize reference files
        $ pytest-3 test_01_config.py  # Run specific test

See Also:
    configsetup.py - Configuration helper for test environment
    init_tests.py - Reference file generation
    README.txt - Detailed test documentation
"""
from __future__ import annotations

import os
import sys

# Get the path of this file (tests directory)
install: str = os.path.dirname(__file__)  # pylint: disable=invalid-name

# Change into the test directory - tests are designed to run here
os.chdir(install)

# Add test directory to path for local imports
sys.path.insert(0, install)

# Get path to nftfw module and add it to path
NFTFWPATH: str = os.path.abspath(install + '/../nftfw')
sys.path.insert(0, NFTFWPATH)

# Check Python version requirement (3.9+)
# The test suite requires Python 3.9+ for modern type hint syntax
if sys.version_info < (3, 9):
    sys.stderr.write('nftfw test suite requires Python 3.9 or later\n')
    sys.exit(1)

# Import and run test initialization
# This must come after path setup, hence the wrong-import-position disable
# pylint: disable=wrong-import-position
from . import init_tests
init_tests.init_tests()
