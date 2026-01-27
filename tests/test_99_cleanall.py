"""Test cleanup for re-entrancy.

This module provides a cleanup test that runs last in the test suite
to remove all working directories and generated test data. This ensures
that the test suite is re-entrant and can be run multiple times without
interference from previous runs.

The test removes:
- srcdata/ directory and all .json and .pickle files within it
- newdata/ directory and all .json and .pickle files within it
- sys/ directory tree (contains databases, cache files, and working data)

This test is numbered 99 to ensure it runs last in the pytest execution
order, allowing it to clean up after all other tests have completed.

See Also:
    - init_tests.py: Creates reference files and initial test data
    - configsetup.py: Sets up test environment directories
"""
from __future__ import annotations

from pathlib import Path
from shutil import rmtree


def test_clean() -> None:
    """Clean up test working directories for re-entrancy.

    This test removes all working directories created during test execution
    to ensure the test suite can be run multiple times without conflicts.

    The cleanup process:
    1. Removes all .json files from srcdata/ and newdata/ directories
    2. Removes all .pickle files from srcdata/ and newdata/ directories
    3. Removes the empty srcdata/ and newdata/ directories
    4. Removes the entire sys/ directory tree (databases, cache, etc.)

    This test should always run last (hence the 99 prefix) to clean up
    after all other tests have completed successfully.
    """
    # Clean srcdata and newdata directories
    for deldir in ["srcdata", "newdata"]:
        path = Path(deldir)
        # Remove all JSON reference files
        for name in path.glob("*.json"):
            name.unlink()
        # Remove all pickle reference files
        for name in path.glob("*.pickle"):
            name.unlink()
        # Remove the now-empty directory
        path.rmdir()

    # Remove entire sys directory tree (databases, cache, working files)
    rmtree("sys")
