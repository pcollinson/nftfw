"""Tests for firewall management workflow (fwmanage module).

This module tests the fwmanage component of nftfw, focusing on:
- Step 1: Loading firewall configuration files (incoming, outgoing, whitelist, blacklist)
- Step 2: Building nftables rule files in build.d directory
- Step 4: Comparing build.d with install.d and determining installation type:
  - Full install: Complete firewall reload needed
  - Set-only install: Only nftables set updates needed (list of set names)
  - None: No changes needed

The tests validate file generation, hash comparison, and installation logic
without actually loading rules into nftables (test environment limitation).

Helper functions support file existence checking, cleanup, and modification
for testing set-only update detection.

See Also:
    nftfw.fwmanage: Firewall management functions (step1-8)
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
import json
import hashlib
from pathlib import Path
import pytest
from nftfw import fwmanage
from .configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config


@pytest.fixture
def cf() -> Config:  # pylint: disable=invalid-name
    """Get config from configsetup.

    Returns:
        Configured Config instance for testing with test environment setup.

    Raises:
        pytest.fail: If configuration initialization fails.
    """
    _cf = config_init()
    return _cf


def test_step1(cf: Config) -> None:
    """Test step 1: Load firewall configuration files.

    Tests that fwmanage.step1() correctly:
    - Loads all firewall configuration files
    - Returns dict mapping file names to their info
    - Matches reference data (srcdata/step1_files.json)
    - No unexpected files are loaded

    Generates newdata/step1_files.json for comparison.

    Args:
        cf: Config instance from cf fixture.
    """
    files = fwmanage.step1(cf)

    # Write current files dict to newdata for comparison
    newpath = Path('newdata/step1_files.json')
    wr = json.dumps(files)
    newpath.write_text(wr, encoding='utf-8')

    # Load reference files
    path = Path('srcdata/step1_files.json')
    contents = path.read_text(encoding='utf-8')
    reference = json.loads(contents)

    # Verify all reference files exist and match
    for k, val in reference.items():
        assert k in files, \
            f'Key {k} missing from srcdata, could be software/or data error'
        assert val == files[k], f'Key {k} - data mismatch'

    # Verify no unexpected files were loaded
    for k in files:
        assert k in reference, f'Key {k} not in reference set'


def test_step2(cf: Config) -> None:
    """Test step 2: Build nftables rule files in build.d.

    Tests that fwmanage.step2() correctly:
    - Creates build.d directory
    - Generates all expected nftables rule files
    - File contents match reference hashes (srcdata/build_files.json)

    Generates newdata/build_files.json with SHA-256 hashes for comparison.

    Args:
        cf: Config instance from cf fixture.
    """
    # Load files from step1 reference (needed for step2)
    path = Path('srcdata/step1_files.json')
    contents = path.read_text(encoding='utf-8')
    files = json.loads(contents)

    # Verify build path
    buildpath = cf.varpath('build')
    assert str(buildpath) == 'sys/build.d'

    # Run step2 to build rule files
    fwmanage.step2(cf, files, buildpath)

    # Generate hashes for all built files
    hashdict = {}
    for f in files:
        p = buildpath / f
        assert p.exists(), f'File {f} not created in build.d'
        c = p.read_text(encoding='utf-8')
        h = hashlib.sha256(c.encode())
        hashdict[f] = h.hexdigest()

    # Write current hashes to newdata for comparison
    newpath = Path('newdata/build_files.json')
    wr = json.dumps(hashdict)
    newpath.write_text(wr, encoding='utf-8')

    # Load reference hashes and verify all files match
    path = Path('srcdata/build_files.json')
    co = path.read_text(encoding='utf-8')
    hashdict = json.loads(co)
    for f in files:
        p = buildpath / f
        c = p.read_text(encoding='utf-8')
        h = hashlib.sha256(c.encode())
        assert h.hexdigest() == hashdict[f], \
            f'File {f} hash mismatch'


def test_step4(cf: Config) -> None:
    """Test step 4: Compare build.d with install.d and determine update type.

    Tests that fwmanage.step4() correctly determines:
    - Full install: When install.d is empty or main files changed
    - Set-only install: When only *_sets.nft files changed (returns list)
    - No install: When build.d matches install.d exactly (returns None)

    Tests all three scenarios:
    1. Empty install.d → full install
    2. Modify blacklist_sets.nft → ['blacklist'] (set-only)
    3. Modify incoming.nft → full install
    4. Modify outgoing.nft → full install

    Args:
        cf: Config instance from cf fixture.
    """
    # Verify paths
    buildpath = cf.varpath('build')
    assert str(buildpath) == 'sys/build.d'
    installpath = cf.varpath('install')
    assert str(installpath) == 'sys/install.d'

    # Load reference hashes and file list
    path = Path('srcdata/build_files.json')
    co = path.read_text(encoding='utf-8')
    hashdict = json.loads(co)
    files = hashdict.keys()

    # Ensure build.d files exist (may need to run step2 if standalone)
    if not have_files(files, buildpath):
        test_step2(cf)

    assert have_files(files, buildpath), 'Build files missing'

    # Start with empty install.d
    remove_files(files, installpath)

    # Test 1: Empty install.d should trigger full install
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result == 'full', 'Expected full install for empty install.d'
    assert have_files(files, installpath), 'Install files not created'

    # Test 2: No changes should return None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None, 'Expected None when no changes'

    # Test 3: Modify blacklist_sets.nft → set-only install
    append_comment(installpath, 'blacklist_sets.nft')
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert isinstance(result, list), 'Expected list for set-only install'
    assert any(result), 'Expected non-empty list'
    assert len(result) == 1, 'Expected single set name'
    assert result[0] == 'blacklist', 'Expected blacklist set'

    # File should be fixed now, so next run returns None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None, 'Expected None after set-only fix'

    # Test 4: Modify incoming.nft → full install
    append_comment(installpath, 'incoming.nft')
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result == 'full', 'Expected full install for incoming.nft change'
    assert have_files(files, installpath), 'Install files not updated'

    # File should be fixed now, so next run returns None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None, 'Expected None after full install fix'

    # Test 5: Modify outgoing.nft → full install
    append_comment(installpath, 'outgoing.nft')
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result == 'full', 'Expected full install for outgoing.nft change'
    assert have_files(files, installpath), 'Install files not updated'

    # File should be fixed now, so next run returns None
    result = fwmanage.step4(cf, buildpath, installpath, hashdict)
    assert result is None, 'Expected None after full install fix'

    # Clean up test files
    remove_files(files, installpath)
    remove_files(files, buildpath)


def have_files(files: Any, path: Path) -> bool:
    """Check if all expected files exist in directory.

    Checks for all files in the files collection plus nftfw_init.nft.

    Args:
        files: Collection of file names to check (dict keys or list).
        path: Directory path to check for files.

    Returns:
        True if all files exist, False if any are missing.
    """
    for f in files:
        fpath = path / f
        if not fpath.exists():
            return False
    # Also check for init file
    fpath = path / 'nftfw_init.nft'
    if not fpath.exists():
        return False
    return True


def remove_files(files: Any, path: Path) -> None:
    """Remove all files from directory.

    Removes all files in the files collection plus nftfw_init.nft.

    Args:
        files: Collection of file names to remove (dict keys or list).
        path: Directory path to remove files from.
    """
    for f in files:
        fpath = path / f
        if fpath.exists():
            fpath.unlink()
    # Also remove init file
    fpath = path / 'nftfw_init.nft'
    if fpath.exists():
        fpath.unlink()


def append_comment(path: Path, file: str) -> None:
    """Append a comment to a file to simulate changes.

    Used to test set-only update detection by modifying files.

    Args:
        path: Directory containing the file.
        file: Name of file to modify.
    """
    pa = path / file
    contents = pa.read_text(encoding='utf-8')
    contents += '\n# Comment added\n'
    pa.write_text(contents, encoding='utf-8')
