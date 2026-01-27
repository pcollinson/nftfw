"""Tests for network file reading and caching.

This module tests the NetReader class, which provides network blacklist
file parsing with JSON caching. The tests verify:
- Parsing of .nets files with CIDR network notation
- Network deduplication and collapsing (overlapping networks merged)
- IPv4 and IPv6 network handling
- IPv6-mapped IPv4 address conversion (::ffff:x.x.x.x format)
- JSON caching mechanism with mtime-based invalidation
- Cache updates when source files are modified
- Cache deletion when source files are removed

The test uses a sample .nets file with various network formats to verify
that NetReader correctly parses, validates, deduplicates, and caches
network ranges for efficient firewall rule generation.

See Also:
    - nftfw.netreader: Network file reading and caching implementation
    - nftfw.config: Configuration management
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from pathlib import Path
import time
import pytest
from nftfw.netreader import NetReader
from .configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config


@pytest.fixture
def cf() -> Config:  # pylint: disable=invalid-name
    """Get config from configsetup.

    Creates a test configuration for network reader testing.

    Returns:
        Config instance configured for testing.

    Raises:
        pytest.fail: If configuration initialization fails.
    """
    # Initialize test configuration
    _cf = config_init()
    return _cf


def test_netreader(cf: Config) -> None:
    """Test network file parsing, caching, and invalidation.

    This test verifies the complete NetReader workflow:
    - Parses .nets files with CIDR notation
    - Collapses overlapping networks (192.0.2.0/23 absorbs /24)
    - Converts IPv6-mapped IPv4 addresses (::ffff:x.x.x.x)
    - Separates IPv4 and IPv6 networks into different records
    - Creates JSON cache for parsed networks
    - Updates cache when source files are modified
    - Deletes cache when source files are removed

    The test validates:
    - Empty records when no files exist
    - Correct parsing of various network formats
    - Network deduplication and collapsing
    - IPv6-mapped IPv4 conversion to standard IPv4
    - Cache file creation and mtime tracking
    - Cache invalidation on file modification
    - Cache deletion on file removal

    Args:
        cf: Config instance from fixture.
    """
    # Sample .nets file with various network formats for testing
    samplefile = """
# should collapse these two
192.0.2.0/23
192.0.2.0/24
2001:db8:fab::/32
# fails
203.0
203.0.117.1-203.0.117.254
# ipv6
2001:DB8:af67::/32
# iplocation uses this format for ipv4
::FFFF:203.13.18.0/120
# should become ipv4 203.0.113.0/24
::ffff:cb00:7100/120
"""

    # Clean up any existing cache and test files
    cachefile = Path('sys/blacknets_cache.json')
    testfile = Path('sys/blacknets.d/te.nets')
    if cachefile.exists():
        cachefile.unlink()
    if testfile.exists():
        testfile.unlink()

    # Test 1: Empty records when no files exist
    nr = NetReader(cf, 'blacknets')
    assert not nr.records, \
        "Expected empty records when no .nets files exist"

    # Test 2: Create test file and verify parsing
    testfile.write_text(samplefile, encoding='utf-8')

    nr = NetReader(cf, 'blacknets')
    # Verify records structure (all ports with ip and ip6 keys)
    assert 'all' in nr.records, \
        "Expected 'all' key in records"
    assert 'ip' in nr.records['all'], \
        "Expected 'ip' key for IPv4 networks"
    assert 'ip6' in nr.records['all'], \
        "Expected 'ip6' key for IPv6 networks"

    # Verify IPv4 networks (should be 3 after deduplication)
    # - 192.0.2.0/23 (collapsed from /23 and /24)
    # - 203.0.113.0/24 (converted from ::ffff:cb00:7100/120)
    # - 203.13.18.0/24 (converted from ::FFFF:203.13.18.0/120)
    assert len(nr.records['all']['ip']) == 3, \
        f"Expected 3 IPv4 networks, got {len(nr.records['all']['ip'])}"
    assert '192.0.2.0/23' in nr.records['all']['ip'], \
        "Expected collapsed network 192.0.2.0/23"
    assert '203.0.113.0/24' in nr.records['all']['ip'], \
        "Expected converted IPv4 network 203.0.113.0/24"
    assert '203.13.18.0/24' in nr.records['all']['ip'], \
        "Expected converted IPv4 network 203.13.18.0/24"

    # Verify IPv6 networks (should be 1 after deduplication)
    # - 2001:db8::/31 (collapsed from 2001:db8:fab::/32 and 2001:DB8:af67::/32)
    assert len(nr.records['all']['ip6']) == 1, \
        f"Expected 1 IPv6 network, got {len(nr.records['all']['ip6'])}"

    # Verify cache file was created
    assert cachefile.exists(), \
        "Expected cache file to be created"

    # Test 3: Cache invalidation on file modification
    # Record original cache mtime
    mtime = cachefile.stat().st_mtime
    # Sleep to ensure mtime will be different
    time.sleep(1)
    # Touch source file to update its mtime
    testfile.touch()
    # Reload NetReader - should regenerate cache
    nr = NetReader(cf, 'blacknets')
    assert mtime != cachefile.stat().st_mtime, \
        "Expected cache to be regenerated after source file modification"

    # Test 4: Cache deletion when source file is removed
    if testfile.exists():
        testfile.unlink()
    nr = NetReader(cf, 'blacknets')
    assert not cachefile.exists(), \
        "Expected cache to be deleted when source file is removed"
