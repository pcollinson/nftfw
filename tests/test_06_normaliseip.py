"""Tests for NormaliseAddress class and IP address normalization.

This module tests the NormaliseAddress component of nftfw, focusing on:
- IPv4 address validation and normalization
- IPv6 address validation and normalization (default /112 network)
- CIDR network notation handling (network address extraction)
- Whitelist callback integration (filtering whitelisted IPs)
- Invalid address rejection (malformed IPs return None)
- Test mode vs production mode behavior

The tests use fixtures to set up NormaliseAddress with and without
whitelist integration via WhiteListCheck callback.

See Also:
    nftfw.normaliseaddress: NormaliseAddress class implementation
    nftfw.whitelistcheck: WhiteListCheck class for whitelist callback
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from pathlib import Path
import pytest
from nftfw.normaliseaddress import NormaliseAddress
from nftfw.whitelistcheck import WhiteListCheck
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


@pytest.fixture
def norm(cf: Config) -> NormaliseAddress:
    """Get NormaliseAddress instance without whitelist callback.

    Creates instance in test mode for basic IP normalization.

    Args:
        cf: Config instance from cf fixture.

    Returns:
        NormaliseAddress instance for IP validation and normalization.
    """
    _na = NormaliseAddress(cf, 'test package')
    return _na


@pytest.fixture
def normwhite(cf: Config) -> NormaliseAddress:
    """Get NormaliseAddress instance with whitelist callback enabled.

    Creates instance with WhiteListCheck callback registered in config
    for testing whitelist filtering functionality.

    Args:
        cf: Config instance from cf fixture.

    Returns:
        NormaliseAddress instance with is_white_fn callback configured.
    """
    _na = NormaliseAddress(cf, 'test package')
    _wh = WhiteListCheck(cf)
    # Register whitelist check function in config (dynamic attribute for testing)
    cf.is_white_fn = _wh.is_white  # type: ignore[attr-defined]
    return _na


def test_basic(norm: NormaliseAddress) -> None:
    """Test basic IP address normalization without modification.

    Tests that valid IPs are returned unchanged:
    - IPv4 addresses: 192.0.2.5, 198.51.100.128, etc.
    - IPv6 network with /112: 2001:db8:fab:11::1:0/112
    - No network conversion for already-complete addresses

    Args:
        norm: NormaliseAddress instance from norm fixture.
    """
    iplist = ('192.0.2.5', '198.51.100.128',
              '198.51.100.5', '2001:db8:fab:11::1:0/112',
              '203.0.113.7')
    for ip in iplist:
        res = norm.normal(ip)
        assert res == ip, f'IP {ip} should be unchanged'


def test_white(cf: Config, normwhite: NormaliseAddress) -> None:
    """Test whitelist filtering functionality.

    Tests that whitelisted IPs are filtered out (return None):
    - Whitelist file exists: data/whitelist.d/198.51.100.254
    - IP matches whitelist
    - normal() returns None when whitelist callback provided

    Args:
        cf: Config instance from cf fixture.
        normwhite: NormaliseAddress instance with whitelist callback.
    """
    # Verify whitelist file exists
    path = Path('data/whitelist.d/198.51.100.254')
    assert path.exists(), 'Whitelist file should exist'

    # Test that whitelisted IP is filtered (returns None)
    res = normwhite.normal('198.51.100.254', cf.is_white_fn)  # type: ignore[attr-defined]
    assert res is None, 'Whitelisted IP should be filtered'


def test_networknorm(norm: NormaliseAddress) -> None:
    """Test IP network normalization and CIDR handling.

    Tests that IPs are converted to network notation:
    - IPv6 host → /112 network: 2001:db8:fab:11::1:234 → 2001:db8:fab:11::1:0/112
    - IPv4 CIDR → network address: 198.51.100.30/24 → 198.51.100.0/24

    Args:
        norm: NormaliseAddress instance from norm fixture.
    """
    # IPv6 host address converts to /112 network (default)
    ip = '2001:db8:fab:11::1:234'
    res = norm.normal(ip)
    assert res == '2001:db8:fab:11::1:0/112', \
        'IPv6 should convert to /112 network'

    # IPv4 CIDR notation extracts network address
    ip = '198.51.100.30/24'
    res = norm.normal(ip)
    assert res == '198.51.100.0/24', \
        'IPv4 CIDR should extract network address'


def test_bad(norm: NormaliseAddress) -> None:
    """Test rejection of invalid IP addresses.

    Tests that malformed IPs return None:
    - Incomplete IPv4: 192.0.2 (missing octet)
    - Invalid format: 192.0.2-255 (dash notation)
    - Incomplete IPv6: 2001:db8:fab (missing segments)

    Args:
        norm: NormaliseAddress instance from norm fixture.
    """
    iplist = ('192.0.2', '192.0.2-255', '2001:db8:fab')

    for ip in iplist:
        res = norm.normal(ip)
        assert res is None, f'Invalid IP {ip} should return None'
