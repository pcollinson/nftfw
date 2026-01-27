"""Tests for ListReader class and IP list file processing.

This module tests the ListReader and SetName components of nftfw, focusing on:
- Loading IP address files from blacklist.d directory
- Building srcdict (raw file data indexed by IP address)
- Building records (compiled data indexed by port sets)
- Port validation and normalization (deduplication, sorting, 'all' handling)
- IP address validation (IPv4, IPv6, CIDR notation)
- Set name generation with collision handling

The tests use fixtures to set up the test environment with IP address files
in data/blacklist.d containing various port configurations.

See Also:
    nftfw.listreader: ListReader and SetName class implementations
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import json
from pathlib import Path
import pytest
from nftfw.listreader import ListReader, SetName
from .configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

    IpAddressType = IPv4Address | IPv4Network | IPv6Address | IPv6Network


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
def listrdr(cf: Config) -> ListReader:
    """Get ListReader instance loaded with blacklist data.

    Loads IP address files from the test environment's blacklist.d directory.

    Args:
        cf: Config instance from cf fixture.

    Returns:
        ListReader instance with blacklist data loaded.
    """
    _list = ListReader(cf, 'blacklist')
    return _list


@pytest.fixture
def setname() -> SetName:
    """Get SetName instance for set name generation.

    Returns:
        SetName instance configured for blacklist set naming.
    """
    _sn = SetName('blacklist')
    return _sn


def test_ix(listrdr: ListReader) -> None:
    """Validate srcdict (raw file data) against reference JSON.

    Tests that:
    - Correct number of IP addresses are loaded (5 addresses)
    - All reference IPs exist in loaded data
    - All IP data matches reference
    - No unexpected IPs are loaded
    - File created by test_08 is cleaned up if present

    The srcdict maps IP addresses to their port specifications (raw file contents).

    Args:
        listrdr: ListReader instance from listrdr fixture.
    """
    # Clean up file that might be created by test_08_logreader.py
    newfile = Path('sys/blacklist.d/198.51.100.32.auto')
    if newfile.exists():
        newfile.unlink()

    srcdict = listrdr.srcdict
    assert len(srcdict) == 5, "Should be 5 addresses"

    # Write current srcdict to newdata for comparison
    newpath = Path('newdata/srcdict.json')
    wr = json.dumps(srcdict)
    newpath.write_text(wr, encoding='utf-8')

    # Load reference srcdict
    path = Path('srcdata/srcdict.json')
    contents = path.read_text(encoding='utf-8')
    reference = json.loads(contents)

    # Verify all reference IPs exist and match
    for k, val in reference.items():
        assert k in srcdict, \
            f'Key {k} missing from srcdata, could be software/or data error'
        assert val == srcdict[k], f'Key {k} - data mismatch'

    # Verify no unexpected IPs were loaded
    for k in srcdict:
        assert k in reference, f'Key {k} not in reference set'


def test_records(listrdr: ListReader) -> None:
    """Validate records (compiled data) against reference JSON.

    Tests that:
    - Correct number of port sets are created (3 sets)
    - All reference port sets exist in compiled records
    - IP addresses match for each port set (IPv4 and IPv6 separately)
    - Set names match for each port set
    - No unexpected port sets are created

    The records dict maps port specifications to sets of IPs and nftables set names.

    Args:
        listrdr: ListReader instance from listrdr fixture.
    """
    records = listrdr.records
    assert len(records) == 3, 'Should be 3 set of ports'

    # Write current records to newdata for comparison
    newpath = Path('newdata/listreader-records.json')
    wr = json.dumps(records)
    newpath.write_text(wr, encoding='utf-8')

    # Load reference records
    path = Path('srcdata/listreader-records.json')
    contents = path.read_text(encoding='utf-8')
    reference = json.loads(contents)

    # Verify all reference records exist and match
    for k, val in reference.items():
        assert k in records, \
            f'Key {k} missing from data, could be software/or data error'
        # Check IP addresses (IPv4 or IPv6)
        if 'ip' in val:
            assert set(val['ip']) == set(records[k]['ip']), f'Key {k} ips differ'
        else:
            assert set(val['ip6']) == set(records[k]['ip6']), f'Key {k} ips differ'
        # Check set names
        assert val['name'] == records[k]['name'], f'Key {k} names differ'

    # Verify no unexpected records were created
    for k in records:
        assert k in reference, f'Key {k} not in reference set'


def test_portchk(listrdr: ListReader) -> None:
    """Test port validation and normalization.

    Tests that portcheck() correctly:
    - Returns single port unchanged ("1" -> "1")
    - Deduplicates ports ("100\n100\n100\n100\n50\n" -> "50,100")
    - Handles 'all' keyword (overrides all other ports)
    - Sorts ports numerically ("20, 100 \n36\n100\n50\n" -> "20,36,50,100")
    - Handles comma-separated and newline-separated formats

    Args:
        listrdr: ListReader instance from listrdr fixture.
    """
    # Single port
    src = "1"
    v = listrdr.portcheck(src)
    assert v == "1"

    # Multiple ports with duplicates - should deduplicate and sort
    src = "100\n100\n100\n100\n50\n"
    v = listrdr.portcheck(src)
    assert v == '50,100'

    # 'all' keyword overrides other ports
    src = "100\n100\nall\n100\n50\n"
    v = listrdr.portcheck(src)
    assert v == 'all'

    # Mixed comma and newline separation - should parse, sort, deduplicate
    src = "20, 100 \n36\n100\n50\n"
    v = listrdr.portcheck(src)
    assert v == '20,36,50,100'


def test_validateip(listrdr: ListReader) -> None:
    """Test IP address validation and normalization.

    Tests that validateip() correctly handles:
    - Valid IPv4 addresses (192.0.2.4)
    - Valid IPv4 CIDR networks (192.0.2.4/24)
    - Valid IPv6 CIDR networks (2001:db8::1/64 -> 2001:db8::/64)
    - Invalid IPv4 addresses (192.0.2.500 -> None)
    - Invalid IPv6 addresses (malformed -> None)

    Args:
        listrdr: ListReader instance from listrdr fixture.
    """
    valip = listrdr.validateip

    # Valid IPv4 address
    ip = '192.0.2.4'
    v = valip(ip)
    assert str(v) == ip

    # Valid IPv4 CIDR network
    ip = '192.0.2.4/24'
    v = valip(ip)
    assert ip == '192.0.2.4/24'

    # Valid IPv6 CIDR network (normalizes to network address)
    ip = '2001:db8::1/64'
    v = valip(ip)
    assert str(v) == '2001:db8::/64'

    # Invalid IPv4 address (octet out of range)
    ip = '192.0.2.500'
    v = valip(ip)
    assert v is None

    # Invalid IPv6 address (malformed)
    ip = '2001:db8:ffff:fff:fff:fff:fff'
    v = valip(ip)
    assert v is None


def test_setname(setname: SetName) -> None:
    """Test nftables set name generation with collision handling.

    Tests that SetName.name() generates:
    - Short port lists: "b_25_465" (prefix + ports with underscores)
    - Medium port lists: "b_25_465_587_110" (up to 4 ports)
    - Long port lists with collision sequence numbers:
      - First long list: "b1_25_465_587_11" (sequence 1, truncated)
      - Second long list: "b2_25_465_587_11" (sequence 2, same truncation)

    The 'b' prefix is from 'blacklist'. Set names are limited to 16 chars.

    Args:
        setname: SetName instance from setname fixture.
    """
    # Two ports - fits in name
    v = setname.name('25,465')
    assert v == 'b_25_465'

    # Three ports - fits in name
    v = setname.name('25,465,587')
    assert v == 'b_25_465_587'

    # Four ports - fits in name
    v = setname.name('25,465,587,110')
    assert v == 'b_25_465_587_110'

    # Five ports - too long, gets sequence number 1 and truncation
    v = setname.name('25,465,587,110,995')
    assert v == 'b1_25_465_587_11'

    # Six ports - too long, gets sequence number 2 (collision with previous)
    v = setname.name('25,465,587,110,995,54')
    assert v == 'b2_25_465_587_11'
