"""Tests for FirewallReader class and firewall rule file processing.

This module tests the FirewallReader component of nftfw, focusing on:
- Loading firewall rule files from incoming.d directory
- Parsing rule file format (nn-action filename pattern)
- Validating action names against RulesReader rules
- Processing IP addresses and CIDR networks (IPv4 and IPv6)
- Processing port numbers and service name lookups
- DNS hostname resolution with socket.getaddrinfo()
- Building record structures with all parsed data

The tests use fixtures to set up the test environment with RulesReader
for rule validation and FirewallReader for parsing incoming.d files.

See Also:
    nftfw.firewallreader: FirewallReader class implementation
    nftfw.rulesreader: RulesReader class for rule validation
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import pickle
import pytest
from nftfw.rulesreader import RulesReader
from nftfw.ruleserr import RulesReaderError
from nftfw.firewallreader import FirewallReader
from .configsetup import config_init

if TYPE_CHECKING:
    from nftfw.config import Config


@pytest.fixture
def cf() -> Config:  # pylint: disable=invalid-name
    """Get config from configsetup with RulesReader initialized.

    Loads rules from test environment and stores RulesReader in config
    for FirewallReader to use for action validation.

    Returns:
        Configured Config instance with rulesreader attribute set.

    Raises:
        pytest.fail: If configuration initialization or rule loading fails.
    """
    _cf = config_init()
    try:
        _rules = RulesReader(_cf)
        # Store in config for internal convention (used by FirewallReader)
        _cf.rulesreader = _rules
    except RulesReaderError as e:
        pytest.fail(f'RulesReaderError: {str(e)}')
    return _cf


@pytest.fixture
def firewallreader(cf: Config) -> FirewallReader:
    """Get FirewallReader instance loaded with incoming firewall rules.

    Loads firewall rule files from the test environment's incoming.d directory.

    Args:
        cf: Config instance from cf fixture with rulesreader initialized.

    Returns:
        FirewallReader instance with incoming rules loaded and parsed.
    """
    _fr = FirewallReader(cf, 'incoming')
    return _fr


def test_reader(firewallreader: FirewallReader) -> None:
    """Validate loaded firewall records against reference pickle.

    Tests that:
    - Correct number of records are loaded (16 records)
    - All record fields match reference data:
      - baseaction: Base action name (before port validation)
      - action: Validated action name (from RulesReader)
      - ports: Port numbers or service names
      - content: IP addresses/networks (raw from file)
      - ip: Parsed IPv4 addresses and networks
      - ip6: Parsed IPv6 addresses and networks

    The test compares loaded records against srcdata/firewallreader.pickle
    reference file and generates newdata/firewallreader.pickle for comparison.

    Args:
        firewallreader: FirewallReader instance from firewallreader fixture.
    """
    records = firewallreader.records
    assert len(records) == 16, "Should be 16 records"

    # Write current records to newdata for comparison
    with open('newdata/firewallreader.pickle', 'wb') as file:
        pickle.dump(records, file)

    # Load reference records
    with open('srcdata/firewallreader.pickle', 'rb') as file:
        reference = pickle.load(file)

    # Verify all records match reference
    # Using range+index instead of enumerate to match reference indexing
    for i in range(len(reference)):  # pylint: disable=consider-using-enumerate
        ref = reference[i]
        rec = records[i]
        # Check each field that exists in reference
        for ix in ['baseaction', 'action', 'ports', 'content', 'ip', 'ip6']:
            if ix in ref:
                # Dynamic TypedDict access is legitimate here for testing
                assert rec[ix] == ref[ix], (  # type: ignore[literal-required]
                    f'Record {i}, field {ix} mismatch')  # type: ignore[literal-required]
