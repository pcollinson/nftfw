"""Tests for RulesReader class and rule file processing.

This module tests the RulesReader component of nftfw, focusing on:
- Loading rule files from rule.d and local.d directories
- Validating rule contents against reference data
- Testing local.d override mechanism (local.d overrides rule.d)
- Testing error handling for malformed shell scripts
- Testing rule execution with environment variables

The tests use fixtures to set up the test environment with a standard
set of rule files in data/rules.d and data/local.d.

See Also:
    nftfw.rulesreader: RulesReader class implementation
    nftfw.ruleserr: RulesReaderError exception
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from pathlib import Path
import json
import pytest
from nftfw.ruleserr import RulesReaderError
from nftfw.rulesreader import RulesReader
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
def rulesrdr(cf: Config) -> RulesReader:
    """Get RulesReader instance loaded with test rules.

    Loads rules from the test environment's rule.d and local.d directories.

    Args:
        cf: Config instance from cf fixture.

    Returns:
        RulesReader instance with rules loaded from test directories.

    Raises:
        RulesReaderError: If rule files contain syntax errors or cannot be loaded.
    """
    try:
        _rules = RulesReader(cf)
        # Store in config for internal convention
        cf.rulesreader = _rules
    except RulesReaderError as e:
        pytest.fail(f'RulesReaderError: {str(e)}')
    return _rules


def test_rules(rulesrdr: RulesReader) -> None:
    """Validate loaded rules against reference JSON.

    Tests that:
    - Correct number of rules are loaded (13 rules)
    - All reference rules exist in loaded rules
    - All rule contents match reference data
    - No unexpected rules are loaded
    - local.d override works correctly (drop.sh from local.d, not rule.d)

    The test compares loaded rules against srcdata/rulesreader.json reference
    file and generates newdata/rulesreader.json for comparison.

    Args:
        rulesrdr: RulesReader instance from rulesrdr fixture.
    """
    rdr = rulesrdr
    rules = rdr.rules
    rulestotal = len(rules)

    # Verify expected number of rules (13 standard rules)
    assert rulestotal == 13, 'Should be 13 rules'

    # Write current rules to newdata for comparison
    newpath = Path('newdata/rulesreader.json')
    wr = json.dumps(rules)
    newpath.write_text(wr, encoding='utf-8')

    # Load reference rules
    path = Path('srcdata/rulesreader.json')
    contents = path.read_text(encoding='utf-8')
    reference = json.loads(contents)

    # Verify all reference rules exist and match
    for k, val in reference.items():
        assert rdr.exists(k), \
            f'Key {k} missing from data, could be software/or data error'
        assert val == rdr.contents(k), f'Key {k} - data mismatch'

    # Verify no unexpected rules were loaded
    for k in rules:
        assert k in reference, f'Key {k} not in reference set'

    # Verify local.d override: drop.sh should come from local.d, not rule.d
    rules_dir = rdr.rulesdir
    assert rules_dir is not None, 'rulesdir should not be None after initialization'
    assert rules_dir['drop'].parent.name == 'local.d', \
        'Key drop should originate in local.d'


def test_errors(rulesrdr: RulesReader) -> None:
    """Test error handling for malformed shell scripts.

    Tests that RulesReaderError is raised for:
    - Scripts with stderr output (bad1)
    - Scripts with syntax errors (bad2 - missing fi)
    - Scripts with invalid exit codes (bad3 - exit 127)

    Args:
        rulesrdr: RulesReader instance from rulesrdr fixture.
    """
    rdr = rulesrdr

    # Define three types of malformed scripts
    bads = {
        'bad1': '(echo fail to stderr 1>&2) \n\n',  # stderr output
        'bad2': 'V=6\nif $V = 6; then \n echo missing fi ; \n\n',  # syntax error
        'bad3': 'exit(127)'  # invalid exit code
    }

    # Inject bad scripts into rules store
    assert rdr.rules_store is not None, 'rules_store should not be None after initialization'
    for k, v in bads.items():
        rdr.rules_store[k] = v

    # Verify each bad script raises RulesReaderError
    env: dict[str, str] = {}
    for k in bads:
        try:
            rdr.execute(k, env)
            pytest.fail('Should fail')
        except RulesReaderError as e:
            # Expected error - verify exception is not None
            assert e is not None, f'RulesReaderError for {k}: {str(e)}'
