"""Tests for pattern file reading and parsing.

This module tests the patternreader component of nftfw, focusing on:
- Loading all pattern files from patterns.d directory
- Parsing pattern file format (file=, ports=, regex lines)
- Compiling regex patterns with __IP__ placeholder substitution
- Port specification validation and normalization
- Pattern filtering (selected_pattern_file option)
- Error handling (missing file=, invalid regex, no patterns)

The tests use pickle for reference data since compiled regex objects
cannot be serialized to JSON.

See Also:
    nftfw.patternreader: pattern_reader and parsefile functions
    nftfw.logreader: Uses patterns for log scanning
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
import pickle
import pytest

from nftfw.patternreader import pattern_reader
from nftfw.patternreader import parsefile
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


def test_patternreader(cf: Config) -> None:
    """Test loading and parsing all pattern files.

    Tests that pattern_reader() correctly:
    - Loads all pattern files from patterns.d directory
    - Returns dict mapping pattern names to pattern info lists
    - Each pattern info dict contains: pattern, file, ports, regex
    - All patterns match reference data (srcdata/patternreader.pickle)
    - Regex patterns are properly compiled

    Generates newdata/patternreader.pickle for comparison.

    Args:
        cf: Config instance from cf fixture.
    """
    patterns = pattern_reader(cf)

    # Save patterns as pickle (can't use JSON due to compiled regex objects)
    # Data format: { pattern_name: [{ pattern, file, ports, regex }, ...] }
    with open('newdata/patternreader.pickle', 'wb') as file:
        pickle.dump(patterns, file)

    # Verify all patterns have 'pattern' key
    for key, val in patterns.items():
        for lines in val:
            assert 'pattern' in lines, \
                f'Pattern {key} missing "pattern" key'

    # Sort pattern lists by 'pattern' key for consistent comparison
    patsort: dict[str, Any] = {
        key: sorted(val, key=lambda x: x['pattern'])
        for key, val in patterns.items()
    }

    # Load reference patterns
    with open('srcdata/patternreader.pickle', 'rb') as file:
        reference = pickle.load(file)

    # Sort reference patterns same way
    refsort: dict[str, Any] = {
        key: sorted(val, key=lambda x: x['pattern'])
        for key, val in reference.items()
    }

    # Verify all reference patterns exist and match
    for key, val in refsort.items():
        assert key in patsort, f'Pattern {key} missing from loaded patterns'
        # Using range+index to match reference indexing
        for i in range(len(val)):  # pylint: disable=consider-using-enumerate
            refval = val[i]
            patval = patsort[key][i]
            # Check standard fields
            for vkey in ('pattern', 'ports', 'file'):
                if vkey in refval:
                    assert vkey in patval, \
                        f'Pattern {key}[{i}] missing {vkey}'
                    assert refval[vkey] == patval[vkey], \
                        f'Pattern {key}[{i}] {vkey} mismatch'
            # Check regex list (compiled patterns)
            if 'regex' in refval:
                assert 'regex' in patval, \
                    f'Pattern {key}[{i}] missing regex'
                for reix in range(len(refval['regex'])):
                    assert refval['regex'][reix] == patval['regex'][reix], \
                        f'Pattern {key}[{i}] regex[{reix}] mismatch'

    # Verify no unexpected patterns were loaded
    for key in patsort:
        assert key in refsort, f'Unexpected pattern {key} in loaded patterns'


def test_parsefile(cf: Config) -> None:
    """Test pattern file parsing with various inputs.

    Tests that parsefile() correctly handles:
    - Empty pattern file → None
    - Valid pattern (file=, ports=, __IP__) → pattern dict
    - Pattern filtering (selected_pattern_file) → None when not selected
    - Missing ports= line → defaults to 'all'
    - Missing file= line → None (required)
    - No regex lines → None (required)
    - Invalid regex syntax → None (catches compilation errors)
    - Regex matching IPv4 and IPv6 addresses

    Args:
        cf: Config instance from cf fixture.
    """
    # Empty pattern returns None
    assert parsefile(cf, 'testname', '') is None, \
        'Empty pattern should return None'

    # Valid pattern with file, ports, and regex
    testdata_lines = ['file = sys/testlogfile.log',
                      'ports = 300,100,200,300',
                      '__IP__']
    testdata = '\n'.join(testdata_lines)

    ret = parsefile(cf, 'testlive', testdata)
    assert ret is not None, 'Valid pattern should return dict'
    assert ret['file'] == 'sys/testlogfile.log', 'File path mismatch'
    assert ret['ports'] == '300,100,200,300', 'Ports mismatch'
    assert 'regex' in ret, 'Missing regex list'
    # Test that compiled regex matches IPv4 and IPv6
    for re in ret['regex']:
        assert re.match('198.51.100.128'), 'Regex should match IPv4'
        assert re.match('2001:db8:fab::8'), 'Regex should match IPv6'

    # Pattern filtering: selected_pattern_file filters out non-matching patterns
    cf.selected_pattern_file = 'apache2'
    ret = parsefile(cf, 'testlive', testdata)
    assert ret is None, 'Non-selected pattern should be filtered'

    # Clear filter
    cf.selected_pattern_file = None
    ret = parsefile(cf, 'testlive', testdata)
    assert ret is not None, 'Pattern should be loaded when filter cleared'

    # Missing ports line defaults to 'all'
    td = [testdata_lines[0], testdata_lines[2]]
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is not None, 'Pattern without ports should use default'
    assert ret['ports'] == 'all', 'Default ports should be "all"'

    # Missing file line returns None (file= is required)
    td = [testdata[1], testdata[2]]
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is None, 'Pattern without file= should return None'

    # No regex lines returns None (at least one regex required)
    td = [testdata[0], testdata[1]]
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is None, 'Pattern without regex should return None'

    # Invalid regex syntax returns None
    td = [testdata[0], testdata[1], r'__IP__ [a-z']  # Unclosed bracket
    ret = parsefile(cf, 'testlive', "\n".join(td))
    assert ret is None, 'Pattern with invalid regex should return None'
