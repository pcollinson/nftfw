"""Incremental log file scanning with pattern matching for blacklist detection.

This module provides the log_reader function and supporting utilities that scan
system log files for patterns indicating malicious activity. It uses incremental
scanning (tracking file positions) and regex pattern matching to efficiently
identify IP addresses that should be blacklisted.

Key Features
------------
- Incremental log scanning (resume from last position using FileposDb)
- File rotation detection via MD5 hash of first line
- Pattern-based IP address extraction using compiled regexes
- Port aggregation across multiple pattern matches
- Incident counting (same IP matching different patterns)
- Test mode support for pattern validation

Architecture
------------
The scanning pipeline has three levels:

1. log_reader(): Top-level function
   - Reads patterns from pattern files
   - Calls one_log_reader() for each log file
   - Aggregates results across all log files
   - Counts incidents (same IP from different patterns)

2. one_log_reader(): Per-file processing
   - Manages file position tracking with FileposDb
   - Detects file rotation via first-line MD5 hash
   - Calls scanlog() to process file content
   - Updates position database after scanning

3. scanlog(): Line-by-line matching
   - Applies all regex patterns to each line
   - Extracts IP addresses from matches
   - Aggregates ports and match counts per IP

Data Structure
--------------
The returned data structure maps IP addresses to detection metadata::

    {
        '192.0.2.1': {
            'ports': [22, 80],  # or 'all', 'test', 'update'
            'pattern': 'ssh-brute',
            'matchcount': 5,
            'incidents': 2  # Added by log_reader, not scanlog
        },
        '192.0.2.2': {
            'ports': 'all',
            'pattern': 'port-scan',
            'matchcount': 1,
            'incidents': 1
        }
    }

Usage Example
-------------
    from .config import Config
    from .logreader import log_reader

    # Initialize configuration
    cf = Config()
    cf.readini()
    cf.setup()

    # Scan logs for blacklist candidates
    results = log_reader(cf, update_position=True)

    # Process results
    for ip, info in results.items():
        if info['matchcount'] >= 5:  # Threshold check
            print(f"Blacklist {ip}: {info['matchcount']} matches on {info['pattern']}")

    # Test a specific pattern without updating positions
    cf.selected_pattern_file = 'ssh-brute'
    cf.selected_pattern_is_test = True
    test_results = log_reader(cf, update_position=False)

See Also
--------
fileposdb.FileposDb : Database for tracking file positions
patternreader : Module for reading and parsing pattern files
blacklist : Module that uses log_reader results for blacklisting
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, TextIO
from pathlib import Path
from hashlib import md5
import re
import logging
from .fileposdb import FileposDb
from .patternreader import pattern_reader

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

# Type aliases for complex data structures
IpMatchDict = dict[str, Any]  # {'ports': list|str, 'pattern': str, 'matchcount': int, ...}
PatternInfo = dict[str, Any]  # {'pattern': str, 'ports': str, 'file': str, 'regex': list}


def log_reader(cf: Config, update_position: bool = True) -> dict[str, IpMatchDict]:
    """Read and scan log files based on patterns, returning matched IP addresses.

    This is the main entry point for log scanning. It reads pattern definitions,
    scans all associated log files, and aggregates matches by IP address. The
    'incidents' count tracks how many different patterns matched the same IP.

    Args:
        cf: Config instance with pattern directory and settings
        update_position: If True, update file positions in database after scanning.
                        Set to False for testing to avoid polluting position tracking.

    Returns:
        Dictionary mapping IP addresses to match information::

            {
                'ip_address': {
                    'ports': [22, 80] or 'all' or 'test' or 'update',
                    'pattern': 'pattern_name',
                    'matchcount': 5,
                    'incidents': 2  # Number of different patterns that matched
                }
            }

        Returns empty dict if no matches or if selected pattern not found.

    Example:
        >>> cf = Config()
        >>> results = log_reader(cf)
        >>> for ip, info in results.items():
        ...     print(f"{ip}: {info['matchcount']} matches, {info['incidents']} incidents")

        Test a specific pattern::

            >>> cf.selected_pattern_file = 'ssh-brute'
            >>> cf.selected_pattern_is_test = True
            >>> results = log_reader(cf, update_position=False)

    Note:
        - If cf.selected_pattern_file is set and not found, logs error and returns empty dict
        - Test patterns (*.test files) that find no matches trigger error logging
        - The 'incidents' field is added by this function based on cross-pattern matching
    """
    out: dict[str, IpMatchDict] = {}
    # Are we testing? If so selected_pattern_file is set
    have_pattern = cf.selected_pattern_file is not None

    action = pattern_reader(cf)

    if have_pattern and not any(action):
        log.error('Requested pattern %s pattern not found', cf.selected_pattern_file)
        return out

    for filename, patinfo in action.items():
        res = one_log_reader(cf, filename, patinfo, update_position)
        for ip, info in res.items():
            if ip not in out:
                info['incidents'] = 1
                out[ip] = info
            else:
                out[ip]['incidents'] += 1
                out[ip]['matchcount'] += info['matchcount']
                out[ip]['ports'] = portmerge(out[ip]['ports'], info['ports'])
                # preserve different pattern names
                out[ip]['pattern'] = patternmerge(out[ip]['pattern'], info['pattern'])

    # extra logging for test files
    if have_pattern \
       and cf.selected_pattern_is_test \
       and not any(out):
        log.error('No matches found in %s', cf.selected_pattern_file)

    return out

def patternmerge(arga:str, argb:str)->str:
    """ Concatenate two comma separated strings
        removing any duplicate value,
        args may be single entries
        return a comma separated string
    """

    if arga == argb:
        return arga
    if arga == '':
        return argb
    if argb == '':
        return arga

    sa = set(arga.split(","))
    sb = set(argb.split(","))

    # don't want spaces
    # there shouldn't be any, but just in case
    sac = {el.strip() for el in sa}
    sbc = {el.strip() for el in sb}

    # use union to remove duplicate entries
    return ",".join(sorted(sac | sbc))


def one_log_reader(
    cf: Config, filename: str,
    patinfo: list[PatternInfo], update_position: bool = True) -> dict[str, IpMatchDict]:
    """Process a single log file with pattern matching and position tracking.

    Uses FileposDb to remember the last read position and MD5 hash of the first
    line. If the file has been rotated (first line changed), starts from beginning.
    Otherwise resumes from last position for incremental scanning.

    The first-line hashing technique is borrowed from Symbiosis firewall.

    Args:
        cf: Config instance
        filename: Full path to log file to scan
        patinfo: List of pattern dictionaries, each containing:
                 - pattern: str (pattern name for reference)
                 - ports: str (comma-separated ports or 'all')
                 - file: str (log file path)
                 - regex: list[compiled regex] (patterns to match)
        update_position: If False, don't update file positions (for testing)

    Returns:
        Dictionary mapping IP addresses to match information::

            {
                'ip_address': {
                    'ports': [22, 80] or 'all' or 'test' or 'update',
                    'pattern': 'pattern_name',
                    'matchcount': 5
                }
            }

        Returns empty dict if file missing, empty, or no matches.

    Example:
        >>> patinfo = [{
        ...     'pattern': 'ssh-brute',
        ...     'ports': '22',
        ...     'file': '/var/log/auth.log',
        ...     'regex': [compiled_regex]
        ... }]
        >>> results = one_log_reader(cf, '/var/log/auth.log', patinfo)

    Note:
        - Test patterns automatically disable position updates
        - File rotation detected by comparing MD5 of first line
        - Missing or empty log files trigger error logging for test patterns
        - Handles file truncation (when log rotates and new file is smaller)
    """
    # pylint: disable=too-many-locals

    # support for the single pattern option
    have_pattern = cf.selected_pattern_file is not None
    is_test = have_pattern and cf.selected_pattern_is_test
    # don't update log file positions for test files
    if is_test:
        update_position = False

    path = Path(filename)
    if not path.exists():
        # complain if this is a test using selected_pattern_file and the
        # file doesn't exist
        if have_pattern:
            log.error('Pattern %s requested, log file is missing', cf.selected_pattern_file)
        return {}

    fsize = path.stat().st_size

    # bail out if nothing in the file
    if fsize == 0:
        # complain if this is a test using selected_pattern_file and the
        # log file is empty
        if have_pattern:
            log.error('Pattern %s requested, empty log file', cf.selected_pattern_file)
        return {}

    # get lastseek position and previous linesig
    # if no entry will be (0, None)
    db = FileposDb(cf)
    lastseek, linesig = db.getfileinfo(filename)
    db.close()

    # Ignore any coding errors
    with open(filename, 'r', errors='ignore', encoding='utf-8') as fhandle:
        # See if this file is new
        line1 = fhandle.readline(2048)
        newsig = md5(line1.encode()).hexdigest()

        # start at zero
        # if unknown before now, or sigs are different
        # or we have a pattern name
        if not linesig \
           or linesig != newsig \
           or is_test:
            # put the file cursor back
            fhandle.seek(0, 0)
        elif lastseek > 0:
            # likely to be common situation
            # has file got shorter - use min to handle truncation
            lastseek = min(lastseek, fsize)
            fhandle.seek(lastseek, 0)

        out = scanlog(patinfo, fhandle)

        if update_position:
            offset = fhandle.tell()
            db = FileposDb(cf)
            db.setfileinfo(filename, offset, newsig)
            db.close()

    return out


def scanlog(allpatinfo: list[PatternInfo], lines: TextIO) -> dict[str, IpMatchDict]:
    """Scan file contents line-by-line using regex patterns to extract IPs.

    Applies all regex patterns to each line, extracting IP addresses from matches.
    Aggregates results by IP, counting matches and merging port lists.

    Args:
        allpatinfo: List of pattern info dictionaries as in one_log_reader
        lines: Open file handle to read lines from

    Returns:
        Dictionary mapping IP addresses to match information::

            {
                'ip_address': {
                    'ports': [22, 80] or 'all' or 'test' or 'update',
                    'pattern': 'pattern_name',
                    'matchcount': 5
                }
            }

    Example:
        >>> with open('/var/log/auth.log', 'r') as f:
        ...     results = scanlog(pattern_info, f)
        ...     print(f"Found {len(results)} unique IPs")

    Note:
        - Each line is matched against all regexes
        - First matching regex wins (short-circuit evaluation)
        - Ports are normalised and merged across multiple matches
        - Match count increments for each occurrence of same IP
    """
    # combine all the possible regexes into a list
    # allregex cannot be a generator expression
    # because it's used several times
    allregex = [(r, p) for p in allpatinfo for r in p['regex']]
    # now look for matches
    found = (matchline(allregex, line) for line in lines)
    # remove empty values
    active = (f for f in found if f)

    # create output dict
    out: dict[str, IpMatchDict] = {}
    for ip, patinfo in active:
        # need to evaluate ports
        ports = normaliseports(patinfo['ports'])
        if ip not in out:
            out[ip] = {'ports': ports,
                       'pattern': patinfo['pattern'],
                       'matchcount': 1}
        else:
            out[ip]['matchcount'] += 1
            out[ip]['ports'] = portmerge(out[ip]['ports'], ports)
            # preserve different pattern names
            out[ip]['pattern'] = patternmerge(out[ip]['pattern'], patinfo['pattern'])

    return out


def normaliseports(ports: str | None) -> str | list[int]:
    """Normalize port specification to standard format.

    Converts port strings to either a sorted list of integers or a special
    string value ('all', 'update', 'test').

    Args:
        ports: Comma-separated port numbers, or 'all', 'update', 'test', or None

    Returns:
        - 'all' if ports is None or 'all'
        - 'update' if ports is 'update'
        - 'test' if ports is 'test'
        - Sorted list of unique port integers otherwise

    Example:
        >>> normaliseports(None)
        'all'
        >>> normaliseports('22,80,22')
        [22, 80]
        >>> normaliseports('all')
        'all'
        >>> normaliseports('443,80,22')
        [22, 80, 443]

    Note:
        Uses a set to automatically remove duplicate port numbers.
    """
    if ports is None:
        return 'all'

    if ports in ('all', 'update', 'test'):
        return ports

    # use a set to remove possible duplicate values
    return sorted(list(set(map(int, ports.split(',')))))


def portmerge(current: str | list[int], new: str | list[int]) -> str | list[int]:
    """Merge two port specifications, preferring special strings over lists.

    When merging ports from multiple pattern matches, special string values
    ('all', 'update', 'test') take precedence over specific port lists.

    Args:
        current: Current port specification (string or list)
        new: New port specification to merge in (string or list)

    Returns:
        - String value if either input is a string (special value takes precedence)
        - Sorted list of unique merged ports if both are lists

    Example:
        >>> portmerge([22], [80])
        [22, 80]
        >>> portmerge([22, 80], 'all')
        'all'
        >>> portmerge('all', [22])
        'all'
        >>> portmerge([22], [80, 443])
        [22, 80, 443]

    Note:
        String values like 'all' override any specific port list, representing
        a broader match scope (all ports should be blocked).
    """
    if isinstance(current, str):
        return current

    if isinstance(new, str):
        return new

    return sorted(list(set(current + new)))


def matchline(
    allregex: list[tuple[re.Pattern[str], PatternInfo]],
    line: str) -> tuple[str, PatternInfo] | None:
    """Apply regex patterns to a line and extract IP address if matched.

    Tries each regex in sequence until one matches. Returns the IP address
    and associated pattern info for the first match.

    Args:
        allregex: List of (compiled_regex, pattern_info) tuples
        line: Log line to match against

    Returns:
        Tuple of (ip_address, pattern_info) if a match is found, None otherwise.
        The IP address is extracted from regex group 1.

    Example:
        >>> import re
        >>> pattern = re.compile(r'Failed login from (\\d+\\.\\d+\\.\\d+\\.\\d+)')
        >>> patinfo = {'pattern': 'ssh-brute', 'ports': '22'}
        >>> result = matchline([(pattern, patinfo)], 'Failed login from 192.0.2.1')
        >>> if result:
        ...     ip, info = result
        ...     print(f"Matched IP: {ip}")

    Note:
        - Expects IP address to be in capture group 1 of the regex
        - Short-circuits on first match (doesn't try remaining patterns)
        - Returns None if no patterns match the line
    """
    for reg, pattern in allregex:
        ma = reg.search(line)
        if ma:
            return (ma.group(1), pattern)
    return None
