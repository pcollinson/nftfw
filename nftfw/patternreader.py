"""Pattern file reader for blacklist log scanning rules.

This module reads and parses pattern files that define rules for scanning log
files to detect malicious activity. Pattern files specify which log files to
scan, what ports to block, and regex patterns to match IP addresses.

Pattern files are text files with a simple command-based syntax that support:
- File path specification (with glob wildcards)
- Port lists for blocking (or special values like 'all', 'test', 'update')
- Regex patterns with __IP__ placeholder for IP address matching
- Comments starting with #

Key Features
------------
- Pattern file parsing with file=, ports=, and regex statements
- Glob wildcard expansion for scanning multiple log files
- Test pattern support (ports=test) for validation
- Selective pattern execution via -p command-line flag
- IPv4 and IPv6 address matching (including ::ffff: prefix)
- Duplicate file detection via canonical path resolution

Pattern File Format
-------------------
Pattern files (*.patterns) in the patterns.d directory have this format::

    # Comment lines start with #
    file = /var/log/auth.log    # Log file to scan (supports globs)
    ports = 22                  # Ports to block (or 'all', 'test', 'update')

    # Regex patterns with __IP__ placeholder
    Failed password for .* from __IP__
    authentication failure.*rhost=__IP__

Special port values:
- **all**: Block all ports for matching IPs
- **test**: Test-only pattern (ignored unless -p flag used)
- **update**: Update firewall database incident count only, no blocking
- **numeric list**: Comma-separated port numbers (e.g., "22,80,443")

Data Structure
--------------
The returned data structure maps log file paths to pattern information::

    {
        '/var/log/auth.log': [
            {
                'pattern': 'ssh-brute',
                'ports': '22',
                'file': '/var/log/auth.log',
                'regex': [compiled_regex1, compiled_regex2, ...]
            }
        ],
        '/var/log/apache2/error.log': [...]
    }

Usage Example
-------------
    from .config import Config
    from .patternreader import pattern_reader

    # Initialize configuration
    cf = Config()
    cf.readini()
    cf.setup()

    # Read all pattern files
    patterns = pattern_reader(cf)

    # Iterate over log files and their patterns
    for logfile, pattern_list in patterns.items():
        print(f"Scanning {logfile}")
        for pat in pattern_list:
            print(f"  Pattern: {pat['pattern']}, Ports: {pat['ports']}")
            print(f"  Regexes: {len(pat['regex'])}")

    # Test a specific pattern
    cf.selected_pattern_file = 'ssh-brute'
    test_patterns = pattern_reader(cf)

See Also
--------
logreader : Module that uses pattern_reader for log scanning
blacklist : Module that orchestrates pattern reading and log scanning
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any
import os
import re
from pathlib import Path
from collections import defaultdict
import logging

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

# Type alias for pattern info dictionary
PatternDict = dict[str, Any]  # {'pattern': str, 'ports': str, 'file': str, 'regex': list}


def pattern_reader(cf: Config) -> dict[str, list[PatternDict]]:
    """Read and parse all pattern files from the patterns directory.

    Reads all *.patterns files from the configured patterns directory,
    parses them, and returns a dictionary mapping log file paths to
    their associated pattern rules.

    Args:
        cf: Config instance with etcpath for patterns directory and
            optional selected_pattern_file for testing

    Returns:
        Dictionary mapping log file paths to lists of pattern info dicts::

            {
                '/var/log/auth.log': [
                    {
                        'pattern': 'ssh-brute',
                        'ports': '22',
                        'file': '/var/log/auth.log',
                        'regex': [compiled_regex1, ...]
                    }
                ]
            }

        Returns empty dict if no valid patterns found.

    Example:
        >>> cf = Config()
        >>> patterns = pattern_reader(cf)
        >>> for logfile, pats in patterns.items():
        ...     print(f"{logfile}: {len(pats)} patterns")

        Test a specific pattern::

            >>> cf.selected_pattern_file = 'ssh-brute'
            >>> test_patterns = pattern_reader(cf)

    Note:
        - Only reads *.patterns files from patterns directory
        - Skips files with ports=test unless selected via cf.selected_pattern_file
        - Glob wildcards in file= statements are expanded
        - Non-existent log files are automatically filtered out
    """
    path = cf.etcpath('patterns')
    files = (f for f in path.glob('*.patterns') if f.is_file())
    patterns = ((f.stem, f.read_text(encoding='utf-8')) for f in files)
    recordlist = (parsefile(cf, f, c) for f, c in patterns)
    # remove empty values
    recordlist = (l for l in recordlist if l)
    return filelist(recordlist)


def parsefile(cf: Config, filename: str,
              contents: str) -> PatternDict | None:
    """Parse a single pattern file into a pattern dictionary.

    Parses file contents extracting file=, ports=, and regex statements.
    Validates syntax and handles test pattern filtering based on
    cf.selected_pattern_file settings.

    Args:
        cf: Config instance with optional selected_pattern_file
        filename: Pattern file name (stem, without .patterns extension)
        contents: Complete file contents as string

    Returns:
        Pattern dictionary with keys::

            {
                'pattern': str,  # Pattern name (filename)
                'ports': str,    # Port list or 'all'/'test'/'update'
                'file': str,     # Log file path
                'regex': list    # Compiled regex patterns
            }

        Returns None if:
        - File is empty
        - Missing required file= statement
        - Invalid port specification
        - No regex patterns found
        - Pattern is test-only and not selected
        - Pattern not selected when cf.selected_pattern_file set

    Example:
        >>> contents = '''
        ... file = /var/log/auth.log
        ... ports = 22
        ... Failed password from __IP__
        ... '''
        >>> result = parsefile(cf, 'ssh-brute', contents)
        >>> print(result['ports'])
        22

    Note:
        - Sets cf.selected_pattern_is_test = True if selected pattern has ports=test
        - Validates port values: 'all', 'test', 'update', or comma-separated numbers
        - File paths must be absolute (start with /) unless TESTING mode
        - __IP__ placeholder is replaced with IPv4/IPv6 regex pattern
    """
    # pylint: disable=too-many-return-statements

    # should always have contents
    if not any(contents):
        return None

    (file, ports, regex) = _pattern_scan(contents, filename)

    # validate statements
    # check for file=
    if not file:
        log.error('Pattern: missing file = statement in %s', filename)
        return None
    if not hasattr(cf, 'TESTING') \
       and file[0] != '/':
        log.error('Pattern: use full path to file in %s', filename)
        return None

    # validate port
    if ports is None:
        ports = 'all'
    else:
        pchk = re.compile(r'(all|update|test|(?:\d+(?:\s*,\s*\d+)*))$')
        if not pchk.match(ports):
            err = 'ports= must be all, test, ' \
                  + 'update or comma separated numeric list'
            log.error('Pattern: %s %s', filename, err)
            return None

    # check for selected pattern
    if cf.selected_pattern_file is not None:
        # if we have a selected_pattern_file, and it's not this file,
        # then ignore it
        # if it is and ports is test set global value this allows single
        # patterns to be run normally
        if filename != cf.selected_pattern_file:
            return None
        if ports == 'test':
            cf.selected_pattern_is_test = True
    else:
        # no selected_pattern_file
        # if the ports value is test ignore it
        if ports == 'test':
            return None

    # if we have no regexes - then return None
    if not any(regex):
        log.error('Pattern: %s - no test expressions, file ignored', filename)
        return None

    # generate output
    res: PatternDict = {'pattern': filename,
                        'ports': ports,
                        'file': file,
                        'regex': regex}
    return res


def _pattern_scan(contents: str,
                  filename: str) -> tuple[str | None, str | None, list[re.Pattern[str]]]:
    """Scan pattern file contents extracting file, ports, and regex patterns.

    Internal function that parses the raw file contents line by line,
    extracting file= and ports= commands and compiling regex patterns.

    Args:
        contents: Complete file contents as string
        filename: Filename for error messages

    Returns:
        Tuple of (file, ports, regex)::

            (
                '/var/log/auth.log',  # file path or None
                '22',                  # ports string or None
                [compiled_regex1, ...]  # list of compiled regexes
            )

    Example:
        >>> contents = '''
        ... file = /var/log/auth.log
        ... ports = 22,80
        ... Failed from __IP__
        ... '''
        >>> file, ports, regexes = _pattern_scan(contents, 'test')
        >>> print(file, ports, len(regexes))
        /var/log/auth.log 22,80 1

    Note:
        - Lines starting with # are comments
        - Accepts file= and ports= commands (only first occurrence counts)
        - __IP__ is replaced with: (?:::ffff:)?([0-9a-fA-F:.]+(?:/[0-9]+)?)
        - Validates regex has exactly 1 capture group (for IP)
        - Invalid regexes are logged and skipped
        - Lines without __IP__ are logged as unknown and skipped
    """
    # pylint: disable=too-many-branches

    # re used to pick out value setting lines
    commandre = re.compile(r'^([a-z]*)\s*=\s*(.*)(:?#.*)?')
    ports = None
    file = None
    regex: list[re.Pattern[str]] = []
    lineno = 0

    # scan file
    lines = (l.strip() for l in contents.split('\n'))
    for line in lines:
        lineno += 1
        # ignore comments
        # don't want to do global #
        # checking in case re's contain #
        if line == '' \
          or line[0] == '#':
            continue

        # look for lines that look like rules
        # accept file= and ports=
        cm = commandre.match(line)
        if cm:
            if cm.group(1) == 'file':
                if not file:
                    file = cm.group(2)
                else:
                    log.info('Pattern: Repeated file statement in %s:%s %s',
                             filename, lineno, line)
            elif cm.group(1) == 'ports':
                if not ports:
                    ports = cm.group(2).strip()
                else:
                    log.info('Repeated ports statement in %s:%s %s',
                             filename, lineno, line)
            else:
                log.error('Pattern: unknown command in %s:%s %s',
                          filename, lineno, line)
            continue

        # remaining lines are regexes
        # replace __IP__ by address match
        # add compiled re to regex list
        # re stolen from symbiosis
        # make this a little more robust
        # the line must contain __IP__
        if '__IP__' in line:
            linere = line.replace(r'__IP__',
                                  r'(?:::ffff:)?([0-9a-fA-F:\.]+(?:/[0-9]+)?)', 1)
            try:
                compiled_pattern = re.compile(linere, re.IGNORECASE)
                if compiled_pattern.groups != 1:
                    fmt = '%s, Line %s ignored ' \
                            + ' - extra regex match groups found - use \\ before ( and )'
                    log.error(fmt, filename, lineno)
                else:
                    regex.append(compiled_pattern)
            except re.error:
                log.error('Pattern: invalid regex in %s: Line %s - line ignored',
                          filename, lineno)
        else:
            log.error('Pattern: Unknown line in %s: Line %s - line ignored',
                      filename, lineno)
    return file, ports, regex


def filelist(recordlist: Any) -> dict[str, list[PatternDict]]:
    """Create dictionary mapping log files to their pattern definitions.

    Takes parsed pattern records and organises them by the log files they
    should scan. Performs glob expansion on file paths and filters out
    non-existent or empty files.

    Args:
        recordlist: Iterable of pattern dictionaries from parsefile()

    Returns:
        Dictionary mapping log file paths to lists of pattern info::

            {
                '/var/log/auth.log': [pattern_dict1, pattern_dict2, ...],
                '/var/log/apache2/error.log': [pattern_dict3, ...]
            }

        Returns empty defaultdict if no valid log files found.

    Example:
        >>> records = [
        ...     {'pattern': 'ssh', 'file': '/var/log/auth.log', ...},
        ...     {'pattern': 'http', 'file': '/var/log/*.log', ...}
        ... ]
        >>> result = filelist(iter(records))
        >>> for logfile in result.keys():
        ...     print(logfile)

    Note:
        - Glob wildcards (*, [, ?) in file paths are expanded
        - Symlinks are resolved to canonical paths to avoid duplicates
        - Only existing, non-empty files are included
        - Same pattern can apply to multiple files via glob expansion
        - Files that don't exist are silently omitted
    """
    action: dict[str, list[PatternDict]] = defaultdict(list)
    for record in recordlist:
        if not record['file']:
            continue
        # file=value
        fname = record['file']
        # glob glob characters
        globchars = set('*[?')
        if any((c in globchars) for c in fname):
            pathlist: list[Path] = []
            # for a glob there may be symlinks which will
            # generate several paths to the same file
            # build up a list using
            # realpath to arrive at the canonical path
            # samefile to eliminate duplicates
            root = Path('/')
            # remove initial / from glob lookup
            glstr = fname if fname[0] != '/' else fname[1:]
            for file in root.glob(glstr):
                f = Path(os.path.realpath(str(file)))
                if not any(pathlist):
                    pathlist.append(f)
                elif not any(l for l in pathlist \
                              if l.samefile(f)):
                    pathlist.append(f)
        else:
            pathlist = [Path(fname)]

        files = (str(f) for f in pathlist \
                 if f.is_file() and f.stat().st_size > 0)
        for filepath in files:
            action[filepath].append(record)

    return action
