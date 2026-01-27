"""nftfwls - Command-line database lister for nftfw blacklist database.

This module provides the nftfwls command-line utility for displaying IP addresses
from the nftfw blacklist database in formatted tables. It offers both terminal and
HTML output formats with various sorting and filtering options.

**Usage:**
    nftfwls [-h] [-c CONFIG] [-w] [-p PATTERN_SPLIT] [-a] [-r] [-g]
            [-m] [-i] [-n] [-q] [-v]

**Display Modes:**

Terminal (default)
    Uses PrettyTable to display formatted ASCII tables with borders and headers

HTML (-w/--web)
    Outputs HTML table markup suitable for embedding in web pages

**Filtering:**

Active (default)
    Shows only IPs that have .auto files in blacklist directory

All (-a/--all)
    Shows all database entries regardless of active status

**Sorting:**

Last incident (default)
    Sorts by timestamp of most recent match (descending)

Match count (-m/--matchcount)
    Sorts by total match count (largest first)

Incidents (-i/--incidents)
    Sorts by total incident count (largest first)

Reverse (-r/--reverse)
    Reverses the sort order

**Display Options:**

GeoIP (default if installed)
    Shows two-letter country code prefix for each IP

No GeoIP (-g/--nogeo)
    Suppresses country code display

Pattern split (config.ini)
    Controls whether comma-separated patterns display on multiple lines

No border (-n/--noborder)
    Removes borders and headers from terminal output

**Table Columns:**

IP
    IP address with optional country code prefix

Port
    Port numbers or 'all'

Ct/Incd
    Match count / Incident count

Latest
    Timestamp of most recent match

First
    Timestamp of first match (or '-' if same as Latest)

Duration
    Time span between First and Latest (or '-' if same)

Pattern
    Pattern name(s) that matched this IP

**Integration:**

The utility integrates with multiple nftfw components:
    - fwdb: Database access for blacklist entries
    - geoipcountry: GeoIP2 country code lookup
    - stats: Duration formatting for time spans
    - config: Configuration management

**Related Modules:**
    - fwdb: Database access layer
    - geoipcountry: GeoIP2 integration
    - stats: Time formatting utilities
    - config: Configuration management
    - nftfwedit: Database editor
    - nf_edit_print: IP information display

Example:
    Show active blacklist entries::\n
        nftfwls\n
    \n
    Show all database entries sorted by match count::\n
        nftfwls -a -m\n
    \n
    Generate HTML output without GeoIP::\n
        nftfwls -w -g\n
"""
from __future__ import annotations

import sys
import datetime
from signal import signal, SIGPIPE, SIG_DFL
from pathlib import Path
import argparse
import logging
from typing import TYPE_CHECKING, Any

from prettytable import PrettyTable
from .fwdb import FwDb
from .config import Config
from .geoipcountry import GeoIPCountry
from .stats import duration

if TYPE_CHECKING:
    pass

log = logging.getLogger('nftfw')

def loaddb(cf: Config, orderby: str = 'last DESC') -> list[dict[str, Any]]:
    """Load all entries from the blacklist database.

    Retrieves all records from the blacklist table in the nftfw database,
    ordered according to the specified sorting criteria.

    **Common Sort Orders:**

    - 'last DESC': Most recent incidents first (default)
    - 'last': Oldest incidents first
    - 'matchcount DESC, incidents': Highest match count first
    - 'incidents DESC, matchcount': Highest incident count first

    Args:
        cf: Config instance with database path
        orderby: SQL ORDER BY clause for sorting (default: 'last DESC')

    Returns:
        List of database record dictionaries with keys: ip, ports, pattern,
        matchcount, incidents, first, last, useall

    Example:
        Load with default sorting::\n
            cf = Config()
            records = loaddb(cf)
            # Returns all entries sorted by last incident time

        Load sorted by match count::\n
            records = loaddb(cf, orderby='matchcount DESC')
    """

    db: FwDb = FwDb(cf)
    result: list[dict[str, Any]] = db.lookup('blacklist', orderby=orderby)
    return result

def loadactive(cf: Config) -> list[str]:
    """Load list of actively blacklisted IP addresses from filesystem.

    Scans the blacklist directory for .auto files (automatically created
    blacklist entries) and returns the IP addresses they represent. Converts
    pipe notation back to CIDR slash notation.

    **File Name Conversion:**

    .auto files use | instead of / for CIDR notation:
        - "192.168.1.0|24.auto" becomes "192.168.1.0/24"
        - "10.0.0.50.auto" becomes "10.0.0.50"

    Args:
        cf: Config instance with blacklist directory path

    Returns:
        List of IP address strings (with / for CIDR notation)

    Example:
        Load active blacklist::\n
            cf = Config()
            active = loadactive(cf)
            # Returns: ['192.168.1.100', '10.0.0.0/8', ...]
    """

    path: Path = cf.etcpath('blacklist')
    out: list[str] = []
    for p in path.glob('*.auto'):
        ip: str = p.stem
        ip = ip.replace('|', '/')
        out.append(ip)
    return out

def activedb(dbdata: list[dict[str, Any]], active: list[str]) -> list[dict[str, Any]]:
    """Filter database entries to only those with active blacklist files.

    Takes the full database and returns only entries that have corresponding
    .auto files in the blacklist directory. This provides a view of currently
    enforced blacklist entries.

    Args:
        dbdata: List of all database record dictionaries
        active: List of IP addresses with .auto files (from loadactive())

    Returns:
        Filtered list of database records for active blacklist entries only

    Example:
        Filter to active entries::\n
            db = loaddb(cf)
            active = loadactive(cf)
            active_db = activedb(db, active)
            # Returns only database entries with .auto files
    """

    out: list[dict[str, Any]] = [e for e in dbdata if e['ip'] in active]
    return out

def datefmt(fmt: str, timeint: int) -> str:
    """Format Unix timestamp as human-readable date/time string.

    Converts Unix epoch timestamps to formatted date/time strings using
    strftime format codes from configuration. Centralized function so date
    formatting is consistent throughout nftfwls and nf_edit_print.

    **Common Format Strings:**

    - '%Y-%m-%d %H:%M:%S': ISO format (2024-01-15 10:30:00)
    - '%d/%m/%Y %H:%M': UK format (15/01/2024 10:30)
    - '%m/%d/%Y %I:%M %p': US format (01/15/2024 10:30 AM)

    Args:
        fmt: strftime format string (from Nftfwls config section)
        timeint: Unix epoch timestamp (seconds since 1970-01-01)

    Returns:
        Formatted date/time string

    Example:
        Format timestamp::\n
            timestamp = 1705318200
            formatted = datefmt('%Y-%m-%d %H:%M:%S', timestamp)
            # Returns: "2024-01-15 10:30:00"
    """

    value: datetime.datetime = datetime.datetime.fromtimestamp(timeint)
    return value.strftime(fmt)

def formatline(date_fmt: str, pattern_split: bool, line: dict[str, Any],
               geoip: GeoIPCountry | None, is_html: bool = False) -> list[str]:
    """Format a database record as a list of display columns.

    Converts a single database record into formatted strings for display in
    a table. Handles GeoIP2 country code prefixes, date formatting, duration
    calculation, port display, and pattern splitting.

    **Column Formatting:**

    1. IP with optional country code prefix
    2. Ports (converts useall flag to 'all')
    3. Match count / Incident count
    4. Latest timestamp (always shown)
    5. First timestamp (or '-' if same as latest)
    6. Duration (or '-' if first == latest)
    7. Pattern name(s)

    **GeoIP2 Integration:**

    If GeoIP2 is installed and country found:
        - Terminal: Prepends "US " to IP
        - HTML: Prepends '<abbr title="United States">US</abbr> '

    **Pattern Splitting:**

    If pattern_split is True:
        - "sshd,apache,postfix" becomes "sshd\\n apache\\n postfix"
        - Displays patterns on separate lines in table

    Args:
        date_fmt: strftime format string for timestamps
        pattern_split: If True, split comma-separated patterns onto multiple lines
        line: Database record dict with keys: ip, ports, pattern, matchcount,
              incidents, first, last, useall
        geoip: GeoIPCountry instance or None to disable GeoIP lookup
        is_html: If True, format for HTML output (adds <abbr> tags)

    Returns:
        List of 7 formatted strings for table columns

    Example:
        Format database record::\n
            record = {
                'ip': '192.168.1.100', 'ports': '22', 'pattern': 'sshd',
                'matchcount': 150, 'incidents': 10, 'first': 1000, 'last': 2000,
                'useall': False
            }
            geoip = GeoIPCountry()
            columns = formatline('%Y-%m-%d', False, record, geoip)
            # Returns: ['US 192.168.1.100', '22', '150/10', ...]
    """

    # Add countrycode to IP if exists
    ip: str = line['ip']
    if geoip is not None and geoip.isinstalled():
        country: str | None
        iso: str | None
        country, iso = geoip.lookup(ip)
        if iso is None:
            iso = "  "
        elif is_html:
            # if html add abbr so mouseover shows country name
            if country is not None:
                iso = f'<abbr title="{country}">{iso}</abbr>'
        ip = iso + " " + ip

    # special handling for last, and duration
    estring: str
    dstring: str
    if line['first'] == line['last']:
        estring = '-'
        dstring = '-'
    else:
        estring = datefmt(date_fmt, line['first'])
        # pylint objects to and suggests an f string
        # dstring = "%8s" % (duration(line['first'], line['last']),)
        dur: str = duration(line['first'], line['last'])
        dstring = f'{str(dur):8s}'
    # deal with the useall flag
    pstring: str = line['ports']
    if line['useall']:
        pstring = 'all'

    # make patterns into two lines
    pats: str
    if pattern_split:
        pats = "\n ".join(line['pattern'].split(","))
    else:
        pats = line['pattern']

    return [ip,
            pstring,
            str(line['matchcount']) + '/' + str(line['incidents']),
            datefmt(date_fmt, line['last']),
            estring,
            dstring,
            pats]

def displaytable(cf: Config, dt: list[dict[str, Any]], nogeo: bool,  # pylint: disable=unused-argument,too-many-arguments
                 noborder: bool, date_fmt: str, pattern_split: bool) -> None:
    """Display database records as formatted ASCII table for terminal.

    Uses PrettyTable library to create formatted ASCII tables with borders,
    headers, and alignment. Displays entry count in IP column header.

    **Table Format:**

    - Left-aligned columns (except Ct/Incd which is centered)
    - Borders and headers (unless noborder=True)
    - Entry count in IP column header: "IP(25)"
    - GeoIP2 country codes if available and not disabled

    **Configuration:**

    Reads from cf (set by main()):
        - date_fmt: strftime format for timestamps
        - pattern_split: Whether to split comma-separated patterns

    Args:
        cf: Config instance
        dt: List of database record dicts to display
        nogeo: If True, suppresses GeoIP2 country code lookup
        noborder: If True, removes borders and headers from table
        date_fmt: strftime format for timestamps (e.g., '%d %b %H:%M')
        pattern_split: If True, split comma-separated patterns to multiple lines

    Returns:
        None. Prints table directly to stdout.

    Example:
        Display with borders::\n
            cf = Config()
            records = loaddb(cf)
            displaytable(cf, records, nogeo=False, noborder=False,
                        date_fmt='%Y-%m-%d %H:%M:%S', pattern_split=False)

        Display without borders::\n
            displaytable(cf, records, nogeo=False, noborder=True,
                        date_fmt='%d %b %H:%M', pattern_split=True)
    """

    # pylint: disable=unsupported-assignment-operation,too-many-positional-arguments
    # doesn't like the assignment to pt.align

    fmt: str = date_fmt
    geoip: GeoIPCountry | None = None
    if not nogeo:
        geoip = GeoIPCountry()

    pt: PrettyTable = PrettyTable()

    if noborder:
        pt.border = False
        pt.header = False

    pt.field_names = ['IP'+'('+str(len(dt))+')',
                      'Port', 'Ct/Incd', 'Latest',
                      'First', 'Duration', 'Pattern']
    for line in dt:
        pt.add_row(formatline(fmt, pattern_split, line, geoip))

    # set up format
    pt.align = 'l'
    pt.align['Ct/Incd'] = 'c'  # type: ignore[index]
    print(pt)

def displayhtml(cf: Config, dt: list[dict[str, Any]], nogeo: bool,  # pylint: disable=unused-argument
                date_fmt: str, pattern_split: bool) -> None:
    """Display database records as HTML table markup.

    Generates HTML table with semantic class names for styling. Country codes
    are wrapped in <abbr> tags with full country name in title attribute for
    mouseover tooltips.

    **HTML Structure:**

    - <table class="nftfwls">
    - <tr class="heading"> for header row
    - <tr class="content"> for data rows
    - <td class="col1">, <td class="col2">, etc. for cells
    - <abbr title="United States">US</abbr> for country codes

    **Formatting:**

    - Spaces converted to &nbsp;
    - Newlines converted to <br>
    - Entry count in IP column header: "IP(25)"

    Args:
        cf: Config instance
        dt: List of database record dicts to display
        nogeo: If True, suppresses GeoIP2 country code lookup
        date_fmt: strftime format for timestamps (e.g., '%d %b %H:%M')
        pattern_split: If True, split comma-separated patterns to multiple lines

    Returns:
        None. Prints HTML markup directly to stdout.

    Example:
        Generate HTML table::\n
            cf = Config()
            records = loaddb(cf)
            displayhtml(cf, records, nogeo=False,
                       date_fmt='%Y-%m-%d %H:%M:%S', pattern_split=True)
    """

    fmt: str = date_fmt
    geoip: GeoIPCountry | None = None
    if not nogeo:
        geoip = GeoIPCountry()

    tdata: list[list[str]] = []
    for record in dt:
        tdata.append(formatline(fmt, pattern_split, record, geoip, is_html=True))

    print('<table class="nftfwls">')
    field_names: list[str] = ['IP'+'('+str(len(dt))+')',
                               'Port', 'Ct/Incd', 'Latest',
                               'First', 'Duration', 'Pattern']
    htmlrow('heading', field_names)
    for row in tdata:
        htmlrow('content', row)
    print('</table>')


def htmlrow(htmlclass: str, line: list[str]) -> None:
    """Print a single HTML table row with formatted cells.

    Generates HTML markup for one table row (<tr>) with multiple data cells
    (<td>). Applies CSS class names to row and cells for styling, and converts
    spaces/newlines to HTML entities.

    **Class Names:**

    Row class
        Either 'heading' or 'content' as specified in htmlclass parameter

    Cell classes
        'col1', 'col2', 'col3', etc. for sequential cells

    **HTML Escaping:**

    - Spaces → &nbsp; (except in first column which may contain <abbr> tags)
    - Newlines → <br>

    Args:
        htmlclass: CSS class name for the <tr> tag ('heading' or 'content')
        line: List of cell contents (already escaped by formatline())

    Returns:
        None. Prints HTML markup directly to stdout.

    Example:
        Print header row::\n
            htmlrow('heading', ['IP(25)', 'Port', 'Ct/Incd', ...])

        Print data row::\n
            htmlrow('content', ['US 192.168.1.100', '22', '150/10', ...])
    """

    print(f'    <tr class="{htmlclass}">')
    ix: int = 0
    for edited in line:
        ix = ix + 1
        colclass: str = 'col' + str(ix)
        print(f'        <td class="{colclass}">', end='')
        if ix > 1:
            # ip may have html in it
            edited = edited.replace(' ', '&nbsp;')
        edited = edited.replace('\n', '<br>')
        print(edited, end='')
        print('</td>')
    print('    </tr>')

def main() -> None:
    """Main entry point for nftfwls command-line utility.

    Parses command-line arguments, initialises configuration, loads database
    records with optional filtering to active entries, and displays results
    as either terminal table or HTML markup.

    **Workflow:**

    1. Set SIGPIPE handler to SIG_DFL (prevents broken pipe errors with head)
    2. Parse command-line arguments with argparse
    3. Initialize Config with dosetup=False
    4. Handle optional --config file override
    5. Read config.ini file
    6. Apply --quiet or --verbose flags to logging
    7. Complete configuration with cf.setup()
    8. Determine sort order from --matchcount, --incidents, --reverse flags
    9. Handle --pattern-split override
    10. Load date_fmt and pattern_split from Nftfwls config section
    11. Load database with loaddb()
    12. Filter to active entries unless --all specified
    13. Display with displayhtml() or displaytable()

    **Sort Orders:**

    Default
        last DESC (most recent incidents first)

    --matchcount (-m)
        matchcount DESC, incidents (highest match count first)

    --incidents (-i)
        incidents DESC, matchcount (highest incident count first)

    --reverse (-r)
        Reverses the selected sort order

    **Error Handling:**

    - Configuration errors: Logs critical message and exits with code 1
    - Config file not found: Logs critical message and exits with code 1
    - Invalid --pattern-split value: Logs error and exits with code 0

    Args:
        None. Parses sys.argv for command-line arguments.

    Returns:
        None. Displays results to stdout, exits with code 0 or 1.

    Example:
        Normal invocation from command line::\n
            $ nftfwls                    # Show active, sorted by last
            $ nftfwls -a -m              # Show all, sorted by matches
            $ nftfwls -w -g              # HTML output without GeoIP
            $ nftfwls -n | head -10      # No borders, pipe to head
    """

    #pylint: disable=too-many-branches, too-many-statements

    # ignore broken pipe error - thrown when using
    # nftfwls into the head command
    signal(SIGPIPE, SIG_DFL)

    cf: Config = Config()

    desc: str = """nftfwls - list firewall information

Default output is to show active entries sorted by
time of last incident (in descending order)
"""

    ap: argparse.ArgumentParser = argparse.ArgumentParser(
        prog='nftfwls',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=desc)
    ap.add_argument('-c', '--config',
                    help='Supply a configuration file overriding the built-in file')
    ap.add_argument('-w', '--web',
                    help='Print output as an HTML table',
                    action='store_true')
    ap.add_argument('-p', '--pattern-split',
                    help='Set the pattern-split value to yes or no, overrides value in config.ini',
                    action='append')
    ap.add_argument('-a', '--all',
                    help='Print database information, don\'t look at firewall directory',
                    action='store_true')
    ap.add_argument('-r', '--reverse',
                    help='Reverse sense of sorting',
                    action='store_true')
    ap.add_argument('-g', '--nogeo',
                    help='Suppress Geoip information, shown if GeoIp is installed',
                    action='store_true')
    ap.add_argument('-m', '--matchcount',
                    help='Sort by counts - largest first',
                    action='store_true')
    ap.add_argument('-i', '--incidents',
                    help='Sort by incidents - largest first',
                    action='store_true')
    ap.add_argument('-n', '--noborder',
                    help='Don\'t add borders and title to the table',
                    action='store_true')
    ap.add_argument('-q', '--quiet',
                    help='Suppress printing of errors on the console, syslog output remains active',
                    action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='Show information messages',
                    action='store_true')

    args: argparse.Namespace = ap.parse_args()

    #
    # Sort out config
    # but don't init anything as yet
    #
    try:
        cf = Config(dosetup=False)
    except AssertionError as e:
        cf.set_logger(logprint=False)
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    # allow change of config file
    if args.config:
        file: Path = Path(args.config)
        if file.is_file():
            cf.set_ini_value_with_section('Locations', 'ini_file', str(file))
        else:
            cf.set_logger(logprint=False)
            log.critical('Aborted: Cannot find config file: %s', args.config)
            sys.exit(1)

    # Load the ini file if there is one
    # options can set new values into the ini setup
    # to override
    try:
        cf.readini()
    except AssertionError as e:
        cf.set_logger(logprint=False)
        log.critical('Aborted: %s', str(e))
        sys.exit(1)

    if args.quiet:
        cf.set_logger(logprint=False)

    if args.verbose:
        cf.set_logger(loglevel='DEBUG')

    try:
        cf.setup()
    except AssertionError as e:
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    orderby: str = 'last DESC'
    if args.reverse:
        orderby = 'last'
    if args.matchcount:
        orderby = 'matchcount DESC, incidents'
        if args.reverse:
            orderby = 'matchcount, incidents'
    if args.incidents:
        orderby = 'incidents DESC, matchcount'
        if args.reverse:
            orderby = 'incidents, matchcount'
    config: dict[str, Any] = cf.get_ini_values_by_section('Nftfwls')
    date_fmt: str = str(config['date_fmt'])
    pattern_split: bool = bool(config['pattern_split'])

    if args.pattern_split:
        for v in args.pattern_split:
            if v == 'yes':
                pattern_split = True
            elif v == 'no':
                pattern_split = False
            else:
                log.error('Value for -p should be "yes" or "no"')
                sys.exit(0)

    db: list[dict[str, Any]] = loaddb(cf, orderby=orderby)
    if not args.all:
        fw: list[str] = loadactive(cf)
        db = activedb(db, fw)

    if args.web:
        displayhtml(cf, db, args.nogeo, date_fmt, pattern_split)
    else:
        displaytable(cf, db, args.nogeo, args.noborder, date_fmt, pattern_split)

if __name__ == '__main__':
    main()
