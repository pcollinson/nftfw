"""nftfwedit - Command-line editor for nftfw blacklist database.

This module provides the nftfwedit command-line utility for managing IP addresses
in the nftfw blacklist database. It offers four main operations (add, blacklist,
delete, remove) plus an information display mode.

**Usage:**
    nftfwedit [-h] [-d | -a | -b] [-p PORT] [-n PATTERN] [-q] [-v]
              [ipaddress [ipaddress ...]]

**Operations:**

add (-a)
    Add IP addresses to database without creating blacklist files.
    Requires --port and --pattern arguments.

blacklist (-b)
    Add IP addresses to both database and blacklist directory as .auto files.
    Port and pattern are optional if IP already exists in database.

delete (-d)
    Remove IP addresses from database and delete associated blacklist files.

remove (-r)
    Delete blacklist files only, leaving database entries intact.

print (default)
    Display information about IP addresses including database records,
    GeoIP2 country data, and DNSBL status.

**Options:**

-p, --port
    Port specification: 'all', numeric port, service name, or comma-separated list

-n, --pattern
    Pattern name that matched these IPs in log files

-m, --matches
    Match count (defaults to 1 for updates). For new blacklist entries,
    minimum is enforced by block_after threshold (default 10).

-g, --gethostname
    Include DNS reverse lookup in information display (can be slow)

-q, --quiet
    Suppress console error messages (syslog remains active)

-v, --verbose
    Show information-level messages

**Integration:**

The utility integrates with multiple nftfw components:
    - nf_edit_validate: IP address, port, and pattern validation
    - nf_edit_print: Pretty printing of IP information
    - nf_edit_dbfns: Database operations (via Scheduler)
    - scheduler: Locking and command execution
    - config: Configuration management

**Workflow:**

1. Parse command-line arguments with argparse
2. Initialize configuration and logging
3. Validate IP addresses, ports, and patterns
4. Dispatch to appropriate operation handler
5. Call scheduler with 'edit' action for database operations
6. Scheduler invokes DbFns.execute() with validated parameters

**Related Modules:**
    - nf_edit_dbfns: Implements database operations
    - nf_edit_validate: Validates user input
    - nf_edit_print: Displays IP information
    - scheduler: Provides locking and command execution
    - config: Configuration management

Example:
    Add IP to database only::\n
        nftfwedit -a 192.168.1.100 -p 22 -n sshd\n
    \n
    Blacklist IP with file creation::\n
        nftfwedit -b 192.168.1.100 -p 22 -n sshd -m 15\n
    \n
    Delete IP from database and filesystem::\n
        nftfwedit -d 192.168.1.100\n
    \n
    Display information about IP::\n
        nftfwedit 192.168.1.100 -g\n
"""
from __future__ import annotations

import sys
import argparse
import logging

from .config import Config
from .nf_edit_validate import validate_and_return_ip_list
from .nf_edit_validate import validate_port
from .nf_edit_validate import validate_pattern
from .nf_edit_print import PrintInfo
from .normaliseaddress import NormaliseAddress
from .scheduler import Scheduler

log = logging.getLogger('nftfw')

def main() -> None:
    """Main entry point for nftfwedit command-line utility.

    Parses command-line arguments, initialises configuration and logging, and
    dispatches to the appropriate operation handler based on the command-line
    options provided.

    **Operations Dispatched:**

    - -d/--delete: Calls run_delete() to remove IPs from database and files
    - -r/--remove: Calls run_remove() to delete files only
    - -a/--add: Calls run_add() to add IPs to database only
    - -b/--blacklist: Calls run_blacklist() to add IPs with file creation
    - (default): Calls print_info() to display IP information

    **Configuration:**

    1. Initialize Config with dosetup=False
    2. Read config.ini file
    3. Apply --quiet or --verbose flags to logging
    4. Complete setup with cf.setup()

    **Error Handling:**

    - Configuration errors: Print error and exit with code 1
    - Invalid arguments: Print usage and error message, exit with code 1
    - No arguments: Print usage and exit with code 0

    Args:
        None. Parses sys.argv for command-line arguments.

    Returns:
        None. Exits with status code 0 on success, 1 on error.

    Example:
        Normal invocation from command line::\n
            $ nftfwedit -b 192.168.1.100 -p 22 -n sshd
            $ nftfwedit -d 192.168.1.100
            $ nftfwedit 192.168.1.100 -g
    """

    # pylint: disable=too-many-branches,too-many-statements

    desc = """Manage IP addresses in the nftfw blacklist database"""
    epilog = """
If one of -d, -a, -b is not supplied, nftfwedit prints information about
the ip address arguments. Information from the blacklist database is
printed if available, along with the country of origin (if geoip2 is
installed) and output from any DNS blocklists, if specified in
config.ini.
"""


    ap = argparse.ArgumentParser(prog='nftfwedit',
                                 description=desc,
                                 epilog=epilog)
    gp = ap.add_mutually_exclusive_group()
    gp.add_argument('-d', '--delete',
                    help="Delete the ip from the database "
                         "and if present, from the blacklist directory.",
                    action='store_true')
    gp.add_argument('-r', '--remove',
                    help="Delete the file with the ip name from the blacklist directory.",
                    action='store_true')
    gp.add_argument('-a', '--add',
                    help="Add the ip to the database - requires port and pattern arguments.",
                    action='store_true')
    gp.add_argument('-b', '--blacklist',
                    help='Add ip to blacklist directory. If necessary add the ip '
                         'to the database, and then requires port and pattern arguments.',
                    action='store_true')
    ap.add_argument('-g', '--gethostname',
                    help='Include hostname information when printing ip address information. '
                         'Can be slow for ip addresses with no information.',
                    action='store_true')
    ap.add_argument('-p', '--port',
                    help="Port for -a or -b action, can be 'all', a port number, a "
                         'service name or comma separated list of port numbers and '
                         'service names.')
    ap.add_argument('-n', '--pattern', help="Pattern name for the -a or -b action")
    ap.add_argument('-m', '--matches',
                    help="For the -a or -b actions, set the number of matches used to count the "
                         "number of problems found in logfiles. For new database entries with "
                         "the -b option, this is forced to be a minimum of 10 (the default "
                         "'block after' value), ensuring that the control file in blacklist.d "
                         "isn't deleted. When the -a and -b options are updating extant database "
                         "entries, the count defaults to 1 which is added to the stored count.")
    ap.add_argument('-q', '--quiet',
                    help='Suppress printing of errors on console, syslog output remains active',
                    action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='Show information messages',
                    action='store_true')
    ap.add_argument('ipaddress', help='IP address list', nargs='*')
    args = ap.parse_args()

    try:
        cf = Config(dosetup=False)
    except AssertionError as e:
        print(f'Aborted: Configuration problem: {str(e)}')
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

    # Now set things up
    try:
        cf.setup()
    except AssertionError as e:
        cf.set_logger(logprint=False)
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    if args.delete:
        run_delete(cf, ap, args)

    elif args.remove:
        run_remove(cf, ap, args)

    elif args.add:
        run_add(cf, ap, args)

    elif args.blacklist:
        run_blacklist(cf, ap, args)

    elif args.pattern:
        print('-n (pattern) is used with the -a and -b options')

    elif args.port:
        print('-p (port) is used with the -a and -b options')

    elif args.matches:
        print('-m (matches) is used with the -a and -b options')

    elif args.gethostname:
        print_info(cf, args, gethostname=True)

    else:
        if not any(args.ipaddress):
            ap.print_usage()
            sys.exit(0)
        print_info(cf, args)


def print_info(cf: Config, args: argparse.Namespace, gethostname: bool = False) -> None:
    """Display detailed information about IP addresses.

    Prints comprehensive information about each IP address including database
    records, GeoIP2 country data, DNSBL status, and optionally DNS reverse
    lookup information. Uses PrintInfo class for formatted output.

    **Workflow:**

    1. Retrieve date_fmt from Nftfwls config section
    2. Validate IP addresses using validate_and_return_ip_list()
    3. Normalise non-CIDR addresses with NormaliseAddress
    4. Display information for each IP using PrintInfo.print_ip()
    5. Add blank line between multiple IPs for readability

    **IP Processing:**

    - CIDR networks (with /) are used as-is
    - Single addresses are normalised (IPv4/IPv6 validation, whitelist check)
    - Invalid addresses are silently filtered out

    Args:
        cf: Config instance with paths and settings
        args: Parsed command-line arguments with ipaddress list
        gethostname: If True, perform DNS reverse lookup (can be slow)

    Returns:
        None. Prints directly to stdout.

    Example:
        Display information without DNS lookup::\n
            args = argparse.Namespace(ipaddress=['192.168.1.100'])
            print_info(cf, args)

        Display with DNS hostname::\n
            print_info(cf, args, gethostname=True)
    """

    ipvalid: list[str] = validate_and_return_ip_list(args.ipaddress)
    normalise: NormaliseAddress = NormaliseAddress(cf, 'nftfwedit')
    iplist: list[str] = []
    for ip in ipvalid:
        if '/' in ip:
            iplist.append(ip)
        else:
            ipn: str | None = normalise.normal(ip)
            if ipn is not None:
                iplist.append(ipn)

    pi: PrintInfo = PrintInfo(cf)
    addnl: bool = len(args.ipaddress) != 1
    for ip in iplist:
        pi.print_ip(ip, showhostinfo=gethostname)
        if addnl:
            print()

def run_delete(cf: Config, ap: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Execute delete operation for IP addresses.

    Removes IP addresses from both the database and blacklist directory. This
    is the handler for the -d/--delete command-line option.

    **Requirements:**

    - Must be run as root (checked via cf.am_i_root())
    - Port and pattern options not allowed (exits with error if present)

    **Workflow:**

    1. Check root privileges
    2. Validate that port/pattern options are not present
    3. Validate IP address list
    4. Call scheduler with 'delete' command to obtain lock
    5. Scheduler invokes DbFns.delete() via 'edit' action

    Args:
        cf: Config instance with paths and settings
        ap: ArgumentParser instance for printing usage on error
        args: Parsed command-line arguments with ipaddress list

    Returns:
        None. May exit with code 1 on error.

    Example:
        Delete single IP::\n
            $ nftfwedit -d 192.168.1.100

        Delete multiple IPs::\n
            $ nftfwedit -d 192.168.1.100 10.0.0.50
    """

    cf.am_i_root()
    if args.port is not None \
       or args.pattern is not None:
        ap.print_usage()
        print('-p (port) and -n (pattern) are not used with -d (delete)')
        sys.exit(1)
    iplist: list[str] = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'delete', iplist)

def run_remove(cf: Config, ap: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Execute remove operation for IP addresses.

    Deletes .auto files from the blacklist directory while preserving database
    entries. This is the handler for the -r/--remove command-line option.

    **Requirements:**

    - Must be run as root (checked via cf.am_i_root())
    - Port and pattern options not allowed (exits with error if present)

    **Workflow:**

    1. Check root privileges
    2. Validate that port/pattern options are not present
    3. Validate IP address list
    4. Call scheduler with 'remove' command to obtain lock
    5. Scheduler invokes DbFns.remove() via 'edit' action

    **Use Case:**

    Temporarily deactivate blacklist entries without losing their history
    in the database. The IP can be re-blacklisted later using existing
    database values.

    Args:
        cf: Config instance with paths and settings
        ap: ArgumentParser instance for printing usage on error
        args: Parsed command-line arguments with ipaddress list

    Returns:
        None. May exit with code 1 on error.

    Example:
        Remove files but keep database entries::\n
            $ nftfwedit -r 192.168.1.100

        Remove multiple files::\n
            $ nftfwedit -r 192.168.1.100 10.0.0.50
    """

    cf.am_i_root()
    if args.port is not None \
       or args.pattern is not None:
        ap.print_usage()
        print('-p (port) and -n (pattern) are not used with -d (delete)')
        sys.exit(1)
    iplist: list[str] = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'remove', iplist)

def run_add(cf: Config, ap: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Execute add operation for IP addresses.

    Adds IP addresses to the database without creating blacklist files. This
    is the handler for the -a/--add command-line option.

    **Requirements:**

    - Must be run as root (checked via cf.am_i_root())
    - Port and pattern options are required (exits with error if missing)
    - Match count defaults to 1 if not specified

    **Workflow:**

    1. Check root privileges
    2. Validate that both port and pattern are present
    3. Validate port and pattern values
    4. Get match count (defaults to 1)
    5. Validate IP address list
    6. Call scheduler with 'add' command to obtain lock
    7. Scheduler invokes DbFns.add() via 'edit' action

    **Use Case:**

    Track IP addresses in the database without actively blocking them. Useful
    for building up match counts before blacklisting.

    Args:
        cf: Config instance with paths and settings
        ap: ArgumentParser instance for printing usage on error
        args: Parsed command-line arguments with ipaddress, port, pattern

    Returns:
        None. May exit with code 1 on error.

    Example:
        Add IP to database with port and pattern::\n
            $ nftfwedit -a 192.168.1.100 -p 22 -n sshd

        Add with custom match count::\n
            $ nftfwedit -a 192.168.1.100 -p 22 -n sshd -m 5
    """

    cf.am_i_root()
    if args.port is None \
       or args.pattern is None:
        ap.print_usage()
        print('-p (port) and -n (pattern) must both be supplied with -a (add)')
        sys.exit(1)
    port: str | list[int]
    pattern: str
    port, pattern = port_and_pattern_check(ap, args.port, args.pattern)
    matches: int = check_match_count(args)
    iplist: list[str] = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'add', iplist, port, pattern, matches)

def run_blacklist(cf: Config, ap: argparse.ArgumentParser,
                  args: argparse.Namespace) -> None:
    """Execute blacklist operation for IP addresses.

    Adds IP addresses to both database and blacklist directory as .auto files.
    This is the handler for the -b/--blacklist command-line option.

    **Requirements:**

    - Must be run as root (checked via cf.am_i_root())
    - Port and pattern are optional if IP exists in database
    - If either port or pattern is provided, both must be supplied

    **Workflow:**

    1. Check root privileges
    2. Validate port/pattern pair if either is present
    3. Get match count (defaults to 1)
    4. Validate IP address list
    5. Call scheduler with 'blacklist' command to obtain lock
    6. Scheduler invokes DbFns.blacklist() via 'edit' action

    **Match Count Threshold:**

    For new database entries, match count is forced to minimum of block_after
    value (default 10) to ensure .auto file isn't immediately deleted during
    expiry processing.

    Args:
        cf: Config instance with paths and settings
        ap: ArgumentParser instance for printing usage on error
        args: Parsed command-line arguments with ipaddress, optional port/pattern

    Returns:
        None. May exit with code 1 on error.

    Example:
        Blacklist new IP with port and pattern::\n
            $ nftfwedit -b 192.168.1.100 -p 22 -n sshd

        Blacklist existing IP (uses database values)::\n
            $ nftfwedit -b 192.168.1.100

        Blacklist with custom match count::\n
            $ nftfwedit -b 192.168.1.100 -p 22 -n sshd -m 15
    """

    cf.am_i_root()
    port: str | list[int] | None = None
    pattern: str | None = None
    if args.port is not None \
       or args.pattern is not None:
        if args.port is None \
           or args.pattern is None:
            ap.print_usage()
            print('-p (port) and -n (pattern) must both be supplied')
            sys.exit(1)
        port, pattern = port_and_pattern_check(ap, args.port, args.pattern)
    matches: int = check_match_count(args)
    iplist: list[str] = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'blacklist', iplist, port, pattern, matches)

def check_match_count(args: argparse.Namespace) -> int:
    """Validate and return the match count from arguments.

    Extracts the match count from command-line arguments and validates that
    it's a valid integer. Returns 1 if no match count was specified.

    **Validation:**

    - If --matches not provided: Returns 1 (default increment)
    - If --matches provided: Converts to int and returns
    - If conversion fails: Prints error and exits with code 1

    Args:
        args: Parsed command-line arguments with optional matches attribute

    Returns:
        Match count as integer (1 if not specified)

    Example:
        Default match count::\n
            args = argparse.Namespace(matches=None)
            count = check_match_count(args)  # Returns 1

        Custom match count::\n
            args = argparse.Namespace(matches='15')
            count = check_match_count(args)  # Returns 15
    """

    if args.matches is None:
        return 1
    try:
        matches: int = int(args.matches)
        return matches
    except ValueError:
        print('Incident count must be a number')
        sys.exit(1)

def port_and_pattern_check(ap: argparse.ArgumentParser, port: str,
                           pattern: str) -> tuple[str | list[int], str]:
    """Validate port and pattern specifications.

    Validates user-provided port and pattern values using nf_edit_validate
    functions. Prints usage and error messages if validation fails, then
    exits with code 1.

    **Validation:**

    Port validation (validate_port)
        - Returns (True, "all") for "all"
        - Returns (True, [port_numbers]) for valid ports
        - Returns (False, error_message) for invalid ports

    Pattern validation (validate_pattern)
        - Returns (True, pattern) for valid patterns
        - Returns (False, error_message) for invalid patterns

    Args:
        ap: ArgumentParser instance for printing usage on error
        port: Port specification string (e.g., "22", "ssh", "22,80,443", "all")
        pattern: Pattern name string (e.g., "sshd", "apache")

    Returns:
        Tuple of (validated_port, validated_pattern) where port is either
        "all" string or list of integer port numbers

    Example:
        Valid port and pattern::\n
            port, pattern = port_and_pattern_check(ap, "ssh,http", "sshd")
            # Returns: ([22, 80], "sshd")

        Special 'all' port::\n
            port, pattern = port_and_pattern_check(ap, "all", "scan")
            # Returns: ("all", "scan")
    """

    # check on port
    okport: bool
    port_result: str | list[int]
    okport, port_result = validate_port(port)
    # check on pattern
    okpattern: bool
    okpattern, pattern = validate_pattern(pattern)
    # if ok is False, error is in second value
    if not okport:
        ap.print_usage()
        print(port_result)
        if not okpattern:
            print(pattern)
        sys.exit(1)
    if not okpattern:
        ap.print_usage()
        print(pattern)
        sys.exit(1)
    return port_result, pattern

def call_scheduler(cf: Config, cmd: str, iplist: list[str],
                   port: str | list[int] | None = None,
                   pattern: str | None = None,
                   matches: int | None = None) -> None:
    """Package parameters and invoke scheduler for database operations.

    Stores operation parameters in cf.editargs dictionary and calls the
    scheduler with 'edit' action. The scheduler obtains a lock and then
    dispatches to DbFns.execute() which performs the actual database
    operation.

    **Workflow:**

    1. Package parameters into cf.editargs dictionary
    2. Create Scheduler instance
    3. Call scheduler with 'edit' action
    4. Scheduler obtains lock
    5. Scheduler dynamically imports nf_edit_dbfns
    6. Scheduler creates DbFns instance and calls execute()
    7. DbFns.execute() dispatches to operation method (add/blacklist/delete/remove)

    **Parameters Passed:**

    editargs['cmd']
        Operation name: 'add', 'blacklist', 'delete', or 'remove'

    editargs['iplist']
        List of validated IP address strings

    editargs['port']
        Port specification: "all", [port_numbers], or None

    editargs['pattern']
        Pattern name string or None

    editargs['matches']
        Match count integer or None

    Args:
        cf: Config instance to store parameters
        cmd: Operation command ('add', 'blacklist', 'delete', 'remove')
        iplist: List of validated IP address strings
        port: Port specification or None
        pattern: Pattern name or None
        matches: Match count or None

    Returns:
        None. Operations are performed by DbFns via scheduler.

    Example:
        Add operation::\n
            call_scheduler(cf, 'add', ['192.168.1.100'], [22], 'sshd', 5)

        Delete operation::\n
            call_scheduler(cf, 'delete', ['192.168.1.100'])

        Blacklist with existing database values::\n
            call_scheduler(cf, 'blacklist', ['192.168.1.100'], None, None, 1)
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments

    # For editing commands - push arguments into cf
    # and call scheduler to get a lock
    cf.editargs = {}
    cf.editargs['cmd'] = cmd
    cf.editargs['iplist'] = iplist
    cf.editargs['port'] = port
    cf.editargs['pattern'] = pattern
    cf.editargs['matches'] = matches
    sc: Scheduler = Scheduler(cf)
    sc.run('edit')
    # will re-appear in nf_edit_dbfns

if __name__ == '__main__':
    main()
