""" nftfwedit - Manage entries in the nftfw blacklist database

usage: nftfwedit [-h] [-d | -a | -b] [-p PORT] [-n PATTERN] [-q] [-v]
                 [ipaddress [ipaddress ...]]

Manage IP addresses in the nftfw blacklist database

positional arguments:
  ipaddress             IP address list

optional arguments:
  -h, --help            show this help message and exit
  -d, --delete          Delete the ip from the database and if present, from the
                        blacklist directory.
  -a, --add             Add the ip to the database - requires port and pattern
                        arguments.
  -b, --blacklist       Add ip to blacklist directory. If necessary add the ip to the
                        database, and then requires port and pattern arguments.
  -g, --gethostname     Include hostname information when printing ip address
                        information. Can be slow for ip addresses with no information.
  -p PORT, --port PORT  Port for -a or -b action, 'all' or port number or comma
                        separated numeric port list (no spaces)
  -n PATTERN, --pattern PATTERN
                        Pattern name for the -a or -b action
  -q, --quiet           Suppress printing of errors on console, syslog output remains
                        active
  -v, --verbose         Show information messages

If one of -d, -a, -b is not supplied, nftfwedit prints information about the
ip address arguments. Information from the blacklist database is printed if
available, along with the country of origin (if geoip2 is installed) and output
from any DNS blocklists, if specified in config.ini.

"""
import sys
import argparse
import logging
from .config import Config
from .nf_edit_validate import validate_and_return_ip_list
from .nf_edit_validate import validate_port
from .nf_edit_validate import validate_pattern
from .nf_edit_print import PrintInfo
from .scheduler import Scheduler
log = logging.getLogger('nftfw')

def main():
    """ Main action """

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
                    help="Delete the ip from the database " \
                    + "and if present, from the blacklist directory.",
                    action='store_true')
    gp.add_argument('-a', '--add',
                    help="Add the ip to the database - requires port and pattern arguments.",
                    action='store_true')
    gp.add_argument('-b', '--blacklist',
                    help='Add ip to blacklist directory. If necessary '\
                    + 'add the ip to the database, and then requires port and pattern arguments.',
                    action='store_true')
    gp.add_argument('-g', '--gethostname',
                    help='Include hostname information when printing ip address information. '\
                    + 'Can be slow for ip addresses with no information.',
                    action='store_true')
    ap.add_argument('-p', '--port',
                    help='Port for -a or -b action, \'all\' or port '\
                    + 'number or comma separated numeric port list (no spaces)')
    ap.add_argument('-n', '--pattern', help="Pattern name for the -a or -b action")
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
        cf.set_logger(logprint=False)
        emsg = 'Aborted: Configuration problem: {0}'.format(str(e))
        log.critical(emsg)
        sys.exit(1)

    # Load the ini file if there is one
    # options can set new values into the ini setup
    # to override
    try:
        cf.readini()
    except AssertionError as e:
        cf.set_logger(logprint=False)
        emsg = 'Aborted: {0}'.format(str(e))
        log.critical(emsg)
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
        emsg = 'Aborted: Configuration problem: {0}'.format(str(e))
        log.critical(emsg)
        sys.exit(1)

    if args.delete:
        run_delete(cf, ap, args)

    elif args.add:
        run_add(cf, ap, args)

    elif args.blacklist:
        run_blacklist(cf, ap, args)

    elif args.pattern:
        print('-n (pattern) is used with the -a and -b options')

    elif args.port:
        print('-p (port) is used with the -a and -b options')

    elif args.gethostname:
        print_info(cf, args, gethostname=True)

    else:
        if not any(args.ipaddress):
            ap.print_usage()
            sys.exit(0)
        print_info(cf, args)


def print_info(cf, args, gethostname=False):
    """ Print the information """

    config = cf.get_ini_values_by_section('Nftfwls')
    cf.date_fmt = config['date_fmt']

    pi = PrintInfo(cf)
    addnl = len(args.ipaddress) != 1
    for ip in args.ipaddress:
        pi.print_ip(ip, showhostinfo=gethostname)
        if addnl:
            print()

def run_delete(cf, ap, args):
    """Run the delete command"""

    cf.am_i_root()
    if args.port is not None \
       or args.pattern is not None:
        ap.print_usage()
        print('-p (port) and -n (pattern) are not used with -d (delete)')
        sys.exit(1)
    iplist = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'delete', iplist)


def run_add(cf, ap, args):
    """Run the add command """

    cf.am_i_root()
    if args.port is None \
       or args.pattern is None:
        ap.print_usage()
        print('-p (port) and -n (pattern) must both be supplied with -a (add)')
        sys.exit(1)
    port, pattern = port_and_pattern_check(ap, args.port, args.pattern)
    iplist = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'add', iplist, port, pattern)

def run_blacklist(cf, ap, args):
    """Run the blacklist command"""

    cf.am_i_root()
    port = None
    pattern = None
    if args.port is not None \
       or args.pattern is not None:
        if args.port is None \
           or args.pattern is None:
            ap.print_usage()
            print('-p (port) and -n (pattern) must both be supplied')
            sys.exit(1)
        port, pattern = port_and_pattern_check(ap, args.port, args.pattern)
    iplist = validate_and_return_ip_list(args.ipaddress)
    if any(iplist):
        call_scheduler(cf, 'blacklist', iplist, port, pattern)

def port_and_pattern_check(ap, port, pattern):
    """Check ports and patterns"""

    # check on port
    okport, port = validate_port(port)
    # check on pattern
    okpattern, pattern = validate_pattern(pattern)
    # if ok is False, error is in second value
    if not okport:
        ap.print_usage()
        print(port)
        if not okpattern:
            print(pattern)
        sys.exit(1)
    if not okpattern:
        ap.print_usage()
        print(pattern)
        sys.exit(1)
    return(port, pattern)

def call_scheduler(cf, cmd, iplist, port=None, pattern=None):
    """Push arguments into cf and call the scheduler

    to obtain a lock
    """

    # For editing commands - push arguments into cf
    # and call scheduler to get a lock
    cf.editargs = {}
    cf.editargs['cmd'] = cmd
    cf.editargs['iplist'] = iplist
    cf.editargs['port'] = port
    cf.editargs['pattern'] = pattern
    sc = Scheduler(cf)
    sc.run('edit')
    # will re-appear in nf_edit_dbfns

if __name__ == '__main__':
    main()
