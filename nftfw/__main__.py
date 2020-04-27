"""nftfw main module """

import sys
import argparse
import re
from pathlib import Path
import pkg_resources
from config import Config
from scheduler import Scheduler
from stdargs import nftfw_stdargs

def main():
    """ Main action """

    version = pkg_resources.require('nftfw')[0].version

    desc = """Firewall management system for nftables based on the Symbiosis firewall"""
    epilog = '\n'.join(["""Main action commands:
    load       Load firewall.
    whitelist  Load whitelist by scanning the system wtmp file, setting
               entries in the whitelist directory.
    blacklist  Load blacklist using files in the patterns directory
               to scan log files, automatically expire entries.
               Use -x to scan and print matches without storing any information.
               Use -p patternname to only process a specific pattern file usually
               for testing.
    tidy       Tidy firewall database by removing entries that are older than
               a set number of days. Intended to be run from cron daily

    """, f'Version: {version}\n'])


    ap = argparse.ArgumentParser(prog='nftfw',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=desc,
                                 epilog=epilog)
    ap.add_argument('-c', '--config',
                    help='Supply a configuration file overriding the built-in file')
    ap.add_argument('-x', '--no-exec',
                    help='Create and test rules, but don\'t install. " \
                    + "Also applies to blacklist, where it scans for possible bad guys, " \
                    + "but doesn\'t store anything.',
                    action='store_true')
    ap.add_argument('-f', '--full',
                    help='Perform a full install, don\'t just update sets',
                    action='store_true')
    ap.add_argument('-p', '--pattern',
                    help='For blacklist, run using one pattern name',
                    action='store')
    ap.add_argument('-i', '--info',
                    help='Display current config settings and exit',
                    action='store_true')
    ap.add_argument('-o', '--option',
                    help='Specify comma separated list of option=value. ' \
                    + 'Overrides values from compiled values and config file. ' \
                    + 'Can be used several times',
                    action='append')
    ap.add_argument('-q', '--quiet',
                    help='Suppress printing of errors on console, syslog output remains active',
                    action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='Show information messages', action='store_true')
    ap.add_argument('action', nargs='?',
                    help='Action to take',
                    choices=['load', 'whitelist', 'blacklist', 'tidy'])
    args = ap.parse_args()

    # Sort out config but don't init anything as yet
    cf = Config(dosetup=False)

    # allow change of config file
    if args.config:
        file = Path(args.config)
        if file.is_file():
            cf.set_ini_value_with_section('Locations', 'ini_file', str(file))
        else:
            print(f'Cannot find config file: {args.config}')
            sys.exit(1)

    # Load the ini file if there is one options can set new values
    # into the ini setup to override

    cf.readini()

    # decode and action standard args
    nftfw_stdargs(cf, args)

    # list options and exit
    if args.info:
        print(repr(cf))
        sys.exit(0)

    # Check on actions
    if args.action not in ('load', 'whitelist', 'blacklist', 'tidy'):
        ap.print_help(sys.stderr)
        sys.exit(1)

    # Now set things up
    cf.setup()

    # install arguments into cf values
    if args.full:
        cf.force_full_install = True

    if args.no_exec:
        cf.create_build_only = True

    if args.pattern:
        # convenience - remove .patterns
        pa = args.pattern
        m = re.match(r'^(.*)\.patterns$', pa)
        if m:
            pa = m.group(1)
        cf.selected_pattern_file = pa

    # no return if not true
    cf.am_i_root()

    sc = Scheduler(cf)
    sc.run(args.action)


if __name__ == '__main__':
    main()
    sys.exit(0)
