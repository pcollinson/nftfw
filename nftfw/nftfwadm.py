"""nftfwadm - admin tools for managing nftfw installation
"""
import sys
import argparse
from pathlib import Path
import pkg_resources
from .config import Config
from .scheduler import Scheduler
from .stdargs import nftfw_stdargs

def main():
    """ Main action """

    version = pkg_resources.require('nftfw')[0].version

    desc = 'Admin tools for managing nftfw installation'
    epilog = '\n'.join(["""Actions:
    save       Saves the currently installed nftables settings
               in a file, which is used for recovery by nftfw if problems
               happen with installation.

               If the file doesn't exist, the current settings are
               stored in the file before installation and then recovered
               when problems occur. The save option allows reverting
               back to non-nftfw settings when testing.

    restore    Restores the saved values in the nft settings and
               replaces /etc/nftables.conf.

    clean      Deletes backup file

    """, f'Version: {version}\n'])

    ap = argparse.ArgumentParser(prog='nftfwadm',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=desc,
                                 epilog=epilog)
    ap.add_argument('-c', '--config',
                    help='Supply a configuration file overriding the built-in file')
    ap.add_argument('-i', '--info',
                    help='Display current config settings and exit',
                    action='store_true')
    ap.add_argument('-o', '--option',
                    help='Specify comma separated list of option=value.' \
                    + 'Overrides values from compiled values and config file. ' \
                    + 'Can be used several times',
                    action='append')
    ap.add_argument('-q', '--quiet',
                    help='Suppress printing of errors on console, syslog output remains active',
                    action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='Show information messages', action='store_true')
    ap.add_argument('action', nargs='?',
                    help='Action to take', choices=['save', 'restore', 'clean'])
    args = ap.parse_args()

    #
    # Sort out config
    # but don't init anything as yet
    #

    try:
        cf = Config(dosetup=False)
    except AssertionError as e:
        print(f'Aborted: Configuration problem: {str(e)}')
        sys.exit(1)

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
    try:
        cf.readini()
    except AssertionError as e:
        print(f'Aborted: {str(e)}')
        sys.exit(1)

    # decode and action standard args
    nftfw_stdargs(cf, args)

    # list options and exit
    if args.info:
        print(repr(cf))
        sys.exit(0)

    # Check on actions
    if args.action not in ('clean', 'save', 'restore'):
        ap.print_help(sys.stderr)
        sys.exit(1)

    # Now set things up
    try:
        cf.setup()
    except AssertionError as e:
        print(f'Aborted: Configuration problem: {str(e)}')
        sys.exit(1)

    # no return if not true
    cf.am_i_root()

    sc = Scheduler(cf)
    sc.run(args.action)

if __name__ == '__main__':
    main()
    sys.exit(0)
