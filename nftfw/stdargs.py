""" nftfw - process shared arguments

    -q - quiet
    -v - verbose
    -o OPTION, --option OPTION
         Specify comma separated list of option=value.
         Overrides values from compiled values and config file.
         Can be used several times
"""

import sys
import re


def nftfw_stdargs(cf, args):
    """ Decode and action standard arguments  """

    if args.quiet:
        cf.set_logger(logprint=False)

    if args.verbose:
        cf.set_logger(loglevel='DEBUG')

    if args.option is None:
        return

    # decode command line overrides
    # into the config system
    # allow comma separated single options
    allopts = []
    for opt in args.option:
        if "," in opt:
            for s in opt.split(','):
                allopts.append(s.strip())
        else:
            allopts.append(opt.strip())
    # process options
    eqre = re.compile(r'([a-z_]*)\s*=\s*(.*)$')
    for opts in allopts:
        match = eqre.match(opts)
        if match:
            _action_vals(cf, match.group(1), match.group(2))
        else:
            print('-o values have format key=value')
            sys.exit(1)

def _action_vals(cf, key, val):
    """ Apply key and val """

    if key == 'root':
        print('Use the -c option to set a config file')
        sys.exit(1)

    if key in cf.ini_string_change:
        val = None if val == '' else val
        cf.set_ini_value(key, val)
    elif key in cf.ini_boolean_change:
        if val.lower() == 'true':
            cf.set_ini_value(key, True)
        elif val.lower() == 'false':
            cf.set_ini_value(key, False)
        else:
            print(f'Value of {key} must be \'true\' or \'false\'')
            sys.exit(1)
    else:
        print(f'Option {key} not recognised, use -i argument ' \
              + 'to get a list (section names are not needed)')
        sys.exit(1)
