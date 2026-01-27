"""Standard command-line argument processing for nftfw.

This module processes standard command-line arguments that are common across
all nftfw commands. These arguments control logging behaviour and allow
configuration value overrides via the command line.

Standard Arguments
------------------
**-q, --quiet**
    Suppress console error messages. Syslog output remains active.
    Sets logprint=False in Config.

**-v, --verbose**
    Show information messages (DEBUG level logging).
    Sets loglevel='DEBUG' in Config.

**-o, --option KEY=VALUE**
    Override configuration values from command line.
    Can be used multiple times.
    Comma-separated values are supported: -o key1=val1,key2=val2
    Section names are not needed (keys are unique across sections).

Option Format
-------------
The -o/--option flag accepts key=value pairs in several formats:

Single option::

    -o blacklist_counter=true

Multiple -o flags::

    -o blacklist_counter=true -o whitelist_logging=Nftfw

Comma-separated options::

    -o blacklist_counter=true,whitelist_logging=Nftfw

Key matching is case-insensitive for the key name.

Value Types
-----------
String values:
    Assigned directly: -o ini_file=/etc/nftfw.ini
    Empty string becomes None: -o some_value=

Boolean values:
    Must be 'true' or 'false' (case-insensitive)
    Example: -o blacklist_counter=true

Special Cases
-------------
The 'root' key is not allowed via -o. Use -c/--config instead to specify
an alternate configuration file location.

Workflow
--------
1. Process -q (quiet) flag if present
2. Process -v (verbose) flag if present
3. Parse all -o (option) flags
4. Split comma-separated options
5. Match each option against regex (key=value format)
6. Validate key is recognized
7. Apply value with correct type conversion

Error Handling
--------------
The function calls sys.exit(1) on errors:
- Invalid option format (not key=value)
- Attempt to set 'root' via -o
- Unrecognized key name
- Boolean value not 'true' or 'false'

Usage Example
-------------
From __main__.py::

    from .config import Config
    from .stdargs import nftfw_stdargs

    cf = Config(dosetup=False)
    cf.readini()

    # Process standard arguments
    nftfw_stdargs(cf, args)

    # Now cf has logging configured and overrides applied
    cf.setup()

See Also
--------
config.py : Configuration management
__main__.py : Main entry point that calls this function

"""
from __future__ import annotations

from typing import TYPE_CHECKING
import sys
import re

if TYPE_CHECKING:
    import argparse
    from .config import Config


def nftfw_stdargs(cf: Config, args: argparse.Namespace) -> None:
    """Process standard command-line arguments and apply to configuration.

    Handles three standard arguments: -q (quiet), -v (verbose), and
    -o (option). Modifies the Config instance with logging settings
    and configuration overrides.

    Args:
        cf: Configuration instance to modify
        args: Parsed command-line arguments from argparse.ArgumentParser.
              Expected attributes:
              - quiet: bool (from -q/--quiet flag)
              - verbose: bool (from -v/--verbose flag)
              - option: list[str] | None (from -o/--option, can be repeated)

    Returns:
        None. Modifies cf instance as side effect.

    Exits:
        Calls sys.exit(1) if invalid option format or unrecognized key.

    Note:
        This function is called after cf.readini() but before cf.setup()
        in the standard workflow. This allows command-line options to
        override config file values before final setup.

        Logging changes take effect immediately. Config value overrides
        are stored and applied during cf.setup().

    Example:
        Standard usage from __main__.py::

            cf = Config(dosetup=False)
            cf.readini()
            nftfw_stdargs(cf, args)  # Apply overrides
            cf.setup()  # Complete setup with overrides

    """
    # Process quiet flag (suppress console output)
    if args.quiet:
        cf.set_logger(logprint=False)

    # Process verbose flag (enable DEBUG level)
    if args.verbose:
        cf.set_logger(loglevel='DEBUG')

    # If no -o options provided, nothing more to do
    if args.option is None:
        return

    # Decode command line overrides into the config system
    # Allow comma-separated options in single -o flag
    allopts: list[str] = []
    for opt in args.option:
        if "," in opt:
            # Split comma-separated options
            for s in opt.split(','):
                allopts.append(s.strip())
        else:
            allopts.append(opt.strip())

    # Process each option with key=value format
    eqre: re.Pattern[str] = re.compile(r'([a-z_]*)\s*=\s*(.*)$')
    for opts in allopts:
        match: re.Match[str] | None = eqre.match(opts)
        if match:
            _action_vals(cf, match.group(1), match.group(2))
        else:
            print('-o values have format key=value')
            sys.exit(1)


def _action_vals(cf: Config, key: str, val: str) -> None:
    """Apply a key=value override to configuration.

    Validates the key name, determines the appropriate type conversion,
    and applies the override to the Config instance.

    Args:
        cf: Configuration instance to modify
        key: Configuration key name (without section prefix)
        val: String value from command line

    Returns:
        None. Modifies cf instance as side effect.

    Exits:
        Calls sys.exit(1) if:
        - key is 'root' (must use -c instead)
        - key is not recognized
        - boolean value is not 'true' or 'false'

    Note:
        The key is matched against cf.ini_string_change and
        cf.ini_boolean_change dictionaries to determine type.

        For string values:
        - Empty string '' is converted to None
        - Other strings are used as-is

        For boolean values:
        - 'true' (case-insensitive) → True
        - 'false' (case-insensitive) → False
        - Other values cause exit with error message

    Example:
        Internal use only (called from nftfw_stdargs)::

            _action_vals(cf, 'blacklist_counter', 'true')
            # Sets cf config value blacklist_counter to True

            _action_vals(cf, 'ini_file', '/etc/nftfw.ini')
            # Sets cf config value ini_file to '/etc/nftfw.ini'

    """
    # Special case: 'root' must be set via -c flag, not -o
    if key == 'root':
        print('Use the -c option to set a config file')
        sys.exit(1)

    # Check if key is a valid string config option
    if key in cf.ini_string_change:
        cf.set_ini_value(key, val)

    # Check if key is a valid boolean config option
    elif key in cf.ini_boolean_change:
        if val.lower() == 'true':
            cf.set_ini_value(key, True)
        elif val.lower() == 'false':
            cf.set_ini_value(key, False)
        else:
            print(f'Value of {key} must be \'true\' or \'false\'')
            sys.exit(1)

    # Key not recognized
    else:
        print(f'Option {key} not recognised, use -i argument '
              + 'to get a list (section names are not needed)')
        sys.exit(1)
