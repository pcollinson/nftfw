""" nftfw nft command API

Provides various functions to access and change the installed
nftables, uses libnftables to execute nft commands

There are two possible implementations
nft_shell.py - the original code using /usr/sbin/nft command
	to talk to the nftables
nft_python.py - uses extended nftables python module to
        talk to libnftables

This code uses the nft_select value in config to choose which
of the implementations to use.

"""

import logging
from . import nft_python
from . import nft_shell

log = logging.getLogger('nftfw')

def nft_load(cf, dirname, filename, test=False):
    """ Execute nft on named arguments

    If fails put short message into log files but output full data
    from nft on stderr

    Parameters
    ----------
    cf : Config
    dirname : str
        where to find the files can be '',
        added to the search path for files
    filename : str
        filename to run
    test :  bool
        if true run nft dry_run set to True

    Returns
    -------
    bool
        True if successful
        False if not
    """

    if cf.nft_select == 'python':
        return nft_python.nft_load(cf, dirname, filename, test)
    else:
        return nft_shell.nft_load(cf, dirname, filename, test)

def nft_flush(cf):
    """ Flush rulesets """

    if cf.nft_select == 'python':
        return nft_python.nft_flush(cf)
    else:
        return nft_shell.nft_flush(cf)

def nft_ruleset(cf):
    """Read entire ruleset from nftables

    Returns
    -------
    tuple
        (rules, errors)
    """

    if cf.nft_select == 'python':
        return nft_python.nft_ruleset(cf)
    else:
        return nft_shell.nft_ruleset(cf)


def nft_save_backup(cf, force=False):
    """Save current nftables settings to a the backup file

    Parameters
    ----------
    force : bool
        If true forces a backup

    Returns
    -------
    str
        preserve  if the backup file exist
        errors    if any errors reading the nft contents
        written   if the save is OK
    """

    if cf.nft_select == 'python':
        return nft_python.nft_save_backup(cf, force)
    else:
        return nft_shell.nft_save_backup(cf, force)

def nft_restore_backup(cf, nodelete=False):
    """Restore backup and delete the backup file
    unless nodelete is True
    """

    if cf.nft_select == 'python':
        return nft_python.nft_restore_backup(cf, nodelete)
    else:
        return nft_shell.nft_restore_backup(cf, nodelete)

def nft_delete_backup(cf):
    """ Delete the backup file """

    if cf.nft_select == 'python':
        return nft_python.nft_delete_backup(cf)
    else:
        return nft_shell.nft_delete_backup(cf)
