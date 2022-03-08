""" nftfw nft command API

Provides various functions to access and change the installed
nftables, uses libnftables to execute nft commands

"""

from pathlib import Path
import logging
from . nftables import Nftables

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

    # pylint: disable=unused-argument

    doing = 'Loading'
    if test:
        doing = 'Testing'
    log.info('%s nft rulesets from %s', doing, filename)

    nft = Nftables()

    if dirname != '':
        nft.add_include_path(dirname)
        filename = Path(dirname) / Path(filename)
    else:
        filename = Path(filename)

    if not filename.exists():
        log.error('Cannot find file: %s', str(filename))
        return False

    if test:
        nft.set_dry_run(True)

    rc, _, errors = nft.cmd_from_file(filename)

    if test:
        nft.set_dry_run(False)

    if errors != '':
        log.error('nft using %s: failed', str(filename))
        log.error(errors)
        return False

    if rc != 0:
        log.error('nft using %s: failed - unspecified error', str(filename))
        return False

    return True

def nft_flush(cf):
    """ Flush rulesets """

    # pylint: disable=unused-argument

    log.info('Flushing nft rulesets')

    nft = Nftables()
    _, _, errors = nft.cmd('flush ruleset')

    if errors != "":
        log.error('nft flush failed')
        log.error(errors)
        return False

    return True

def nft_ruleset(cf):
    """Read entire ruleset from nftables

    Returns
    -------
    tuple
        (rules, errors)
    """

    # pylint: disable=unused-argument

    nft = Nftables()
    _, rules, errors = nft.cmd('list ruleset')
    return (rules, errors)

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

    # check if file exists unless force is True
    path = cf.varfilepath('backup')
    if not force and path.exists():
        return 'preserve'

    # get the rules
    (rules, errs) = nft_ruleset(cf)
    if errs != '':
        log.error('Error reading rulesets from nftables %s', errs)
        return 'errors'

    path.write_text(rules)
    return 'written'

def nft_restore_backup(cf, nodelete=False):
    """Restore backup and delete the backup file
    unless nodelete is True
    """

    # check if file exists
    path = cf.varfilepath('backup')
    if not path.exists():
        log.error('Backup file %s not found', str(path))
        return False
    # flush ruleset
    if not nft_flush(cf):
        # flush reports errors
        log.error('Backup file %s not deleted', str(path))
        return False
    # load backup
    log.info('Loading backup settings from %s', str(path))
    res = nft_load(cf, '', str(path))
    if not res:
        # will be errors above
        log.error('Backup file %s not deleted', str(path))
        return False

    if not nodelete:
        path.unlink()
    return True

def nft_delete_backup(cf):
    """ Delete the backup file """

    # check if file exists
    path = cf.varfilepath('backup')
    if path.exists():
        path.unlink()
