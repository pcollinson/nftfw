""" nftfw nft command API

Provides various functions to access and change the installed
nftables, uses shell to call the nft command

Uses the 3.6 version of subprocess to support 3.6 installations

"""

import subprocess
from pathlib import Path
import logging
log = logging.getLogger('nftfw')

def nft_load(cf, dirname, filename, test=False):
    """ Execute nft on named arguments

    If fails put short message into log files but output full data
    from nft on stderr

    Parameters
    ----------
    cf : config object
    dirname : str
        where to find the files can be '',
        when the -I flag is not given to nft
    filename : str
        filename to run
    test :  bool
        f true run nft using -c

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

    args = ['/usr/sbin/nft']

    if dirname != '':
        args += ['-I', dirname]
        filename = Path(dirname) / Path(filename)
    else:
        filename = Path(filename)

    if not filename.exists():
        log.error('Cannot find file: %s', str(filename))
        return False

    if test:
        args += ['-c']

    args += ['-f', str(filename)]
    compl = subprocess.run(args,
                           stderr=subprocess.PIPE)
    if compl.stderr != b'':
        errs = compl.stderr.decode()
        log.error('nft using %s: failed', str(filename))
        log.error(errs)
        return False

    return True

def nft_flush(cf):
    """ Flush rulesets """

    # pylint: disable=unused-argument

    log.info('Flushing nft rulesets')
    args = ['/usr/sbin/nft', 'flush', 'ruleset']
    compl = subprocess.run(args, stderr=subprocess.PIPE)
    if compl.stderr != b'':
        errs = compl.stderr.decode()
        log.error('nft flush failed')
        log.error(errs)
        return False

    return True

def nft_ruleset(cf):
    """Read entire ruleset from nftables

    Returns
    -------
    tuple
        (decoded stdout, decoded stderr)
    """
    # pylint: disable=unused-argument

    args = ['/usr/sbin/nft', 'list', 'ruleset']
    compl = subprocess.run(args, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    rules = '' if compl.stdout == b'' else compl.stdout.decode()
    errs = ''  if compl.stderr == b'' else compl.stderr.decode()
    return (rules, errs)

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
