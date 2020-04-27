"""nftfwadm  management options

Manages save, restore and clean for nftfwadm
Called from fwmanage

This started life as being considerably more complicated but things
have moved into the nft module Decided to leave this in place

"""
import logging
import nft
log = logging.getLogger('nftfw')


def fw_save(cf):
    """fw_save entry point

    Saves a backup file using current nftables settings,
    replaces any extant file

    Parameters
    ----------
    cf : Config
    """

    log.info('Install backup file')
    nft.nft_save_backup(cf, force=True)

def fw_restore(cf):
    """fw_restore entry point

    Calls nft_restoreBackup

    Parameters
    ----------
    cf : Config
    """

    nft.nft_restore_backup(cf)

def fw_clean(cf):
    """fw_clean entry point

    Removes backup file

    Parameters
    ----------
    cf : Config
    """

    log.info('Delete backup file')
    nft.nft_delete_backup(cf)
