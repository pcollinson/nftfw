"""Firewall management commands for nftfwadm utility.

This module provides wrapper functions for common firewall management operations
(save, restore, clean) used by the nftfwadm command-line utility. It delegates
to the nft module for actual nftables interaction.

Historical Note
---------------
This module started as a more complicated implementation but has been simplified
as functionality moved into the nft module. It remains as a clean interface
layer between nftfwadm and the nft module.

Commands
--------
**save**
    Creates a forced backup of current nftables rules, overwriting any existing
    backup. Used to manually save the current firewall state.

**restore**
    Restores nftables rules from the backup file and deletes the backup on
    success. Used to revert to a previously saved state.

**clean**
    Deletes the backup file without restoring. Used to clean up after
    successful changes.

Workflow
--------
These commands are invoked by the nftfwadm utility (or via scheduler when
'save', 'restore', or 'clean' actions are requested)::

    1. User runs: nftfwadm save
    2. Scheduler calls: fw_save(cf)
    3. fw_save() calls: nft.nft_save_backup(cf, force=True)
    4. Backup file created at cf.varfilepath('nftables.backup')

Usage Example
-------------
Via nftfwadm utility::

    # Save current rules
    nftfwadm save

    # Make changes to firewall
    nftfw load

    # If something goes wrong, restore
    nftfwadm restore

    # If everything is good, clean up backup
    nftfwadm clean

From Python code::

    from .config import Config
    from . import fwcmds

    cf = Config()

    # Create backup before making changes
    fwcmds.fw_save(cf)

    # ... make firewall changes ...

    # If changes failed, restore
    fwcmds.fw_restore(cf)

    # If changes succeeded, remove backup
    fwcmds.fw_clean(cf)

See Also
--------
nft.py : Provides the underlying nftables operations
scheduler.py : Invokes these commands based on user actions
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import logging
from . import nft

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')


def fw_save(cf: Config) -> None:
    """Save current nftables rules to backup file (forced overwrite).

    Creates a backup of the current nftables ruleset by reading all rules from
    the kernel and saving them to the backup file. Always overwrites any existing
    backup file (force=True).

    This is the 'save' action in nftfwadm, used to manually create a backup
    before making firewall changes.

    Args:
        cf: Config instance for accessing paths and nft_select setting

    Returns:
        None

    Example:
        Manual backup before changes::

            from .config import Config
            from . import fwcmds

            cf = Config()
            fwcmds.fw_save(cf)
            log.info("Backup created, safe to make changes")

        Via nftfwadm::

            $ nftfwadm save
            # Backup file created at /var/lib/nftfw/nftables.backup

    Note:
        Unlike nft.nft_save_backup(), this always forces overwrite (force=True).
        The backup file location is cf.varfilepath('nftables.backup').

    See Also:
        nft.nft_save_backup() : Underlying backup function
        fw_restore() : Restore from backup
        fw_clean() : Delete backup file
    """
    log.info('Install backup file')
    nft.nft_save_backup(cf, force=True)


def fw_restore(cf: Config) -> None:
    """Restore nftables rules from backup file.

    Loads the backup file and installs those rules into the kernel, replacing
    the current ruleset. The backup file is automatically deleted after
    successful restoration.

    This is the 'restore' action in nftfwadm, used to revert to a previously
    saved firewall state after a failed change.

    Args:
        cf: Config instance for accessing paths and nft_select setting

    Returns:
        None

    Example:
        Restoring after failed changes::

            from .config import Config
            from . import fwcmds

            cf = Config()

            # Save current state
            fwcmds.fw_save(cf)

            # Try to make changes
            try:
                # ... firewall changes ...
                pass
            except Exception:
                # Changes failed, restore backup
                fwcmds.fw_restore(cf)
                log.error("Restored previous firewall state")

        Via nftfwadm::

            $ nftfwadm restore
            # Rules restored from /var/lib/nftfw/nftables.backup
            # Backup file deleted after successful restore

    Note:
        If restoration fails, the backup file is preserved for retry.
        The backup file is deleted only on successful restoration.

    See Also:
        nft.nft_restore_backup() : Underlying restore function
        fw_save() : Create backup
        fw_clean() : Delete backup without restoring
    """
    nft.nft_restore_backup(cf)


def fw_clean(cf: Config) -> None:
    """Delete the nftables backup file.

    Removes the backup file created by fw_save() without restoring it. This is
    typically used after successful firewall changes to clean up the backup.

    This is the 'clean' action in nftfwadm, used to remove the backup file
    once you're confident the new rules are working correctly.

    Args:
        cf: Config instance for accessing paths and nft_select setting

    Returns:
        None

    Example:
        Cleaning up after successful changes::

            from .config import Config
            from . import fwcmds
            from . import nft

            cf = Config()

            # Save current state
            fwcmds.fw_save(cf)

            # Install new rules
            success = nft.nft_load(cf, dirname, filename)

            if success:
                # New rules working, remove backup
                fwcmds.fw_clean(cf)
                log.info("Backup removed, changes confirmed")
            else:
                # Something went wrong, restore
                fwcmds.fw_restore(cf)

        Via nftfwadm::

            $ nftfwadm clean
            # Backup file /var/lib/nftfw/nftables.backup deleted

    Note:
        This does not restore the backup - it simply deletes it.
        Make sure the current ruleset is working before cleaning.

    See Also:
        nft.nft_delete_backup() : Underlying delete function
        fw_save() : Create backup
        fw_restore() : Restore from backup
    """
    log.info('Delete backup file')
    nft.nft_delete_backup(cf)
