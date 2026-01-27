"""nftfw nftables Python backend using libnftables.

This module provides the Python-based implementation of the nftables interface
using the system-installed nftables Python library. It offers functions to:

- Load and test nftables rule files
- Flush the current ruleset
- Read the active ruleset
- Backup and restore nftables configurations

The module uses the Nftables class from the nftables library to execute
commands and manage firewall rules without spawning shell processes.

Example:
    Loading firewall rules with test mode::

        from nftfw.config import Config
        from nftfw.nft_python import nft_load

        cf = Config()
        success = nft_load(cf, '/etc/nftfw/build.d', 'nftfw.nft', test=True)
        if success:
            print("Rules validated successfully")

    Creating and restoring a backup::

        from nftfw.nft_python import nft_save_backup, nft_restore_backup

        # Save current state
        result = nft_save_backup(cf, force=True)
        if result == 'written':
            print("Backup created")

        # Restore if needed
        if nft_restore_backup(cf):
            print("Backup restored successfully")
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from pathlib import Path
import logging
from nftables import Nftables  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

def nft_load(cf: Config, dirname: str, filename: str, test: bool = False) -> bool:
    """Execute nft commands from a file.

    Loads nftables rules from the specified file, optionally using dry-run mode
    for testing. If a directory is provided, it's added to the nftables include
    path to resolve any include directives in the rule file.

    Args:
        cf: Configuration object (currently unused but maintained for API consistency)
        dirname: Directory path to add to include search path (empty string to skip)
        filename: Name of the nftables rule file to load
        test: If True, execute in dry-run mode without actually loading rules

    Returns:
        True if rules loaded (or validated) successfully, False on error

    Example:
        Test rules before loading::

            cf = Config()
            if nft_load(cf, '/etc/nftfw/build.d', 'nftfw.nft', test=True):
                # Rules are valid, load for real
                nft_load(cf, '/etc/nftfw/build.d', 'nftfw.nft')
    """

    # pylint: disable=unused-argument

    doing = 'Loading'
    if test:
        doing = 'Testing'
    log.info('%s nft rulesets from %s', doing, filename)

    nft = Nftables()

    if dirname != '':
        nft.add_include_path(dirname)
        filepath = Path(dirname) / Path(filename)
    else:
        filepath = Path(filename)

    if not filepath.exists():
        log.error('Cannot find file: %s', str(filepath))
        return False

    if test:
        nft.set_dry_run(True)

    rc, _, errors = nft.cmd_from_file(filepath)

    if test:
        nft.set_dry_run(False)

    if errors != '':
        log.error('nft using %s: failed', str(filepath))
        log.error(errors)
        return False

    if rc != 0:
        log.error('nft using %s: failed - unspecified error', str(filepath))
        return False

    return True

def nft_flush(cf: Config) -> bool:
    """Flush all nftables rulesets.

    Removes all tables, chains, and rules from the active nftables
    configuration. This is a destructive operation that clears the
    entire firewall state.

    Args:
        cf: Configuration object (currently unused but maintained for API consistency)

    Returns:
        True if flush succeeded, False on error

    Example:
        Clear all firewall rules::

            cf = Config()
            if nft_flush(cf):
                print("Firewall rules cleared")
            else:
                print("Failed to flush rules")
    """

    # pylint: disable=unused-argument

    log.info('Flushing nft rulesets')

    nft = Nftables()
    _, _, errors = nft.cmd('flush ruleset')

    if errors != "":
        log.error('nft flush failed')
        log.error(errors)
        return False

    return True

def nft_ruleset(cf: Config) -> tuple[str, str]:
    """Read entire ruleset from nftables.

    Retrieves the complete active nftables configuration as text,
    suitable for saving to a file or comparing with generated rules.

    Args:
        cf: Configuration object (currently unused but maintained for API consistency)

    Returns:
        Tuple of (rules, errors) where:
        - rules: String containing the complete nftables ruleset
        - errors: String containing any error messages (empty if successful)

    Example:
        Retrieve and display current rules::

            cf = Config()
            rules, errors = nft_ruleset(cf)
            if not errors:
                print("Current ruleset:")
                print(rules)
            else:
                print(f"Error: {errors}")
    """

    # pylint: disable=unused-argument

    nft = Nftables()
    _, rules, errors = nft.cmd('list ruleset')
    return (rules, errors)

def nft_save_backup(cf: Config, force: bool = False) -> str:
    """Save current nftables settings to the backup file.

    Creates a backup of the active nftables ruleset to allow restoration
    if a new configuration causes problems. By default, refuses to overwrite
    an existing backup file unless force is True.

    Args:
        cf: Configuration object providing the backup file path
        force: If True, overwrite existing backup file; if False, preserve existing backup

    Returns:
        One of three status strings:
        - 'preserve': Backup file already exists and force=False
        - 'errors': Failed to read current nftables ruleset
        - 'written': Backup successfully created

    Example:
        Create backup before loading new rules::

            cf = Config()
            status = nft_save_backup(cf, force=True)
            if status == 'written':
                print("Backup created successfully")
            elif status == 'preserve':
                print("Backup already exists")
            else:
                print("Failed to create backup")
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

def nft_restore_backup(cf: Config, nodelete: bool = False) -> bool:
    """Restore backup and optionally delete the backup file.

    Restores the nftables configuration from a previously saved backup file.
    This performs a three-step process: flush current rules, load backup rules,
    and optionally delete the backup file. If any step fails, the backup file
    is preserved.

    Args:
        cf: Configuration object providing the backup file path
        nodelete: If True, preserve backup file after restoration; if False, delete it

    Returns:
        True if backup restored successfully, False on error

    Example:
        Restore previous configuration::

            cf = Config()
            if nft_restore_backup(cf, nodelete=True):
                print("Backup restored (file preserved)")
            else:
                print("Restore failed")
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

def nft_delete_backup(cf: Config) -> None:
    """Delete the backup file.

    Removes the nftables backup file if it exists. This is called after
    successfully loading new rules to clean up the backup.

    Args:
        cf: Configuration object providing the backup file path

    Example:
        Clean up after successful rule load::

            cf = Config()
            nft_delete_backup(cf)
            print("Backup file deleted")
    """

    # check if file exists
    path = cf.varfilepath('backup')
    if path.exists():
        path.unlink()
