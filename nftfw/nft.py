"""nftables interface facade for nftfw.

This module provides a unified API for interacting with nftables, delegating to
one of two backend implementations based on configuration. It acts as a facade
that allows switching between shell-based and Python-based nftables interfaces
without changing calling code.

Backend Implementations
-----------------------
**nft_shell.py**
    Original implementation using /usr/sbin/nft command-line tool.
    Suitable for systems without Python nftables bindings.

**nft_python.py**
    Modern implementation using libnftables Python bindings.
    Provides better performance and error handling.

Selection
---------
The backend is selected via the `nft_select` configuration option:
- 'python': Use nft_python.py (Python bindings)
- 'shell': Use nft_shell.py (command-line tool)

Key Features
------------
- Unified API regardless of backend
- Rule loading with test/dry-run mode
- Complete ruleset backup and restore
- Ruleset flushing (remove all rules)
- Consistent error handling across backends

Workflow
--------
1. Configuration specifies backend (cf.nft_select)
2. All functions check cf.nft_select
3. Functions delegate to appropriate backend module
4. Return values and error handling standardised across backends

Usage Example
-------------
Loading rules::

    from .config import Config
    from . import nft

    cf = Config()
    success = nft.nft_load(cf, '/path/to/rules', 'firewall.nft')
    if not success:
        print("Failed to load rules")

Backing up and restoring::

    # Save current ruleset
    result = nft.nft_save_backup(cf)
    if result == 'written':
        print("Backup created")

    # Later, restore from backup
    success = nft.nft_restore_backup(cf)
    if success:
        print("Rules restored")

See Also
--------
nft_python.py : Python-based nftables interface
nft_shell.py : Shell-based nftables interface
fwmanage.py : Main consumer of this module
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import logging
from . import nft_python
from . import nft_shell

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')


def nft_load(cf: Config, dirname: str, filename: str, test: bool = False) -> bool:
    """Execute nft to load rules from a file.

    Loads nftables rules from the specified file, optionally running in test
    mode (dry-run) to validate without installing. If loading fails, logs a
    short error message and outputs full nft error details to stderr.

    The dirname parameter is added to nft's search path for include files,
    allowing rules to reference other files via include directives.

    Args:
        cf: Config instance with nft_select setting
        dirname: Directory to add to nft search path (can be empty string)
        filename: Name of nft rules file to load
        test: If True, run in dry-run mode (validate only, don't install)

    Returns:
        True if rules loaded successfully, False on error

    Example:
        Loading production rules::

            success = nft_load(cf, '/var/lib/nftfw/install.d', 'firewall.nft')
            if not success:
                log.error("Failed to install firewall rules")

        Testing rules before installation::

            # Test in build directory first
            if nft_load(cf, '/var/lib/nftfw/build.d', 'firewall.nft', test=True):
                # Tests passed, now install for real
                nft_load(cf, '/var/lib/nftfw/install.d', 'firewall.nft')

    Note:
        The actual implementation (Python or shell) is selected based on
        cf.nft_select. Both backends provide identical interfaces.
    """
    if cf.nft_select == 'python':
        return nft_python.nft_load(cf, dirname, filename, test)
    return nft_shell.nft_load(cf, dirname, filename, test)


def nft_flush(cf: Config) -> bool:
    """Flush all nftables rulesets.

    Removes all nftables rules, chains, and tables from the kernel. This is
    typically used before loading a completely new ruleset or when resetting
    the firewall to a clean state.

    Args:
        cf: Config instance with nft_select setting

    Returns:
        True if flush successful, False on error

    Example:
        Resetting firewall::

            if nft_flush(cf):
                log.info("Firewall rules flushed")
                # Now load new rules
                nft_load(cf, dirname, filename)

    Warning:
        This removes ALL nftables rules. The system will have no firewall
        protection until new rules are loaded. Use with caution.

    Note:
        The actual implementation (Python or shell) is selected based on
        cf.nft_select. Both backends provide identical interfaces.
    """
    if cf.nft_select == 'python':
        return nft_python.nft_flush(cf)
    return nft_shell.nft_flush(cf)


def nft_ruleset(cf: Config) -> tuple[str, str]:
    """Read entire ruleset from nftables.

    Retrieves the complete current nftables configuration from the kernel,
    including all tables, chains, rules, sets, and maps. The ruleset is
    returned in nft's native format suitable for saving or comparison.

    Args:
        cf: Config instance with nft_select setting

    Returns:
        Tuple of (rules, errors):
            - rules: Complete ruleset as string (nft format)
            - errors: Error messages if any, empty string on success

    Example:
        Reading current ruleset::

            rules, errors = nft_ruleset(cf)
            if not errors:
                print(f"Current ruleset has {len(rules.splitlines())} lines")
                # Save to file
                with open('/tmp/current-rules.nft', 'w') as f:
                    f.write(rules)
            else:
                log.error(f"Failed to read ruleset: {errors}")

        Comparing rulesets::

            old_rules, _ = nft_ruleset(cf)
            # ... make changes ...
            new_rules, _ = nft_ruleset(cf)
            if old_rules != new_rules:
                print("Ruleset changed")

    Note:
        The actual implementation (Python or shell) is selected based on
        cf.nft_select. Both backends provide identical interfaces.
    """
    if cf.nft_select == 'python':
        return nft_python.nft_ruleset(cf)
    return nft_shell.nft_ruleset(cf)


def nft_save_backup(cf: Config, force: bool = False) -> str:
    """Save current nftables settings to the backup file.

    Creates a backup of the current nftables ruleset by reading all rules
    from the kernel and saving them to the backup file. If a backup already
    exists, it is preserved unless force=True.

    The backup file location is determined by cf.varfilepath('nftables.backup').

    Args:
        cf: Config instance with nft_select setting and varfilepath() method
        force: If True, overwrites existing backup. If False, preserves
               existing backup and returns 'preserve'.

    Returns:
        One of three strings:
            - 'preserve': Backup file already exists (not overwritten)
            - 'errors': Failed to read current ruleset from kernel
            - 'written': Backup successfully created

    Example:
        Creating a backup before changes::

            result = nft_save_backup(cf)
            if result == 'written':
                log.info("Backup created successfully")
                # Safe to make changes now
                nft_load(cf, dirname, filename)
            elif result == 'preserve':
                log.info("Using existing backup")
            else:
                log.error("Failed to create backup")

        Forcing a fresh backup::

            # Always create new backup
            result = nft_save_backup(cf, force=True)
            if result == 'written':
                print("Fresh backup created")

    Note:
        The actual implementation (Python or shell) is selected based on
        cf.nft_select. Both backends provide identical interfaces.
    """
    if cf.nft_select == 'python':
        return nft_python.nft_save_backup(cf, force)
    return nft_shell.nft_save_backup(cf, force)


def nft_restore_backup(cf: Config, nodelete: bool = False) -> bool:
    """Restore nftables rules from backup file.

    Loads the previously saved backup file and installs those rules into the
    kernel, replacing the current ruleset. By default, the backup file is
    deleted after successful restoration unless nodelete=True.

    Args:
        cf: Config instance with nft_select setting
        nodelete: If True, keeps backup file after restoration.
                  If False (default), deletes backup on success.

    Returns:
        True if restoration successful, False on error

    Example:
        Restoring after failed update::

            result = nft_save_backup(cf)
            if result == 'written':
                # Try to install new rules
                if not nft_load(cf, dirname, 'new-rules.nft'):
                    log.error("New rules failed, restoring backup")
                    if nft_restore_backup(cf):
                        log.info("Backup restored successfully")

        Restoring but keeping backup::

            # Restore but preserve backup file
            if nft_restore_backup(cf, nodelete=True):
                log.info("Restored, backup file preserved")

    Note:
        If restoration fails, the backup file is always preserved regardless
        of the nodelete parameter.

        The actual implementation (Python or shell) is selected based on
        cf.nft_select. Both backends provide identical interfaces.
    """
    if cf.nft_select == 'python':
        return nft_python.nft_restore_backup(cf, nodelete)
    return nft_shell.nft_restore_backup(cf, nodelete)


def nft_delete_backup(cf: Config) -> None:
    """Delete the nftables backup file.

    Removes the backup file created by nft_save_backup(). This is typically
    called after successful installation of new rules to clean up.

    Args:
        cf: Config instance with nft_select setting

    Returns:
        None

    Example:
        Cleaning up after successful update::

            result = nft_save_backup(cf)
            if result == 'written':
                if nft_load(cf, dirname, filename):
                    # Success, remove backup
                    nft_delete_backup(cf)
                    log.info("Rules installed, backup removed")

    Note:
        The actual implementation (Python or shell) is selected based on
        cf.nft_select. Both backends provide identical interfaces.
    """
    if cf.nft_select == 'python':
        return nft_python.nft_delete_backup(cf)
    return nft_shell.nft_delete_backup(cf)
