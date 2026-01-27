"""Firewall management system for nftfw.

This module manages the creation, testing, and installation of nftables
firewall rules. It orchestrates the complete workflow from loading
configuration to installing rules in the kernel.

Architecture
------------
The firewall management system uses a two-stage build process:
1. **Build directory**: Rules are prepared and tested in isolation
2. **Install directory**: Tested rules are moved for actual use

This separation allows intelligent updates - comparing new rules with
installed rules enables selective set updates without disturbing running
firewall rules. Only the changed elements need to be reloaded.

Workflow (8 Steps)
------------------
The fw_manage() function orchestrates the complete workflow:

**Step 1: Load Information**
- Parse incoming.d and outgoing.d firewall rules
- Load whitelist.d, blacklist.d, and blacknets.d IP lists
- Process rule.d templates and local.d customizations

**Step 2: Save to Build Directory**
- Write all rules to build.d (or test.d in test mode)
- Create nftables include files for each component
- Generate both full-load and set-update variants

**Step 3: Test Installation**
- Validate rules using `nft -c` (check mode)
- Ensure syntax is correct before attempting actual install
- Exit immediately if validation fails

**Step 4: Determine Installation Type**
- Compare build.d with install.d files
- Return None if no changes (skip install)
- Return 'full' if rules changed or forced
- Return list of sets (e.g., ['blacklist', 'whitelist']) for set-only updates

**Step 5: Test Partial Updates** (if applicable)
- Validate set-update commands work correctly
- Some IP additions create ranges that can fail
- Fall back to 'full' if set update validation fails

**Step 6: Create Backup**
- Save current nftables ruleset to backup file
- Check if backup already exists (indicates previous failure)
- Backup enables rollback if installation fails

**Step 7: Perform Installation**
- Execute full install or set updates via nft
- Restore backup if installation fails
- Keep backup if previous backup existed (preserve flag)

**Step 8: Save to /etc/nftables.conf**
- Read installed ruleset from kernel
- Write to /etc/nftables.conf for persistence across reboots
- Only executed if step 7 succeeded

Configuration
-------------
From various sections of nftfw.ini:

- **create_build_only** (bool): Test mode - build but don't install
  Default: False (controlled by -x flag)
- **force_full_install** (bool): Force full install even if only sets changed
  Default: False (controlled by -f flag)

File Organization
-----------------
Generated files for each component (e.g., blacklist):

- **blacklist.nft**: Rule commands (e.g., drop packets from blacklist set)
- **blacklist_sets.nft**: Set commands (e.g., flush/add elements)
- **blacklist_sets_init.nft**: Full set initialisation for new install
- **blacklist_sets_update.nft**: Set element updates for partial reload
- **blacklist_sets_reload.nft**: Combined update+sets file

The _reload.nft file includes both _sets_update.nft and _sets.nft,
allowing atomic set updates without full firewall reload.

Example Usage
-------------
Basic firewall load:

    from .config import Config
    from .fwmanage import fw_manage

    cf = Config()
    fw_manage(cf)  # Load and install firewall

Test mode (build but don't install):

    cf = Config()
    cf.create_build_only = True
    fw_manage(cf)  # Creates files in test.d

Force full install:

    cf = Config()
    cf.force_full_install = True
    fw_manage(cf)  # Forces complete reinstall

See Also
--------
- rulesreader.py: Parse rule.d template files
- firewallreader.py: Read incoming.d and outgoing.d directories
- listreader.py: Read whitelist.d and blacklist.d directories
- netreader.py: Read blacknets.d directory for network lists
- nft.py: Interface to nftables command
"""
from __future__ import annotations

import sys
import shutil
from filecmp import cmpfiles
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from .rulesreader import RulesReader
from .ruleserr import RulesReaderError
from .firewallreader import FirewallReader
from .firewallprocess import FirewallProcess
from .listreader import ListReader
from .listprocess import ListProcess
from .netreader import NetReader
from . import nft

if TYPE_CHECKING:
    from .config import Config

log = logging.getLogger('nftfw')

def fw_manage(cf: Config) -> None:
    """Execute complete firewall management workflow.

    This is the main entry point for the 'load' action. It orchestrates
    the complete 8-step workflow for building, testing, and installing
    nftables firewall rules.

    Args:
        cf: Configuration instance

    Example:
        Basic firewall load:

            from .config import Config
            from .fwmanage import fw_manage

            cf = Config()
            fw_manage(cf)

        Test mode (build but don't install):

            cf = Config()
            cf.create_build_only = True
            fw_manage(cf)

    Note:
        The workflow can exit early at several points:
        - Step 3: Exits with code 1 if nft validation fails
        - Step 4: Returns if no installation needed (no changes)
        - Test mode: Returns after step 4 without installing
        - Step 6: Returns if backup creation fails
        - Step 8: Skipped if step 7 installation failed

        In test mode (create_build_only=True), steps 5-8 are skipped.
        Files are created in test.d instead of build.d for validation
        purposes without affecting the running firewall.
    """
    # Step 1 - load all information
    files = step1(cf)

    # Step 2 - Save all the information in the build directory
    buildpath = cf.varpath('build')
    step2(cf, files, buildpath)

    # Step 3 - run nft to test the full installation
    step3(cf, buildpath)

    # Step 4 - See if we need a complete re-install or we can just
    # update the sets with new information or nothing is needed
    # because all the files are identical
    installpath = cf.varpath('install')
    install = step4(cf, buildpath, installpath, files)
    if install is None:
        return

    # Testing support
    # Bail out here if requested
    if cf.create_build_only:
        if install == 'full':
            log.info('Full installation suppressed. Full install must be forced later.')
        else:
            args = ' and '.join(install)
            log.info('Set update of %s suppressed. Full install must be forced later', args)
        return

    # Step 5 - Check partial set change rules work
    # will return 'full' on fail
    if install != 'full':
        assert isinstance(install, list)  # Type narrowing for mypy
        install = step5(cf, install, buildpath)

    # Step 6 - Check and create backup
    backup_result, retain_backup = step6(cf)
    if backup_result == 'errors':
        return

    # Step 7 - Perform the install
    # install is None, 'full' or a list
    # of files to be run
    result = step7(cf, install, backup_result, retain_backup)

    # Step 8 - Read the nftables setting back
    # and place in /etc/nftables.conf
    if result:
        step8(cf)

def step1(cf: Config) -> dict[str, str]:
    """Load all firewall configuration information.

    Reads and processes all configuration files from etc directory:
    - incoming.d and outgoing.d firewall rules
    - whitelist.d, blacklist.d, blacknets.d IP lists
    - rule.d templates and local.d customizations

    Args:
        cf: Configuration instance

    Returns:
        Dictionary mapping filenames to nftables commands:
            - Keys: Filenames (e.g., 'incoming.nft', 'blacklist_sets.nft')
            - Values: nftables command strings

    Example:
        Load configuration:

            files = step1(cf)
            print(files.keys())
            # ['incoming.nft', 'outgoing.nft', 'whitelist.nft',
            #  'whitelist_sets.nft', 'whitelist_sets_init.nft', ...]

    Note:
        This step calls loadinfo() which instantiates all reader classes
        and stores RulesReader in cf.rulesreader for shared access across
        other components.

        The function exits with code 1 if RulesReaderError is raised,
        indicating a syntax error in rule.d files.
    """
    log.info('Loading data from %s', str(cf.etc_base))
    return loadinfo(cf)

def step2(cf: Config, files: dict[str, str], buildpath: Path) -> None:
    """Save all nftables files to the build directory.

    Writes all generated nftables configuration files to the build
    directory (or test directory in test mode). Each file gets a
    shebang line for direct execution.

    Args:
        cf: Configuration instance
        files: Dictionary mapping filenames to nftables command strings
        buildpath: Path to build directory (build.d or test.d)

    Example:
        Save files to build directory:

            files = step1(cf)
            buildpath = cf.varpath('build')
            step2(cf, files, buildpath)

    Note:
        All generated files get a shebang line (#!/usr/sbin/nft -f)
        making them directly executable.

        The nftfw_init.nft file is copied from the etc directory and
        serves as the main entry point that includes all other files.

        Files are written with default permissions; ownership is set
        by the caller if needed.
    """
    log.info('Creating reference files in %s', str(buildpath))

    # Copy the init file
    srcfile = cf.nftfw_init
    contents = srcfile.read_text()
    # now write it out to nftfw_init.nft
    destfile = buildpath / 'nftfw_init.nft'
    destfile.write_text(contents)

    # Now save the files we have in the files dict
    for fname in files.keys():
        dest = buildpath / fname
        txt = '#!/usr/sbin/nft -f\n' + files[fname]
        with open(dest, 'w', encoding='utf-8') as f:
            f.write(txt)

def step3(cf: Config, buildpath: Path) -> None:
    """Validate nftables configuration using nft check mode.

    Tests the generated nftables configuration by running nft in check
    mode (-c flag). This validates syntax without affecting the running
    firewall. Exits immediately if validation fails.

    Args:
        cf: Configuration instance
        buildpath: Path to build directory containing files to test

    Raises:
        SystemExit: Exits with code 1 if nft validation fails

    Example:
        Test build directory:

            buildpath = cf.varpath('build')
            step3(cf, buildpath)  # Exits if invalid

    Note:
        The nft command is run with the -c (check) flag, which validates
        the configuration without modifying the running ruleset.

        The test uses nftfw_init.nft as the entry point, which includes
        all other generated files.

        If validation fails, the function logs an error and exits with
        code 1, preventing any installation attempt.
    """
    log.info('Testing new nftables installation')
    cmdfile = 'nftfw_init.nft'
    if not nft.nft_load(cf, str(buildpath), cmdfile, test=True):
        log.info('Test failed using %s', cmdfile)
        sys.exit(1)

def step4(cf: Config, buildpath: Path, installpath: Path,
          files: dict[str, str]) -> str | list[str] | None:
    """Determine installation type by comparing build with install directory.

    Compares files in build directory with install directory to determine
    if a full install, partial set update, or no install is needed.

    Args:
        cf: Configuration instance
        buildpath: Path to build directory with new files
        installpath: Path to install directory with current files
        files: Dictionary of generated filenames (from step1)

    Returns:
        Installation type:
            - None: No changes, skip installation
            - 'full': Full install required (rules changed or forced)
            - list[str]: Set-only update (e.g., ['blacklist', 'whitelist'])

    Example:
        Determine installation type:

            install = step4(cf, buildpath, installpath, files)
            if install is None:
                print("No changes needed")
            elif install == 'full':
                print("Full installation required")
            else:
                print(f"Set update needed: {install}")

    Note:
        Full install is required when:
        - No files match (initial install)
        - force_full_install flag is set
        - Rule files (incoming.nft, outgoing.nft) changed
        - Any *_sets.nft file changed (not just *_sets_init.nft)

        Set-only update is possible when:
        - Only *_sets_init.nft or *_sets_update.nft files changed
        - No rule files changed

        Changed files are copied from build to install directory
        regardless of installation type determined.
    """
    log.info('Determine required installation')
    comparefiles = ['nftfw_init.nft']
    for file in files.keys():
        comparefiles.append(file)

    match, mismatch, errors = cmpfiles(str(buildpath),
                                       str(installpath),
                                       comparefiles,
                                       shallow=False)

    # if no files match then install all files
    # OR we've been asked for a full install

    install: str | list[str] | None = None

    if not any(match) \
      or cf.force_full_install:
        if not any(match):
            log.info('Initial install needed')
        if cf.force_full_install:
            log.info('Full install forced')
        else:
            log.info('Full install required')
        copyfiles(buildpath, installpath, comparefiles)
        install = 'full'
    elif any(errors)  \
         or any(mismatch):
        copyneeded = errors + mismatch
        copyfiles(buildpath, installpath, copyneeded)
        chk = check_for_update_type(copyneeded)
        if chk is not None:
            install = chk
            log.info('Update needed for %s', 'and'.join(install))
        else:
            install = 'full'
            log.info('Full install required')
    else:
        # everything is up-to-date
        log.info("No install needed")
        install = None
    return install

def step5(cf: Config, install: list[str], buildpath: Path) -> str | list[str]:
    """Validate partial set update commands.

    Tests that set update commands work correctly. Some IP address
    additions can create ranges that cause nftables to fail. If any
    set update test fails, falls back to requiring a full install.

    Args:
        cf: Configuration instance
        install: List of set names to update (e.g., ['blacklist', 'whitelist'])
        buildpath: Path to build directory containing update files

    Returns:
        Installation type:
            - 'full': If any set update test fails
            - install: Original list if all tests pass

    Example:
        Test set updates:

            install = ['blacklist', 'whitelist']
            result = step5(cf, install, buildpath)
            if result == 'full':
                print("Set update failed, need full install")

    Note:
        Each set gets a *_sets_reload.nft file that includes both the
        update commands (*_sets_update.nft) and the set manipulation
        commands (*_sets.nft).

        The test uses nft -c (check mode) to validate without affecting
        the running firewall.

        IP address additions can sometimes trigger nftables to create
        IP ranges, which may fail in certain circumstances. When this
        happens, a full install is required instead of a set update.
    """
    assert isinstance(install, list)
    for name in install:
        log.info('Testing reload of %s', name)
        fname = name + '_sets_reload.nft'
        if not nft.nft_load(cf, str(buildpath), fname, test=True):
            log.info('Test failed using %s', fname)
            return 'full'
    return install

def step6(cf: Config) -> tuple[str, bool]:
    """Create backup of current nftables ruleset.

    Saves the current nftables ruleset to a backup file before attempting
    installation. This enables rollback if installation fails.

    Args:
        cf: Configuration instance

    Returns:
        Tuple of (backup_result, retain_backup):
            - backup_result: 'written', 'preserve', or 'errors'
            - retain_backup: True if backup should be kept after install

    Example:
        Create backup before installation:

            backup_result, retain_backup = step6(cf)
            if backup_result == 'errors':
                return  # Abort installation

    Note:
        Backup results:
        - 'written': Backup created successfully
        - 'preserve': Backup file already exists (previous failure)
        - 'errors': Backup creation failed

        If backup_result is 'preserve', it indicates a previous
        installation attempt failed. The existing backup should be
        retained even after successful installation to allow manual
        inspection.

        If backup_result is 'errors', the installation should be
        aborted as rollback would not be possible.

        The backup file is typically stored as nftables.backup in
        the var directory.
    """
    # save backup file
    log.info('Saving backup file')
    backup_result = nft.nft_save_backup(cf)
    retain_backup = False

    if backup_result == 'errors':
        log.error('Backup failed, installation aborted')

    if backup_result == 'preserve':
        log.error('*** Important: Backup file exists and probably should not. '
                  'nftfw cannot safely test new installations and needs be able to. '
                  "Use 'sudo nftfwadm clean' and reload nftfw with 'nftfw -f load' ***" )
        # provide argument for restoreBackup
        retain_backup = True

    return backup_result, retain_backup

def step7(cf: Config, install: str | list[str], backup_result: str,
          retain_backup: bool) -> bool:
    """Perform nftables installation.

    Executes either a full installation or partial set updates. Restores
    from backup if installation fails. Cleans up backup file on success
    (unless retain_backup is True).

    Args:
        cf: Configuration instance
        install: Installation type ('full' or list of set names)
        backup_result: Result from step6 ('written', 'preserve', 'errors')
        retain_backup: If True, keep backup file even on success

    Returns:
        True if installation succeeded, False otherwise

    Example:
        Perform installation:

            result = step7(cf, install, backup_result, retain_backup)
            if result:
                print("Installation succeeded")
            else:
                print("Installation failed, backup restored")

    Note:
        Full installation:
        - Loads nftfw_init.nft which includes all rule and set files
        - Completely replaces the running nftables configuration

        Set updates:
        - Loads *_sets_reload.nft for each set in the list
        - Only updates set elements, not rules
        - Faster and less disruptive than full install

        On failure:
        - Automatically restores from backup file
        - Logs error messages
        - Returns False to indicate failure

        Backup file handling:
        - Deleted if install succeeds and backup_result == 'written'
        - Kept if retain_backup is True (preserve flag from step6)
        - Kept if installation failed (for debugging)
    """
    installdir = str(cf.varpath('install'))
    # seems like pylint doesn't like
    # returns inside ifs so retval
    retval = True

    if install == 'full':
        log.info('Running full installation')
        if not nft.nft_load(cf, installdir, 'nftfw_init.nft'):
            log.error('Full installation failed')
            nft.nft_restore_backup(cf, nodelete=retain_backup)
            retval = False
        else:
            log.info('Full installation succeeded')

    if isinstance(install, list):
        for name in install:
            # Reload using single nft call
            log.info('Running reload of %s', name)
            fname = name + '_sets_reload.nft'
            if not nft.nft_load(cf, installdir, fname):
                log.error('Set reload for %s failed, reloading backup', name)
                # recover backup
                # cannot do much more that this because the nftables
                # state is uncertain
                nft.nft_restore_backup(cf, nodelete=retain_backup)
                retval = False
            else:
                log.info('Reload of %s succeeded', name)

    # if backup was not needed, and it's not preserved delete it
    if retval and backup_result == 'written':
        log.info('Removing backup file')
        nft.nft_delete_backup(cf)
    else:
        log.info('Backup file not removed')
    return retval

def step8(cf: Config) -> None:
    """Save installed ruleset to /etc/nftables.conf for persistence.

    Reads the current nftables ruleset from the kernel and writes it
    to /etc/nftables.conf. This ensures the configuration persists
    across reboots.

    Args:
        cf: Configuration instance

    Example:
        Save ruleset after successful installation:

            if step7_result:
                step8(cf)  # Save to /etc/nftables.conf

    Note:
        This step is only executed if step7 succeeds. If step7 fails,
        step8 is skipped to avoid saving a failed configuration.

        The ruleset is read from the running kernel using 'nft list ruleset',
        not from the files in install.d. This ensures the saved configuration
        matches what's actually running.

        If the ruleset read fails (errors or empty output), the function
        returns early without writing to nftables.conf, logging the error.

        The nftables.conf file is typically /etc/nftables.conf and is
        loaded by systemd on boot to restore the firewall configuration.
    """
    log.info('Install rules in %s', cf.nftables_conf)
    rules, errs = nft.nft_ruleset(cf)
    if errs != "":
        log.error("Ruleset read from system failed")
        log.error(errs)
        return

    if rules == "":
        log.error("Ruleset read from system failed, no data returned")
        return

    outfile = cf.nftables_conf
    outfile.write_text(rules)

# end of fwmanage

def check_for_update_type(files: list[str]) -> list[str] | None:
    """Determine if changed files allow set-only update.

    Analyzes the list of changed files to determine if a partial set
    update is possible, or if a full install is required.

    Args:
        files: List of changed filenames (from cmpfiles mismatch+errors)

    Returns:
        Update type:
            - None: Full install required (rules changed)
            - list[str]: Set-only update (e.g., ['blacklist', 'whitelist'])

    Example:
        Check if set-only update is possible:

            changed = ['blacklist_sets.nft', 'whitelist_sets.nft']
            result = check_for_update_type(changed)
            # Returns: ['blacklist', 'whitelist']

            changed = ['incoming.nft']
            result = check_for_update_type(changed)
            # Returns: None (full install required)

    Note:
        Full install is required if any of these files changed:
        - incoming.nft or outgoing.nft (rule files)
        - whitelist.nft, blacklist.nft, or blacknets.nft (set rule files)

        Set-only update is possible if only these files changed:
        - *_sets.nft (set manipulation commands)
        - *_sets_init.nft (full set initialisation)
        - *_sets_update.nft (set element updates)

        The function returns a list of set names that need updating,
        allowing selective reload of just those sets without disturbing
        the firewall rules.
    """
    if 'incoming.nft' in files \
       or 'outgoing.nft' in files:
        return None

    ret: list[str] | None = None
    for li in ['whitelist', 'blacklist', 'blacknets']:
        # if the rules have changed
        # full install needed
        if li+'.nft' in files:
            return None
        if li+'_sets.nft' in files:
            if ret is None:
                ret = [li]
            else:
                ret += [li]
    return ret

def copyfiles(buildpath: Path, installpath: Path, files: list[str]) -> None:
    """Copy changed files from build directory to install directory.

    Copies files that have changed from the build directory to the
    install directory, preserving file metadata (timestamps, permissions).

    Args:
        buildpath: Path to build directory (source)
        installpath: Path to install directory (destination)
        files: List of filenames to copy

    Example:
        Copy changed files:

            changed = ['blacklist_sets.nft', 'whitelist_sets.nft']
            copyfiles(buildpath, installpath, changed)

    Note:
        Uses shutil.copy2() which preserves:
        - File modification time
        - File access time
        - File permissions
        - Other metadata

        This is important for comparing files between build and install
        directories in subsequent runs.
    """
    for file in files:
        srcfile = buildpath / file
        shutil.copy2(srcfile, installpath)

def loadinfo(cf: Config) -> dict[str, str]:
    """Load all configuration and generate nftables command files.

    This is the core processing function that reads all firewall
    configuration and generates nftables command strings for each
    component.

    Args:
        cf: Configuration instance

    Returns:
        Dictionary mapping filenames to nftables command strings

    Raises:
        SystemExit: Exits with code 1 if RulesReaderError occurs

    Example:
        Load and generate all files:

            files = loadinfo(cf)
            for filename, content in files.items():
                print(f"{filename}: {len(content)} bytes")

    Note:
        Processing steps:

        1. **Rules** (rule.d):
           - RulesReader parses template files
           - Stored in cf.rulesreader for shared access

        2. **Firewall rules** (incoming.d, outgoing.d):
           - FirewallReader loads .rule files
           - FirewallProcess generates nft commands
           - Creates: incoming.nft, outgoing.nft

        3. **IP lists** (whitelist.d, blacklist.d, blacknets.d):
           - ListReader/NetReader load IP addresses
           - ListProcess generates multiple file variants:
             - <name>.nft: Rule commands (e.g., drop from set)
             - <name>_sets.nft: Set manipulation commands
             - <name>_sets_init.nft: Full set initialisation
             - <name>_sets_update.nft: Set element updates only
             - <name>_sets_reload.nft: Combined update+sets

        The _reload.nft files are used for partial updates, allowing
        set elements to be updated without reloading all firewall rules.

        RulesReader is instantiated first and stored in cf.rulesreader
        because it's needed by both FirewallProcess and ListProcess to
        resolve rule templates.
    """
    files: dict[str, str] = {}

    # Rules
    # Put rulesreader into cf so it's called once and its results are
    # shared
    try:
        cf.rulesreader = RulesReader(cf)
    except RulesReaderError as e:
        log.error(str(e))
        sys.exit(1)

    # Firewall
    # incoming and outgoing
    # Call FirewallReader to get all the records
    # Process to make the database that we need
    # Then generate to create the nft commands
    for fw in ('incoming', 'outgoing'):
        fr = FirewallReader(cf, fw)
        process = FirewallProcess(cf, fw, fr.records)
        files[fw+'.nft'] = process.generate()

    # Blacklist, Blacknets and Whitelist are somewhat more complicated
    # Need a file for sets and one for nft commands
    # need to generate two variants for set initialisation
    # one for a complete load
    # one for an update
    # we will create
    # <name>_sets_init.nft - complete
    # <name>_sets_update.nft - update
    # <name>_sets_reload.nft - includes _update_ and _sets_
    # <name>_sets.nft
    # <name>.nft
    for fw, reader in (('whitelist', ListReader),
                       ('blacklist', ListReader),
                       ('blacknets', NetReader)):
        read = reader(cf, fw)
        listproc = ListProcess(cf, fw, read.records)
        listproc.generate()
        files[fw+'_sets_init.nft'] = listproc.get_set_init_create()
        # make the update file include set info
        updatecmds = listproc.get_set_init_update()
        files[fw+'_sets_update.nft'] = updatecmds
        files[fw+'_sets.nft'] = listproc.get_set_cmds()
        files[fw+'_sets_reload.nft'] = f'include "{fw}_sets_update.nft"\n' + \
                                       f'include "{fw}_sets.nft"\n'
        files[fw+'.nft'] = listproc.get_list_cmds()
    return files
