"""nftfw fwmanage

Default command entry point

The module manages creation and installation of the nftables.

Files are prepared and tested in the build directory, and moved to the
install directory for use. Using two sets of files allows comparison
of updates, so selective updates of set contents can be done without
disturbing running rules.

If nftfw is given the -x flag, the test build is done in a testing
directory, the change managed in config.py

Normal sequence of events
-------------------------
Step 1: Load all information

Step 2: Save information in build directory

Step 3: Run nft to validate installation. During development, it
        seemed that nft gave poor error messages when using include
        files. Initially, the test is done on a prepared file with all
        files included inline 'by steam'. However, this is no longer
        the case, tests are done on files using includes - although
        the support for the inline files remain.

Step 4: See if we need to perform full install or update sets or do
        nothing

Step 5: If updating sets, check that the rules for that work
        sometimes they fail when expanding the set by an ip that
        causes a range

Step 6: Save backup of current settings

Step 7: Perform the required installation, unless inhibited by
        create_build_only flag in cf

Step 8: Save installed settings in /etc/nftables.conf

The selection of installation type is done by comparing files from the
last installation. Full installation can be forced.

"""
import sys
import shutil
from filecmp import cmpfiles
import logging
from .rulesreader import RulesReader
from .ruleserr import RulesReaderError
from .firewallreader import FirewallReader
from .firewallprocess import FirewallProcess
from .listreader import ListReader
from .listprocess import ListProcess
from .netreader import NetReader
from . import nft

log = logging.getLogger('nftfw')

def fw_manage(cf):
    """Entry point

    Generate nft files

    Parameters
    ----------
    cf : Config
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

def step1(cf):
    """Step 1 - load all information

    Parameters
    ----------
    cf : Config

    Returns
    -------
    Dict[name : contents]
        name : str
            is the name of a file to be used
        contents : str
             is the nft commands to be output
    """

    log.info('Loading data from %s', str(cf.etc_base))
    return loadinfo(cf)

def step2(cf, files, buildpath):
    """Step 2 - Save all the information in the build directory

    Parameters
    ----------
    cf : Config
    files : Dict[name : contents]
        name : str
            is the name of a file to be used
        contents : str
             is the nft commands to be output
    buildpath : Path
        Path to build directory
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
        with open(dest, 'w') as f:
            f.write(txt)

def step3(cf, buildpath):
    """Step 3 - run nft to test the full installation

    Dies if tests fail

    Parameters
    ----------
    cf : Config
    buildpath : Path
        Path to build directory
    """

    log.info('Testing new nftables installation')
    cmdfile = 'nftfw_init.nft'
    if not nft.nft_load(cf, str(buildpath), cmdfile, test=True):
        log.info('Test failed using %s', cmdfile)
        sys.exit(1)

def step4(cf, buildpath, installpath, files):
    """Step 4 - See if we need a complete re-install or we can just
    update the sets with new information or nothing is needed because
    all the files are identical

    Parameters
    ----------
    cf : Config
    buildpath : Path
        Path to build directory
    installpath : Path
        Path to install directory
    files : Dict[name : contents]
        name : str
            is the name of a file to be used
        contents : str
            are the nft commands to be output

    Returns
    -------
    str : {None, 'full', List[str]}
        None - nothing to be done
    full - full install needed
        list of files to be installed
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

    install = None

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

def step5(cf, install, buildpath):
    """Step 5: Check partial update rules work

    If updating sets, check that the rules work. Sometimes
    they fail when expanding the set by an ip that creates a range

    Parameters
    ----------
    cf : class
        Config class instance
    install : ('full', List[str] - list of sets to update
    buildpath : path to buildarea

    Returns
    ------
    'full' or install list that passed in

    """

    assert isinstance(install, list)
    for name in install:
        log.info('Testing reload of %s', name)
        fname = name + '_sets_reload.nft'
        if not nft.nft_load(cf, str(buildpath), fname, test=True):
            log.info('Test failed using %s', fname)
            return 'full'
    return install

def step6(cf):
    """Step 6 - Create backup if wanted

    Parameters
    ----------
    cf : Config

    Returns
    -------
    tuple
    	backup_result : {'errors', 'preserve'}
                errors - tell caller to die
                preserve - backup file exists when
                           install attempted
        retain_backup : bool
            True - tells caller to keep backup file
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

def step7(cf, install, backup_result, retain_backup):
    """Step 7 - Perform the install

    Parameters
    ----------
    cf : Config
    install : {'full', List[str]}
        full - full install needed
        list of files to be installed
    backup_result : {'errors', 'preserve'}
        errors - tell caller to die
        preserve - backup file exists wheninstall attempted
    retain_backup : bool
        True - tells caller to hang onto backup

    Returns
    -------
    bool
        True if installation OK
        False otherwise

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

def step8(cf):
    """Step 8 - Read the nftables setting back
    and place in /etc/nftables.conf

    Parameters
    ----------
    cf : Config
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

def check_for_update_type(files):
    """Check to see if a set only update is needed.

    Parameters
    ----------
    files : Dict[name : contents]
        name : str
            is the name of a file to be used
        contents : str
             is the nft commands to be output

    Returns
    -------
    bool or List[str]
        None if update not needed, or otherwise
        return an array of the lists that need to be changed
    """

    if 'incoming.nft' in files \
       or 'outgoing.nft' in files:
        return None

    ret = None
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

def copyfiles(buildpath, installpath, files):
    """Copy files from build to install """

    for file in files:
        srcfile = buildpath / file
        shutil.copy2(srcfile, installpath)

def loadinfo(cf):
    """Load all the information needed to create files content

    Parameters
    ----------
    cf : Config

    Returns
    -------
    Dict[name : contents]
        name : str
            is the name of a file to be used
        contents : str
             is the nft commands to be output
    """

    files = {}

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
        process = ListProcess(cf, fw, read.records)
        process.generate()
        files[fw+'_sets_init.nft'] = process.get_set_init_create()
        # make the update file include set info
        updatecmds = process.get_set_init_update()
        files[fw+'_sets_update.nft'] = updatecmds
        files[fw+'_sets.nft'] = process.get_set_cmds()
        files[fw+'_sets_reload.nft'] = f'include "{fw}_sets_update.nft"\n' + \
                                       f'include "{fw}_sets.nft"\n'
        files[fw+'.nft'] = process.get_list_cmds()
    return files
