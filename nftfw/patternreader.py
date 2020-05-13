""" nftfw pattern_reader

Used by the blacklist operation

Patterns are text files specifying rules to be applied to log files.

Main idea is to create a data structure indexed by filename of log
file, which has list of regexes to be applied to each line and other
information to process the pattern generating firewall entries.

Returns
-------
Dict[file : List[Dict]]
file : str
    Main index is file name of log file to scan
The value is a list of dicts:
    pattern : str
         pattern name for reference
    ports : str
        comma separated ports to match (may be 'all')
    file : str
        logfile to scan
    regex : List[compiled regex]
        List of regexes to scan each line of the log file with
"""
import os
import re
from pathlib import Path
from collections import defaultdict
import logging
log = logging.getLogger('nftfw')

def pattern_reader(cf):
    """Read pattern files

    Files have commands:

    file = logfile path

    Symbiosis doesn't include wildcards in paths, adding
    this allows /srv log files to be processed by a single
    set of patterns.

    ports = port list.

    Comma separated list of numeric ports to be denied if this match
    succeeds.
    Can be 'all' to mean block all ports.
    Can be the word 'update' to allow filewall database incident
    update only from the IP.
    Can be the word 'test' to indicate that this is a test
    pattern and will only be used when requested by
    the -p argument to the program, otherwise the
    pattern file will be ignored

    The file has comments - # followed by text.

    Finally there's a list of regex patterns including
    __IP__ which are used to find an ip address in the line.

    """

    path = cf.nftfwpath('patterns')
    files = (f for f in path.glob('*.patterns') if f.is_file())
    patterns = ((f.stem, f.read_text()) for f in files)
    recordlist = (parsefile(cf, f, c) for f, c in patterns)
    # remove empty values
    recordlist = (l for l in recordlist if l)
    return filelist(recordlist)

def parsefile(cf, filename, contents):
    """Parse a single pattern file into record value

    Ignore any files with ports=test unless we have a
    cf.selected_pattern_file when we ignore all but the
    selected_pattern_file pattern

    if we have a cf.selected_pattern_file and the file
    contains ports=test set global flag
    selected_pattern_is_test
    so we can take special action when reading files

    Parameters
    ----------
    filename : str
        Source file name
    contents : str
        File contents

    Returns
    -------
    Dict[file : List[Dict]]
    file : str
        Main index is file name of log file to scan
    The value is a list of dicts:
        pattern : str
             pattern name for reference
        ports : str
            comma separated ports to match (may be 'all')
            numeric values are checked here, but multiple
            values and order is checked and normalised
            in blacklist.py
        file : str
            logfile to scan
        regex : List[compiled regex]
            List of regexes to scan each line of the log file with
    """

    # pylint: disable=too-many-return-statements

    # should always have contents
    if not any(contents):
        return None

    (file, ports, regex) = _pattern_scan(contents, filename)

    # validate statements
    # check for file=
    if not file:
        log.error('Pattern: missing file = statement in %s', filename)
        return None
    if not hasattr(cf, 'TESTING') \
       and file[0] != '/':
        log.error('Pattern: use full path to file in %s', filename)
        return None

    # validate port
    if ports is None:
        ports = 'all'
    else:
        pchk = re.compile(r'(all|update|test|(?:\d+(?:\s*,\s*\d+)*))$')
        if not pchk.match(ports):
            err = 'ports= must be all, test, ' \
                  + 'update or comma separated numeric list'
            log.error('Pattern: %s %s', filename, err)
            return None

    # check for selected pattern
    if cf.selected_pattern_file is not None:
        # if we have a selected_pattern_file, and it's not this file,
        # then ignore it
        # if it is and ports is test set global value this allows single
        # patterns to be run normally
        if filename != cf.selected_pattern_file:
            return None
        if ports == 'test':
            cf.selected_pattern_is_test = True
    else:
        # no selected_pattern_file
        # if the ports value is test ignore it
        if ports == 'test':
            return None

    # if we have no regexes - then return None
    if not any(regex):
        log.error('Pattern: %s - no test expressions, file ignored', filename)
        return None

    # generate output
    res = {'pattern':filename,
           'ports':ports,
           'file':file,
           'regex':regex
           }
    return res

def _pattern_scan(contents, filename):
    """Scan a file

    Parameters
    ----------
    contents : str
        File contents
    filename : str
        Filename for error messages

    Returns
    -------
    tuple
    file : str
        file name
    ports : str
        comma separated ports list
    regex : List[]
        List of compiled regexes

    """

    # re used to pick out value setting lines
    commandre = re.compile(r'^([a-z]*)\s*=\s*(.*)(:?#.*)?')
    ports = None
    file = None
    regex = []
    lineno = 0

    # scan file
    lines = (l.strip() for l in contents.split('\n'))
    for line in lines:
        lineno += 1
        # ignore comments
        # don't want to do global #
        # checking in case re's contain #
        if line == '' \
          or line[0] == '#':
            continue

        # look for lines that look like rules
        # accept file= and ports=
        cm = commandre.match(line)
        if cm:
            if cm.group(1) == 'file':
                if not file:
                    file = cm.group(2)
                else:
                    log.info('Pattern: Repeated file statement in %s:%s %s',
                             filename, lineno, line)
            elif cm.group(1) == 'ports':
                if not ports:
                    ports = cm.group(2).strip()
                else:
                    log.info('Repeated ports statement in %s:%s %s',
                             filename, lineno, line)
            else:
                log.error('Pattern: unknown command in %s:%s %s',
                          filename, lineno, line)
            continue

        # remaining lines are regexes
        # replace __IP__ by address match
        # add compiled re to regex list
        # re stolen from symbiosis
        # make this a little more robust
        # the line must contain __IP__
        if '__IP__' in line:
            linere = line.replace(r'__IP__', r'(?:::ffff:)?([0-9a-fA-F:\.]+(?:/[0-9]+)?)', 1)
            try:
                cm = re.compile(linere, re.IGNORECASE)
                if cm.groups != 1:
                    log.error('Pattern in %s, Line %s ignored - extra regex match groups found - use \ before ( and )',
                              filename, lineno)
                else:
                    regex.append(cm)
            except re.error:
                log.error('Pattern: invalid regex in %s: Line %s - line ignored',
                          filename, lineno)
        else:
            log.error('Pattern: Unknown line in %s: Line %s - line ignored',
                      filename, lineno)
    return (file, ports, regex)

def filelist(recordlist):
    """Create dict From the raw data obtained from files

    recordlist is an array of information from parsed files

    Output a dict indexed by the files to scan, where the contents of each
    entry is an array of the records from record list

    If the files don't exist, they will be omitted from the final list.

    Expanding on symbiosis, we'll do a glob on the files so HTML logs in
    the srv tree can be scanned by a single ruleset. Doing this uses
    pathlib to expand the glob.

    Files that don't exist are removed from the set of actions so it's
    possible to have no actions.
    """

    action = defaultdict(list)
    for record in recordlist:
        if not record['file']:
            continue
        # file=value
        fname = record['file']
        # glob glob characters
        globchars = set('*[?')
        if any((c in globchars) for c in fname):
            pathlist = []
            # for a glob there may be symlinks which will
            # generate several paths to the same file
            # build up a list using
            # realpath to arrive at the canonical path
            # samefile to eliminate duplicates
            root = Path('/')
            # remove initial / from glob lookup
            glstr = fname if fname[0] != '/' else fname[1:]
            for file in root.glob(glstr):
                f = Path(os.path.realpath(str(file)))
                if not any(pathlist):
                    pathlist.append(f)
                elif not any(l for l in pathlist \
                              if l.samefile(f)):
                    pathlist.append(f)
        else:
            pathlist = [Path(fname)]

        files = (str(f) for f in pathlist \
                 if f.is_file() and f.stat().st_size > 0)
        for file in files:
            action[file].append(record)

    return action
