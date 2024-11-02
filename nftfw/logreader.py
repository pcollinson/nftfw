"""nftfw LogReader - used by the blacklist operation

Creates a data structure used by blacklist
"""

from pathlib import Path
from hashlib import md5
import logging
from .fileposdb import FileposDb
from .patternreader import pattern_reader
log = logging.getLogger('nftfw')

def log_reader(cf, update_position=True):
    """Read and store matched info from log files based on patterns

    if update_position is False, then don't update stored log positions.

    provide error logging if a test pattern file is found

    Use pattern reader to get all data
    Use one_log_reader to scan logs

    Parameters
    ----------
    update_position : bool
        If True updates position in the position database

    Returns
    -------
    Dict[ip: Dict[content]]
    ip : str
        ipaddress found in the matches

    content Dict values
      ports : {'all', 'test', 'update', or List[ports]}
          note that the ports value can be a list,
          I wish I'd called it something else - perhaps portlist
      matchcount: int
          matches found this run
      incidents: int
          count of hits from different rules
      pattern: str
          name of matched pattern
    """

    out = {}
    # Are we testing? If so selected_pattern_file is set
    have_pattern = cf.selected_pattern_file is not None

    action = pattern_reader(cf)

    if have_pattern and not any(action):
        log.error('Requested pattern %s pattern not found', cf.selected_pattern_file)
        return out

    for filename, patinfo in action.items():
        res = one_log_reader(cf, filename, patinfo, update_position)
        for ip, info in res.items():
            if ip not in out:
                info['incidents'] = 1
                out[ip] = info
            else:
                out[ip]['incidents'] += 1
                out[ip]['matchcount'] += info['matchcount']
                out[ip]['ports'] = portmerge(out[ip]['ports'], info['ports'])

    # extra logging for test files
    if have_pattern \
       and cf.selected_pattern_is_test \
       and not any(out):
        log.error('No matches found in %s', cf.selected_pattern_file)

    return out

def one_log_reader(cf, filename, patinfo, update_position=True):
    """Process data for a single logfile

    Uses sqlite3 database to remember the last position and the md5 hash
    of the first line if any. The neat idea of hashing the first line of
    the file to see if it's changed is stolen from Symbiosis.

    calls scanlog to process the lines if update_position is True

    Parameters
    ----------
    cf : Config
    filename : str
        Log file we are scanning
    patinfo: List[Dict[
                pattern : str
                    pattern name for reference
                ports : str
                    comma separated ports to match (may be 'all')
                file : str
                   logfile to scan
                   regex : List[compiled regex]
                   List of regexes to scan each line of the log file with
                   ]]
    update_position : bool
        Leaves file positions alone if False

    Returns
    -------
    Dict[ip : Dict[value]]
        return dict indexed by ip addresses, each value is a dict:
            ports:  {'all', 'test', 'update' or a comma separated list}
            pattern: str
                name of matching pattern
            matchcount: int
                number of matches in this run
    """

    # pylint: disable=too-many-locals

    # support for the single pattern option
    have_pattern = cf.selected_pattern_file is not None
    is_test = have_pattern and cf.selected_pattern_is_test
    # don't update log file positions for test files
    if is_test:
        update_position = False

    path = Path(filename)
    if not path.exists():
        # complain if this is a test using selected_pattern_file and the
        # file doesn't exist
        if have_pattern:
            log.error('Pattern %s requested, log file is missing', cf.selected_pattern_file)
        return {}

    fsize = path.stat().st_size

    # bail out if nothing in the file
    if fsize == 0:
        # complain if this is a test using selected_pattern_file and the
        # log file is empty
        if have_pattern:
            log.error('Pattern %s requested, empty log file', cf.selected_pattern_file)
        return {}

    # get lastseek position and previous linesig
    # if no entry will be (0, None)
    db = FileposDb(cf)
    lastseek, linesig = db.getfileinfo(filename)
    db.close()

    # Ignore any coding errors
    with open(filename, 'r', errors='ignore') as fhandle:
        # See if this file is new
        line1 = fhandle.readline(2048)
        newsig = md5(line1.encode()).hexdigest()

        # start at zero
        # if unknown before now, or sigs are different
        # or we have a pattern name
        if not linesig \
           or linesig != newsig \
           or is_test:
            # put the file cursor back
            fhandle.seek(0, 0)
        elif lastseek > 0:
            # likely to be common situation
            # has file got shorter
            if fsize < lastseek:
                lastseek = fsize
            fhandle.seek(lastseek, 0)

        out = scanlog(patinfo, fhandle)

        if update_position:
            offset = fhandle.tell()
            db = FileposDb(cf)
            db.setfileinfo(filename, offset, newsig)
            db.close()

    return out

def scanlog(allpatinfo, lines):
    """Given an open file, scan it using regexes

    Parameters
    ----------
    allpatinfo : Patinfo datastructure as in onelogreader
    lines : str
        File contents

    Returns
    -------
    Dict[ip : Dict[value]]
        return dict indexed by ip addresses, each value is a dict:
            ports:  {'all', 'test', 'update' or a comma separated list}
            pattern: str
                name of matching pattern
            matchcount: int
                number of matches in this run
    """

    # combine all the possible regexes into a list
    # allregex cannot be a generator expression
    # because it's used several times
    allregex = [(r, p) for p in allpatinfo for r in p['regex']]
    # now look for matches
    found = (matchline(allregex, line) for line in lines)
    # remove empty values
    active = (f for f in found if f)

    # create output dict
    out = {}
    for ip, patinfo in active:
        # need to evaluate ports
        ports = normaliseports(patinfo['ports'])
        if ip not in out:
            out[ip] = {'ports': ports,
                       'pattern': patinfo['pattern'],
                       'matchcount': 1}
        else:
            out[ip]['matchcount'] += 1
            out[ip]['ports'] = portmerge(out[ip]['ports'], ports)
    return out

def normaliseports(ports):
    """Normalise port list

    Parameters
    ----------
    ports : str
        Comma separated list of ports

    Returns
    -------
    str | List
        If None - set to all
        Otherwise make sorted list
    """

    if ports is None:
        return 'all'

    if ports in ('all', 'update', 'test'):
        return ports

    # use a set to remove possible duplicate values
    return sorted(list(set(map(int, ports.split(',')))))

def portmerge(current, new):
    """Merge ports

    Parameters
    ----------
    current : str or List
        Current set of ports
    new : str or List
        New port to add

    Returns
    -------
    str or List
        The list will be a sorted unique set of ports
    """

    if isinstance(current, str):
        return current

    if isinstance(new, str):
        return new

    return sorted(list(set(current + new)))

def matchline(allregex, line):
    """ Apply regexes to line

    Parameters
    ----------
    allregex : List[(regex, patinfo)]
        a list of tuples
    line : Line to be matched

    Returns
    -------
    tuple :   (ip, matching pattern)
        if a match is found
    None  : None if no match
    """

    for reg, pattern in allregex:
        ma = reg.search(line)
        if ma:
            return (ma.group(1), pattern)
    return None
