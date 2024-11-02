""" nftfwls - List data from nftfw blacklist database
"""

import sys
import datetime
from signal import signal, SIGPIPE, SIG_DFL
from pathlib import Path
import argparse
import logging
from prettytable import PrettyTable
from .fwdb import FwDb
from .config import Config
from .geoipcountry import GeoIPCountry
from .stats import duration
log = logging.getLogger('nftfw')

def loaddb(cf, orderby='last DESC'):
    """Load all data in firewall database

    Parameters
    ----------
    cf : Config
    orderby : str
        Sorting order for data

    Returns
    -------
    List[Dict[blacklist database schema]]

"""

    db = FwDb(cf)
    result = db.lookup('blacklist', orderby=orderby)
    return result

def loadactive(cf):
    """Load active ips from firewall directory

    Parameters
    ----------
    cf : Config

    Returns
    -------
    List[str]
        List of filename stems ending in .auto
        in blacklist directory
    """

    path = cf.etcpath('blacklist')
    out = []
    for p in path.glob('*.auto'):
        ip = p.stem
        ip = ip.replace('|', '/')
        out.append(ip)
    return out

def activedb(dbdata, active):
    """Reduce database to active entries

    Parameters
    ----------
    dbdata : List[Dict[]]
        List of database entries
    active : List
        List of stems in blacklist directory

    Returns
    -------
    List[Dict[active entries database schema]]
    """

    out = [e for e in dbdata if e['ip'] in active]
    return out

def datefmt(fmt, timeint):
    """Return formatted date - here so it can be changed
    in one place

    Parameters
    ----------
    fmt : str
        Time format from the ini file
    timeint : int
        Unix timestamp

    Returns
    -------
    str
        Formatted string
    """

    value = datetime.datetime.fromtimestamp(timeint)
    return value.strftime(fmt)

def formatline(date_fmt, pattern_split, line, geoip, is_html=False):
    """Format a single line of data

    Parameters
    ----------
    date_fmt : str
        Format string from ini file
    pattern_split : bool
        If true split patterns at comma into
        newline and a space
    line : Dict(database)
    geoip : Instance of the geoip class
    is_html : bool
        True if HTML output wanted

    Returns
    -------
    List
        List of display columns
    """

    # Add countrycode to IP if exists
    ip = line['ip']
    if geoip is not None and geoip.isinstalled():
        country, iso = geoip.lookup(ip)
        if iso is None:
            iso = "  "
        elif is_html:
            # if html add abbr so mouseover shows country name
            if country is not None:
                iso = f'<abbr title="{country}">{iso}</abbr>'
        ip = iso + " " + ip

    # special handling for last, and duration
    if line['first'] == line['last']:
        estring = '-'
        dstring = '-'
    else:
        estring = datefmt(date_fmt, line['first'])
        # pylint objects to and suggests an f string
        # dstring = "%8s" % (duration(line['first'], line['last']),)
        dur = duration(line['first'], line['last'])
        dstring = f'{str(dur):8s}'
    # deal with the useall flag
    pstring = line['ports']
    if line['useall']:
        pstring = 'all'

    # make patterns into two lines
    if pattern_split:
        pats = "\n ".join(line['pattern'].split(","))
    else:
        pats = line['pattern']

    return [ip,
            pstring,
            str(line['matchcount']) + '/' + str(line['incidents']),
            datefmt(date_fmt, line['last']),
            estring,
            dstring,
            pats]

def displaytable(cf, dt, nogeo, noborder=False):
    """Display the data to terminal

    Parameters
    ----------
    cf : Config
    dt : List[Dict[database]]
        Database entries to show
    noborder : bool
        If true displays no border
    """

    # pylint: disable=unsupported-assignment-operation
    # doesn't like the assignment to pt.align

    # cf values loaded in __main__
    fmt = cf.date_fmt
    pattern_split = cf.pattern_split
    geoip = None
    if not nogeo:
        geoip = GeoIPCountry()

    pt = PrettyTable()

    if noborder:
        pt.border = False
        pt.header = False

    pt.field_names = ['IP'+'('+str(len(dt))+')',
                      'Port', 'Ct/Incd', 'Latest',
                      'First', 'Duration', 'Pattern']
    for line in dt:
        pt.add_row(formatline(fmt, pattern_split, line, geoip))

    # set up format
    pt.align = 'l'
    pt.align['Ct/Incd'] = 'c'
    print(pt)

def displayhtml(cf, dt, nogeo):
    """Display the data as HTML table

    Parameters
    ----------
    cf : Config
    dt : List[Dict[database]]
        Database entries to show
    """

    fmt = cf.date_fmt
    pattern_split = cf.pattern_split
    geoip = None
    if not nogeo:
        geoip = GeoIPCountry()

    tdata = []
    for line in dt:
        tdata.append(formatline(fmt, pattern_split, line, geoip, is_html=True))

    print('<table class="nftfwls">')
    field_names = ['IP'+'('+str(len(dt))+')',
                   'Port', 'Ct/Incd', 'Latest',
                   'First', 'Duration', 'Pattern']
    htmlrow('heading', field_names)
    for line in tdata:
        htmlrow('content', line)
    print('</table>')


def htmlrow(htmlclass, line):
    """Print an htmlrow

    Parameters
    ----------
    htmlclass : str
        Class to be added to row
    line : List(data)

"""

    print(f'    <tr class="{htmlclass}">')
    ix = 0
    for edited in line:
        ix = ix + 1
        colclass = 'col' + str(ix)
        print(f'        <td class="{colclass}">', end='')
        if ix > 1:
            # ip may have html in it
            edited = edited.replace(' ', '&nbsp;')
        edited = edited.replace('\n', '<br>')
        print(edited, end='')
        print('</td>')
    print('    </tr>')

def main():
    """ Main action """

    #pylint: disable=too-many-branches, too-many-statements

    # ignore broken pipe error - thrown when using
    # nftfwls into the head command
    signal(SIGPIPE, SIG_DFL)

    cf = Config()

    desc = """nftfwls - list firewall information

Default output is to show active entries sorted by
time of last incident (in descending order)
"""

    ap = argparse.ArgumentParser(prog='nftfwls',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=desc)
    ap.add_argument('-c', '--config',
                    help='Supply a configuration file overriding the built-in file')
    ap.add_argument('-w', '--web',
                    help='Print output as an HTML table',
                    action='store_true')
    ap.add_argument('-p', '--pattern-split',
                    help='Set the pattern-split value to yes or no, overrides value in config.ini',
                    action='append')
    ap.add_argument('-a', '--all',
                    help='Print database information, don\'t look at firewall directory',
                    action='store_true')
    ap.add_argument('-r', '--reverse',
                    help='Reverse sense of sorting',
                    action='store_true')
    ap.add_argument('-g', '--nogeo',
                    help='Suppress Geoip information, shown if GeoIp is installed',
                    action='store_true')
    ap.add_argument('-m', '--matchcount',
                    help='Sort by counts - largest first',
                    action='store_true')
    ap.add_argument('-i', '--incidents',
                    help='Sort by incidents - largest first',
                    action='store_true')
    ap.add_argument('-n', '--noborder',
                    help='Don\'t add borders and title to the table',
                    action='store_true')
    ap.add_argument('-q', '--quiet',
                    help='Suppress printing of errors on the console, syslog output remains active',
                    action='store_true')
    ap.add_argument('-v', '--verbose',
                    help='Show information messages',
                    action='store_true')

    args = ap.parse_args()

    #
    # Sort out config
    # but don't init anything as yet
    #
    try:
        cf = Config(dosetup=False)
    except AssertionError as e:
        cf.set_logger(logprint=False)
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    # allow change of config file
    if args.config:
        file = Path(args.config)
        if file.is_file():
            cf.set_ini_value_with_section('Locations', 'ini_file', str(file))
        else:
            cf.set_logger(logprint=False)
            log.critical('Aborted: Cannot find config file: %s', args.config)
            sys.exit(1)

    # Load the ini file if there is one
    # options can set new values into the ini setup
    # to override
    try:
        cf.readini()
    except AssertionError as e:
        cf.set_logger(logprint=False)
        log.critical('Aborted: %s', str(e))
        sys.exit(1)

    if args.quiet:
        cf.set_logger(logprint=False)

    if args.verbose:
        cf.set_logger(loglevel='DEBUG')

    try:
        cf.setup()
    except AssertionError as e:
        log.critical('Aborted: Configuration problem: %s', str(e))
        sys.exit(1)

    orderby = 'last DESC'
    if args.reverse:
        orderby = 'last'
    if args.matchcount:
        orderby = 'matchcount DESC, incidents'
        if args.reverse:
            orderby = 'matchcount, incidents'
    if args.incidents:
        orderby = 'incidents DESC, matchcount'
        if args.reverse:
            orderby = 'incidents, matchcount'
    if args.pattern_split:
        for v in args.pattern_split:
            if v == 'yes':
                cf.pattern_split = True
            elif v == 'no':
                cf.pattern_split = False
            else:
                log.error('Value for -p should be "yes" or "no"')
                sys.exit(0)

    config = cf.get_ini_values_by_section('Nftfwls')
    cf.date_fmt = config['date_fmt']
    cf.pattern_split = config['pattern_split']

    db = loaddb(cf, orderby=orderby)
    if not args.all:
        fw = loadactive(cf)
        db = activedb(db, fw)

    if args.web:
        displayhtml(cf, db, args.nogeo)
    else:
        displaytable(cf, db, args.nogeo, args.noborder)

if __name__ == '__main__':
    main()
