""" nftfw - prints the file position database """

import sys
sys.path.insert(0, '..')
from prettytable import PrettyTable
import time, datetime
import argparse
import logging
log = logging.getLogger('nftfw')
from nftfw.config import Config
from nftfw.fileposdb import FileposDb

def datefmt(timeint):
    """ Return formatted date - here so it can be changed
        in one place
    """

    value = datetime.datetime.fromtimestamp(timeint)
    return value.strftime('%d %b %y %H:%M:%S')

def prdb(cf):

    db = FileposDb(cf, createdb=False)
    ans = db.lookup('filepos', orderby='ts DESC')

    pt = PrettyTable()
    pt.field_names = [ 'Name', 'Posn', 'Time']


    for line in ans:
        pt.add_row([line['file'],
                    line['posn'],
                    datefmt(line['ts'])])


    # set up format
    pt.align = 'l'
    pt.align['Posn'] = 'r'
    print(pt)

if __name__ == '__main__':

    cf = Config()
    desc = """posdb - list logfile positional information"""

    ap = argparse.ArgumentParser(prog='posdb',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=desc)
    ap.add_argument('-z', '--zero',
                    help='Clear position information for named files',
                    action='append')
    args = ap.parse_args()

    if args.zero is None:
        prdb(cf)
    else:
        db = FileposDb(cf)
        for file in args.zero:
            ans = db.lookup('filepos', where='file = ?', vals=(file,))
            if len(ans) == 0:
                print(f'Cannot find {file} in database')
                sys.exit(1)
            else:
                db.setfilepos(file, 0)
