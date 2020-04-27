""" Nftfw utmp tester - prints current utmp file """

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')

    import time
    from nftfw_utmp import Utmp, UtmpDecode
    from utmpconst import *

    utmp = Utmp()
    utmp.utmpname(WTMP_FILE)
    utmp.setutent()

    for utv in utmp.getutentbytype(USER_PROCESS):
        utl = UtmpDecode(utv)
        print ("%-10s %-10s %-15s %-20s %s" % (utl.ut_user, utl.ut_line, utl.ut_host, time.ctime(utl.ut_tv.tv_sec), utl.ut_addr))
    utmp.endutent()
    

