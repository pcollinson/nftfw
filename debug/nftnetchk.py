#!/usr/bin/python3
"""
Program to look at the contents of the nftfw firewall.db database
and see if these addresses can be removed because they are being
rejected by entries in the blacknets.d directory.
"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    from nftfw.nftnetchk import main

    main()
