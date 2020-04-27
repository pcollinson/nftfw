#!/usr/bin/env python3
"""nftfw WhiteListCheck debug

Print datastructure from list reader
for whitelist and blacklist

"""
import sys
sys.path.insert(0, '../nftfw')
import logging
log = logging.getLogger('nftfw')

if __name__ == '__main__':

    from config import Config
    from whitelistcheck import WhiteListCheck

    cf = Config()
    wh = WhiteListCheck(cf)
    print(wh.whitedict)

    ip = wh.normalise_addr.normal_ipaddr('ip', '46.235.230.113')
    print(ip, wh.is_white('ip', ip))

    ip = wh.normalise_addr.normal_ipaddr('ip', '46.235.230.113/31')
    print(ip, wh.is_white('ip', ip))

    ip = wh.normalise_addr.normal_ipaddr('ip6', '2a00:1098:82:11::1')
    print(ip, wh.is_white('ip', ip))

    ip = wh.normalise_addr.normal_ipaddr('ip6', '2a00:1098:82:11::ffff')
    print(ip, wh.is_white('ip', ip))
