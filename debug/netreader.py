#!/usr/bin/env python3
"""nftfw NetReader debug

Print datastructure from list reader
for whitelist and blacklist

Uses the filereader directly

"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')

    from nftfw.config import Config
    from nftfw.netreader import NetReader, NetReaderFromFiles

    cf = Config()
    nr = NetReaderFromFiles(cf, 'blacknets')

    print('IP4');
    print('Number of ip4', len(nr.lists['ip']))
#    for r in nr.lists['ip']:
#        print(r)

    print('IP6');
    print('Number of ip6', len(nr.lists['ip6']))
#    for r in nr.lists['ip6']:
#        print(r)

    cachetest = True
    if cachetest:
        print('Testing caching')
        cachefile = 'blacknets_test.json'


        nr = NetReader(cf, 'blacknets', cachefile=cachefile)

        print('IP4');
        print('Number of ip4', len(nr.records['all']['ip']))
        for r in nr.records['all']['ip']:
            print(r)

        print('IP6');
        print('Number of ip6', len(nr.records['all']['ip']))
        for r in nr.records['all']['ip']:
            print(r)
