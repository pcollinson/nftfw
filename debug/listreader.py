#!/usr/bin/env python3
"""nftfw ListReader debug

Print datastructure from list reader
for whitelist and blacklist

"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')

    from nftfw.config import Config
    from nftfw.listreader import ListReader

    cf = Config()
    wf = ListReader(cf, 'whitelist', need_compiled_ix=False)
    print(wf.srcdict)

    w = ListReader(cf, 'whitelist')

    print('whitelist');
    for r,vals in w.records.items():
        print(r)
        print(vals)

    b = ListReader(cf, 'blacklist')
    print('blacklist');
    for r,vals in b.records.items():
        print(r)
        print(vals)
