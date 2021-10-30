#!/usr/bin/env python3
""" nftfw ListProcess debug

Prints datastructures created from listprocess
"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')

    from nftfw.config import Config
    from nftfw.rulesreader import RulesReader
    from nftfw.ruleserr import RulesReaderError
    from nftfw.listreader import ListReader
    from nftfw.listprocess import ListProcess

    cf = Config()
    cf.rulesreader = RulesReader(cf)

    for c in ['whitelist', 'blacklist']:
        print(c)
        reader = ListReader(cf, c)
        process = ListProcess(cf, c, reader.records)
        process.generate()
        print("Create Sets")
        print(process.get_set_init_create())
        print("Update Sets")
        print(process.get_set_init_update())
        print("Sets")
        print(process.get_set_cmds())
        print("Chains")
        print(process.get_list_cmds())
