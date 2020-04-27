#!/usr/bin/env python3
""" nftfw ListProcess debug

Prints datastructures created from listprocess
"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')
    import logging
    log = logging.getLogger('nftfw')

    from config import Config
    from rulesreader import RulesReader
    from ruleserr import RulesReaderError
    from listreader import ListReader
    from listprocess import ListProcess

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
