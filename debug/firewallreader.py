"""
    nftfw firewallreader class
"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')
    import logging
    log = logging.getLogger('nftfw')
    from rulesreader import RulesReader
    from rulesreader import RulesReaderError
    from firewallreader import FirewallReader

    from config import Config

    cf = Config()
    try:
        cf.rulesreader = RulesReader(cf)
    except RulesReaderError as e:
        log.error(str(e))
        exit(1)

    r = FirewallReader(cf, 'incoming')
    for p in r.records:
        print(p)
    r = FirewallReader(cf, 'outgoing')
    for p in r.records:
        print(p)
