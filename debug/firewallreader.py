"""
    nftfw firewallreader class
"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')
    from nftfw.rulesreader import RulesReader
    from nftfw.rulesreader import RulesReaderError
    from nftfw.firewallreader import FirewallReader

    from nftfw.config import Config

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
