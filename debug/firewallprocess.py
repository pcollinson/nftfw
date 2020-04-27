""" firewall process Standalone debug 

Print data structures

"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')
    import logging
    log = logging.getLogger('nftfw')
    from config import Config
    from rulesreader import RulesReader
    from ruleserr import RulesReaderError
    from firewallreader import FirewallReader
    from firewallprocess import FirewallProcess

    cf = Config()
    try:
        cf.rulesreader = RulesReader(cf)
    except RulesReaderError as e:
        log.error(str(e))
        sys.exit(1)

    read = FirewallReader(cf, 'incoming')
    process = FirewallProcess(cf, 'incoming', read.records)
    il = process.generate()
    print(il)

    read = FirewallReader(cf, 'outgoing')
    process = FirewallProcess(cf, 'outgoing', read.records)
    il = process.generate()
    print(il)
