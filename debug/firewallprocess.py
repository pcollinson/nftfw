""" firewall process Standalone debug

Print data structures

"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')
    from nftfw.config import Config
    from nftfw.rulesreader import RulesReader
    from nftfw.ruleserr import RulesReaderError
    from nftfw.firewallreader import FirewallReader
    from nftfw.firewallprocess import FirewallProcess

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
