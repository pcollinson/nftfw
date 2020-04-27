"""nftfw RulesReader debug 

Reads and prints rules in rule.d

"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')
    import logging
    log = logging.getLogger('nftfw')

    from config import Config
    from rulesreader import RulesReader
    from ruleserr import RulesReaderError    
    
    cf = Config()
    try:
        r = RulesReader(cf)
    except RulesReaderError as e:
        log.error(str(e))
        exit(1)
    for k in r.keys():
        print(k)
    for k,v in r.items():
        print(k, v)
    
