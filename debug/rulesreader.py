"""nftfw RulesReader debug

Reads and prints rules in rule.d

"""

def testexecute(r):
    """ Test execution for a test rule """

    rule = """#!/bin/sh
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi
echo add rule $PROTO $TABLE $CHAIN tcp dport '{80,443}' $IPSWITHDIRECTION $COUNTER $LOGGER jump httpaccept
echo 'Who am I running as'?
whoami

"""
    r.rules_store['debugxx'] = rule

    env = {'DIRECTION':'incoming',
           'PROTO':'tcp',
           'TABLE':'ip',
           'CHAIN':'filter'
           }
    ans = r.execute('debugxx', env)
    print(ans)

if __name__ == '__main__':
    import os
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')

    from nftfw.config import Config
    from nftfw.rulesreader import RulesReader
    from nftfw.ruleserr import RulesReaderError

    cf = Config()
    try:
        r = RulesReader(cf)
    except RulesReaderError as e:
        log.error(str(e))
        exit(1)
    """
    for k in r.keys():
        print(k)
    for k,v in r.items():
        print(k, v)
    """
    testexecute(r)
    print(os.getuid())
