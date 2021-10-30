""" nft command debug

    Executes a ruleset read
"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')
    from nftfw.config import Config
    from nftfw.nft import *

    cf = Config()
    cf.am_i_root()

#    filename = 'nftfw.nft'
#    v = nft_load(cf, cf.build_dir, filename, test=True)

    rules,errs = nft_ruleset(cf)
    if errs != '':
        print('ERRORS')
        print(errs)
    if rules != '':
        print('RULES')
        print(rules)
