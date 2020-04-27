""" config.py - print config values"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')
    from config import Config
    cf = Config()
    print(repr(cf))
