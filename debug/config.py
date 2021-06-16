""" config.py - print config values"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '../nftfw')
    from config import Config
    try:
        cf = Config()
    except AssertionError as e:
        print(str(e))
        exit(1)

    print(cf.etc_base)
    print(repr(cf))
