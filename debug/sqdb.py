""" nftfw sqdb debug

Dumps current firewall database

"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    from nftfw.config import Config
    from nftfw.sqdb import SqDb

    cf = Config()
    path = cf.varfilepath('firewall')
    db = SqDb(cf, path, None)
    for v in db.lookup('blacklist'):
        print(v)
