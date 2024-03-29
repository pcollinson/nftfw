""" nftfw fwdb debug """

if __name__ == '__main__':
    import sys
    import time
    sys.path.insert(0, '..')
    from nftfw.config import Config
    from nftfw.fwdb import FwDb

    cf = Config()
    db = FwDb(cf, createdb=False)
    # check on possible expired values
    before = int(time.time()) - 90*24*60*60
    possibles = db.lookup_ips_for_deletion(before)
    ips = [dict['ip'] for dict in possibles]
    print('Possible expired values')
    print(ips)
