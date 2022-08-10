""" Debug for normalise ip address """

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    from nftfw.config import Config
    from nftfw.normaliseaddress import NormaliseAddress

    cf = Config()
    na = NormaliseAddress(cf)

    list = ('192.0.2.5', '198.51.100.128',
            '198.51.100.5', '2001:db8:fab:11::1:1',
            '203.0.113.7')


    for ip in list:
        v = na.normal(ip)
        print(v)

    cf.TESTING = True

    for ip in list:
        v = na.normal(ip)
        print(v)
