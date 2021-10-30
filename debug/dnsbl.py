""" Lookup ip addresses in DNS Blacklists for nftfwedit -p """

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    from nftfw.dnsbl import Dnsbl
    from nftfw.config import Config

    cf = Config()
    dn = Dnsbl(cf)
    if dn.isinstalled():
        for a in sys.argv[1:]:
            lookup = dn.lookup(a)
            print(lookup)
