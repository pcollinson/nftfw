""" nftfw logger manager debug

"""
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')
    from nftfw.config import Config

    cf = Config(dosetup=False)
    cf.readini()
    cf.set_logger(loglevel='DEBUG')
    cf.set_logger(logsyslog=False)
    cf.setup()
    log.info('Testing info')
    log.error('Testing error')
