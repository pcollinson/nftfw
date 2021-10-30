""" nftfw LogReader debug

Reads logs and doesn't update any position
Prints data structure created by logreader

"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')
    from nftfw.config import Config
    from nftfw.logreader import log_reader

    cf = Config()

    action = log_reader(cf, update_position=False)
    for file in action.keys():
        alist = action[file]
        print(f"{file} {alist}")
