""" nftfw patternReader debug

    Reads active patterns and prints the data structure
"""

if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')
    import logging
    log = logging.getLogger('nftfw')
    from nftfw.config import Config
    from nftfw.patternreader import pattern_reader

    cf = Config()
    print("NB: only returns actions where files matching the patterns have been found");
    action = pattern_reader(cf)
    for file in action.keys():
        alist = action[file]
        print(f"{file} {alist}")
        print()
