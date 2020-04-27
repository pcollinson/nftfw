% NFTFW(1) | Nftfw documentation

NAME
====

**nftfwedit** — command line tool to 

SYNOPSIS
======

| **nftfw** \[**-h**\] \[**-c** _config_] \[**-o** _option_] \[**-q |-x | -f | -i | -v**] \[_action_]


DESCRIPTION
=========


FILES
=====

*/etc/nftfw* or */usr/local/etc/nftfw*

:   Location of  control files

*/var/lib/nftfw/* or */usr/local/var/lib/nftfw*

:   Location of *build*, *install*, lock file and sqlite3 database storing file positions and blacklist information


BUGS
====

See GitHub Issues: <https://github.com/pcollinson/nftfw/issues>

AUTHOR
======

Peter Collinson

SEE ALSO
========

**nft(1)**, **nftfwls(1)**,  **nftfwedit(1)**, **nftfwadm(1)**,  **nftfw-config(5)**, **nftfw-files(5)**
