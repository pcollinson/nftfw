% NFTCHKNET(1) | Nftfw documentation

NAME
====

**nftnetchk** — command line tool to check if IPs in the firewall database are present in blacknets.d files

SYNOPSIS
======

| **nftnetchk** \[**-h | -l**\]


DESCRIPTION
=========

_nftnetchk_ is a command line tool that checks if the IP addresses in the files in _blacknets.d_ are legal. In addition, it will determine if the IP addresses present in the firewall database are unnecessary because they are part of any network contained in files in _blacknets.d_. Entries in _blacknets.d_  are usually network ranges expressed using CIDR format and are added into _blacknets.d_ by hand. This tool will list entries in the firewall database that are no longer needed because they are covered by the _blacknets.d_ values.

If _nftnetchk_ has nothing to report, it won't output anything.

Output is normally a 'pretty printed' table with these headings:

- IP:  The IP found IP address that can be removed.
- Found in:  The name of the file in _blacknets.d_ of which the network IP is part.
- Net:  The network entry that contains the IP
- Latest:  The date and time of last recorded activity for this address
- First:  The date and time of first recorded activity for this  address ('-' if same as Latest)
- Duration: How long between the Latest and First

The **-l** (or **--list**) option just outputs  IP addresses as a list. The output can be used to remove the IPs from the database:

	sudo nftnetchk -l | while read ip; do sudo nftfwedit -d $ip; done

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
