% NFTFWEDIT(1) | Nftfw documentation

NAME
====

**nftfwedit** — command line to add, delete and blacklist IPs and IP information print

SYNOPSIS
======

| **nftfwedit** \[**-h**\]  \[** -d | -a | -b **\]  \[**-p** _PORT_] \[**-n** _PATTERN_] \[** -q **] \[** -v **] \[** ipaddress [ ipaddress ... ]**\]


DESCRIPTION
=========

_nftfwedit_ is a command line tool to add or remove IP addresses from the _nftfw_ blacklist database, and also optionally from the _blacklist.d_ directory affecting the running firewall. Options on the command line are followed by one of more IP addresses.

If one of the **delete** (**-d**) , **add** (**-a**) or **blacklist** (**-b**) options is not supplied, _nftfwedit_ prints information about its ip address arguments. Information from the blacklist database is printed if available, along with the country of origin (if _geoip2_ is installed) and output from any DNS blocklists, if specified in _config.ini_.

These are the available options to the program:

**-h**, **-\-help**

:   Prints brief usage information.

**-d**, **-\-delete**

:   The nominated IP addresses are deleted from the blacklist database, and if present, the file is removed from the _blacklist.d_ directory. Requires root access.

**-a**, **-\-add**

:   The nominated IP addresses are added to the blacklist database. The port (**-p**) and pattern (**-n**) options must be supplied to create a valid database entry. Requires root access.

**-b**, **-\-blacklist**

:   The nominated IP addresses are added to the _blacklist.d_ directory. If an address to be added is present in the blacklist database, then the installation uses that information to create the file. When the database doesn't contain the address, it's added to the database, and in this case the port and pattern options must be supplied. Requires root access.

**-p**,**-\-port** PORT

:   Supply the ports used when blocking the IP address. The PORT value can be _all_, a single numeric port number or a comma separated list of ports.

**-n**,**-\-pattern** PATTERN

:   Supply the pattern name stored in the database and used to indicate the source of the blacklist entry when listed by _nftfwls_.

:   Suppress printing of errors and information messages to the terminal, syslog output remains active. Terminal output is suppressed when the output is not directed to a terminal

**-q**, **-\-quiet**

:   Suppress printing of errors and information messages to the terminal, syslog output remains active. Terminal output is suppressed when the output is not directed to a terminal

**-v**, **-\-verbose**

:   Change the default logging settings to INFO to show all errors and information messages.


FILES
=====

Files can be located in _/_ or _/usr/local_.


_/usr/local/etc/nftfw_

:   Location of control files and directories

_/usr/local/etc/nftfw/nftfw_init.nft_

:  **nftables** basic framework

_/usr/local/etc/nftfw/config.ini_

: ini file with basic settings for *nftfw*, overriding built-in values

_/usr/local/var/lib/nftfw/_

:   Location of *build.d*, *test.d*, *install.d*, lock files and the sqlite3 databases storing file positions and blacklist information


BUGS
====

See GitHub Issues: <https://github.com/pcollinson/nftfw/issues>

AUTHOR
======

Peter Collinson (huge credit to the ideas from Patrick Cherry's work for the firewall for the Symbiosis hosting system).

SEE ALSO
========

**nft(1)**, **nftfw(1)**,  **nftfwls(1)**, **nftfwadm(1)**,  **nftfw-config(5)**, **nftfw-files(5)**
