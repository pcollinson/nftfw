% NFTFWEDIT(1) | Nftfw documentation

NAME
====

**nftfwedit** \- command line to add, delete and blacklist IPs and IP information print

SYNOPSIS
======

| **nftfwedit** \[**-h**\]  \[** -d | -r | -a | -b **\]  \[**-p** _PORT_] \[**-m** _MATCHES_] \[**-n** _PATTERN_] \[** -q **] \[** -g **] \[** -v **] \[** ipaddress [ ipaddress ... ]**\]


DESCRIPTION
=========

_nftfwedit_ is a command line tool to add or remove IP addresses from the _nftfw_ blacklist database, and also optionally from the _blacklist.d_ directory affecting the running firewall. Options on the command line are followed by one of more IP addresses.

If one of the **delete** (**-d**) , **remove** (**-r**), **add** (**-a**) or **blacklist** (**-b**) options is not supplied, _nftfwedit_ prints information about its ip address arguments. Information from the blacklist database is printed if available, along with the country of origin (if _geoip2_ is installed) and output from any DNS blocklists, if specified in _config.ini_.

These are the available options to the program:

**-h**, **-\-help**

:   Prints brief usage information.

**-d**, **-\-delete**

:   The nominated IP addresses are deleted from the blacklist database, and if present, the file is removed from the _blacklist.d_ directory. Requires root access.

**-r**, **-\-remove**

:   The nominated IP addresses are removed from the _blacklist.d_ directory. The database is not touched. Requires root access.

**-a**, **-\-add**

:   The nominated IP addresses are added to the blacklist database. For a new item, the port (**-p**) and pattern (**-n**) options must be supplied. A match count (**-m***) can also be supplied. Requires root access.

**-b**, **-\-blacklist**

:   The nominated IP addresses are added to the _blacklist.d_ directory and the blacklist database. For a new item, the port (**-p**) and pattern (**-n**) options must be supplied. A match count (**-m***) can also be supplied. The count may be adjusted to ensure that the nftfw blacklist command will not remove the file automatically. Subsequent use with the same IP address will increment the counts. Requires root access.

**-g**, **-\-gethostname**

:   Include hostname information when printing ip address information. This is optional because name lookups can be slow for ip addresses with known hostname.

**-p**,**-\-port** PORT

:   Supply the ports used when blocking the IP address. The PORT value can be _all_, a single numeric port number, the name of a service found in _/etc/services_ or a comma separated list of numeric ports and names.

**-n**,**-\-pattern** PATTERN

:   Supply the pattern name stored in the database and used to indicate the source of the blacklist entry when listed by _nftfwls_.

:   Suppress printing of errors and information messages to the terminal, syslog output remains active. Terminal output is suppressed when the output is not directed to a terminal.

**-m**,**-\-matches** MATCHES

:   For the **-a** or **-b** actions, set the number of matches used to count the number of problems found in logfiles. For new database entries with the **-b*** option, this is forced to be a minimum of 10 (the default 'block after' value), ensuring that the control file in blacklist.d isn't deleted. For the **-a** option, the value defaults to 1.

:   When the **-a** and **-b** options are updating extant database entries, the count defaults to 1 which is added to the stored count.

**-q**, **-\-quiet**

:   Suppress printing of errors and information messages to the terminal, syslog output remains active. Terminal output is suppressed when the output is not directed to a terminal.

**-v**, **-\-verbose**

:   Change the default logging settings to INFO to show all errors and information messages.


FILES
=====

Files can be located in _/_ or _/usr/local_.


_/etc/nftfw_

:   Location of control files and directories

_/etc/nftfw/nftfw_init.nft_

:  **nftables** basic framework

_/etc/nftfw/config.ini_

: ini file with basic settings for *nftfw*, overriding built-in values

_/var/lib/nftfw/_

:   Location of *build.d*, *test.d*, *install.d*, lock files and the sqlite3 databases storing file positions and blacklist information


BUGS
====

See GitHub Issues: <https://github.com/pcollinson/nftfw/issues>

AUTHOR
======

Peter Collinson (huge credit to the ideas from Patrick Cherry's work for the firewall for the Symbiosis hosting system).

SEE ALSO
========

**nft(1)**, **nftfwls(1)**, **nftnetchk(1)**, **nftfwadm(1)**, **nftfw-config(5)**, **nftfw-files(5)**
