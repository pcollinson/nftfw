% NFTFWLS(1) | Nftfw documentation

NAME
====

**nftfwls** \- list **nftfw** blacklist database

SYNOPSIS
======

| **nftfwls** \[**-h**\] \[**-c** _config_]  \[**-p** yes|no \] \[**-a |-r | -m | -i | -n | -w | -q | -v **\]


DESCRIPTION
=========

**nftfwls** displays the status of the database storing the state of the **nftfw** firewall. The default output only displays the IP addresses found in _/usr/local/etc/nftfw/blacklist.d_. The **-a** option shows all entries in the database, and ignores the contents of the _blacklist.d_ directory. HTML output is also possible.

**nftfwls** 'pretty prints' a table with these headings:

-  IPs:   The blocked IP address
- Port: The port list used in the firewall for the IP
- Ct/Incd: The number of matches in log files triggered by this IP; a / and the number of reported distinct incidents
- Latest: The date and time of the latest incident. The _date_fmt_ key in _config.ini_ can alter  date formats from the default.
- First: The date and time of the first incident (or a minus sign '-' if it's the same as Latest)
- Duration: The time difference between the two times
- Pattern: The pattern or patterns that reported the incident or incidents

If the _geoip2_ country database is available, the IP address is preceded by the ISO two letter country code of te site where the IP is located.

Text output
----------

Text output uses the Python 'prettytable' module. When piping the output into another program, it's helpful to remove the column separators, adding **-n** option make this happen.

HTML output
-----------
The **-w** option selects HTML output. It prints an HTML table suitable for inclusion on a web page. Classes in the table allow styling.

- Class: 'nftfwls' - for <table\>
- Class: 'heading' for the heading <tr\>
- Class; 'content' for the remaining <tr\> lines
- Class: 'col1', 'col2', up to 'col7' for the appropriate <td\> cells.

If the _geoip2_ country database is available, the IP address is preceded by the ISO two letter country code of te site where the IP is located. Mouse over the code to get the full country name.

Options
-------

**-h**, **-\-help**

:   Prints brief usage information.

**-w**, **-\-web**

: Print output as an HTML table, enabling  integration into a web page.

**-a **, **-\-all**

:   Prints all the informarion in the database, ignoring entries in _blacklist.d_

**-p **, **-\-pattern_split** yes|no

: If 'yes', splits the pattern column at any comma, making separate lines for entries with more than one stored pattern; if 'no' prints a single line for the pattern column. The _pattern_split_ value in the config.ini file sets the usual default value.

**-r**, **-\-reverse**

:   Reverse sorting order

**-m**, **-\-matchcount**

:   Sort by match count

**-i**, **-\-incidents**

:   Sort by incidents

**-n**, **-\-noborder**

:   Don't print a border to the table.

**-c **, **-\-config** CONFIG

:   Supply a configuration file, overriding any values from the default system settings.

**-q**, **-\-quiet**

:   Suppress printing of errors and information messages to the terminal, syslog output remains active. Terminal output is suppressed when the output is not directed to a terminal

**-v**, **-\-verbose**

:   Change the default logging settings to INFO to show all errors and information messages.

 FILES
=====

Files can be located in _/_ or  _/usr/local_.

_/usr/local/etc/nftfw_

:   Location of  control files

_/usr/local/var/lib/nftfw/_

:   Location of *build*, *install*, lock file and sqlite3 databases storing file positions and blacklist information

BUGS
====

See GitHub Issues: <https://github.com/pcollinson/nftfw/issues>

AUTHOR
======

Peter Collinson (huge credit to the ideas from Patrick Cherry's work for the firewall for the Symbiosis hosting system).

SEE ALSO
========

**nft(1)**, **nftfw(1)**, **nftfwedit(1)**, **nftfwadm(1)**, **nftfw-config(5)**, **nftfw-files(5)**
