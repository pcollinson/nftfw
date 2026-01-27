% NFTFWAN(1) | Nftfw documentation

NAME
====

**nftfwan** — command line tool to analyse the counters installed by **nftfw**  into **nftables**

SYNOPSIS
======

| **nftfwan** \[**-h**\] \[**-f** _FILE_] \[**-4 |-6 | -u | -p | -r | -n **]


DESCRIPTION
=========

**nftfwan** is a command line tool that reads the some of counters from the **nftfw** firewall running in **nftables**.  This data is provided by **nftfables** in JSON format and requires parsing to obtain the counters. **nftfwan** needs to be run by the super user to have the necessary permission to read the data.

The aim of **nftfwan** is to get a measure of what is happening to the inbound connections to the system. It gives an overall view of the type of traffic a system is subjected to, how much of that traffic is blocked by the firewall systems, how much is filtered into the applications with open ports, and how much is simply ignored. The script is not 'general purpose', it uses knowledge of the flow of packets through the firewall  provided with the **nftfw** system and may not provide correct numbers if this flow is changed.

The script reads the data from the kernel and outputs two tables, that are 'pretty printed'. The first shows 'Usage', the general flow through the firewall, the numbers are computed from the counts of packets entering a particular filter. The rows named in the first column and are:

- IP Connects - the number of external IP connects
- Whitelist - the number of connects that have been accepted for whitelisting
- Blacknets - the number of connects that have been rejected by the _blacknets_ system
- Blacklist - the number of connects that have been rejected by the _blacklist_ system
- To firewall - the number of connects that have been passed into the _incoming_ chain, looking for matches with specified ports
- _Firewall processing_ - a separator to mark that the rows below are taken from the _incoming_ chain and the total used for percentages changes
- Accepted packets - how many connections have been accepted for processing by the filter in _incoming_
- Dropped packets - how may connections didn't find a destination in _incoming_

The second table 'Service'  breaks down accepted connections in _incoming_ by service type. The first column shows the service name if it is shown if the port number appears in the standard _/etc/services_ file on the system., otherwise the port number is displayed.

Both tables show numbers for IPv4, IPv6 and a total in subsequent columns. Arguments to the script can reduce the columns that are displayed.

Options
-------

**-h**, **-\-help**

:   Prints brief usage information.

**-4**, **-\-ip**

:   Restrict output to IPv4

**-6**, **-\-ip6**

:   Restrict output to IPv6

**-u **, **-\-usage**

:   Only output usage information

**-p **, **-\-ports**

:   Only output port information

**-n**, **-\-noborders**

:   Don't print borders to the tables

**-r**, **-\-raw**

:   Print decoded data from the kernel and exit. Prints IPv4 and IPv6  unless -4 or -6 is included.  This is a debugging aid.

**-f **, **-\-file** FILE

:   Read data from the file. This is a debugging aid.

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

**nft(1)**, **nftfwls(1)**,  **nftfwedit(1)**, **nftnetchk(1)**,  **nftfwadm(1)**, **nftfw-config(5)**, **nftfw-files(5)**
