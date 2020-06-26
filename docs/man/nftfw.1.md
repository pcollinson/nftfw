% NFTFW(1) | Nftfw documentation

NAME
====

**nftfw** — manage the Nftfw firewall generator

SYNOPSIS
======

| **nftfw** \[**-h**\] \[**-c** _config_] \[**-p** _patternname_] \[**-o** _option_] \[**-x | -f | -i | -q | -v **] \[**_load|blacklist|whitelist|tidy_**\]


DESCRIPTION
=========

**nftfw** is the front-end for the firewall system that generates rules for nftables. It uses files in four directories in _/usr/local/etc/nftfw_ to create firewall rules.  The directories create  incoming and outgoing firewalls, and also  tables for whitelisting and blacklisting particular IP addresses. The distribution is installed relative to the system's root or  below _/usr/local_.

The **nftfw** command has several options, and most of these don't change that often when the system is in operation. Editing the ini format file _/etc/nftfw/config.ini_  changes the values of options - see nftfw-config(5). You may make temporary variable changes to configuration values from the command line using the **-o** option to **nftfw** (see below).

The optional command argument to **nftfw** runs main modules of the program. All actions need users to have root access permission. A  lock file ensures the running of only one instance of the program, **nftfw** queues actions if it's busy, and runs queued actions at the finish of the task in hand.

**nftfw** uses an initial setup file _/usr/local/etc/nftfw/nftfw_init.nft_ to form the framework for the completed ruleset. When **nftfw** builds the firewall rules, the _nftfw_init.nft_ file is copied into the build system, and uses include statements to pull in rules from the separate files created from the four directories.

The system, as distributed, provides a firewall for a hosted server with one external internet connection. Administrators can change the _nftfw_init.nft_ file to support more complex network needs.

Actions are:

**load**

The **load** command builds the firewall files by taking input from files in directories in _/usr/local/etc/nftfw_:

-  _incoming.d_  contains rules controlling  access to services on the system;
-  _outbound.d_ sets any rules controlling packets leaving the system;
-  _whitelist.d_ contains files named for the IP addresses that are to have full access to the system and
-  _blacklist.d_ contains files named for IP addresses  in the inbound packets that should not have access.

nftfw-files(5) describes the contents and formats of files in these directories.

**nftfw load** performs these steps, creating files in directories in _/usr/local/var/lib/nftfw_:

1. The command builds a  firewall ruleset in several files in _build.d_, and copies _nftfw_init.nft_  into the directory creating the initial framework. Rules generated from _incoming.d_ and _outgoing.d_  support the basic system services. Rules formed from the _whitelist.d_ and _blacklist.d_ directories make use of nftables sets. These sources change more often than the other directories, and the use of sets allows **nftfw** to change parts of the installed ruleset without completely reloading the firewall.

2. **nftfw** now runs the **nft -c** command validating the rules. Errors cause  **nftfw** to abandon any further processing.

3. If all is well,  **nftfw** compares the files with those in _install.d_ retained from the last run of the program.  File comparison allows **nftfw** to decide on doing nothing, making a full update, or just updating the blacklist and/or whitelist sets.

4. **nftfw** copies all the files into the _install.d_ directory and loads these rules into the system's kernel depending on the decision above.

5. Finally **nftfw** captures the kernel settings and stores them in _/etc/nftables.conf_, which is where the Debian system expects to find the rules on system start-up.

The steps from (4) above could result in a broken system if parts of the installation fails. **nftfw** avoids the possible disaster by storing a backup copy of the kernel's rules before attempting any update. On failure, **nftfw** reverts to the backup rules.

**whitelist**

The **whitelist** action is a scanner for the system's wtmp(5) or utmp(5) file. The system records user logins in this file along with the IP address used to access the system. **nftfw** creates a file named for the IP address in _/usr/local/etc/nftfw/whitelist.d_  as long as the IP address is global.

The **whitelist** command expires addresses that were automatically created (identified by the suffix _.auto_) after a set number of days given in **nftfw**'s config file.

If the scanner makes any changes, **whitelist** invokes the **load** command automatically installing the changes in the firewall.

 See nftfw-files(5) for information on the file formats used for whitelist control files.

**blacklist**

The **blacklist** command is a file scanner creating IP address files in _/usr/local/etc/nftfw/blacklist.d_.  The scanner reads pattern files from _/usr/local/etc/nftfw/patterns.d_.  Pattern files contain a file name (or a range of files given by shell  *glob* rules), the relevant ports for blocking  and a set of regular expressions matching offending lines in the nominated log files.

When **nftfw** finds a match, it updates a sqlite3(1) database with the information and uses the frequency of matches (given in the config file) to decide whether to blacklist the IP.

When scanning log files, the blacklist engine remembers the position in the file at the end of the last scan, so only examines new entries on every pass. The **blacklist** command also expires blacklisted IPs after a set number of days. See nftfw-files(5) for information on the file formats used for blacklist control files.

If the scanner makes any changes, **blacklist** invokes the **load** command automatically installing the changes in the firewall.

**tidy**

The **tidy** command removes old entries from the blacklist database stopping it from growing to immense proportions. **tidy** removes IP's that haven't appeared for a set number of days. The configuration file (see nftfw-config(5)) supplies the number of days.

These are the available options to the program:

**-h**, **-\-help**

:   Prints brief usage information.

**-f**, **-\-full**

:   Does a full install, ignores the file compare installation step.

**-x**, **-\-no-exec**

:   Create rules in _/var/lib/nftfw/test.d and test them. When used with the **blacklist** command, prints the result of scanning for matches without saving any information and without updating stored log file positions.

**-C**, **-\-config** CONFIG

:   Supply a alternate configuration file, overriding any values from the default system settings.

**-p**,**-\-pattern**

:  The argument only applies to the **blacklist** command, and runs the command using only one pattern file (the name of the file omitting the suffix .pattern). When combined with **-x** and setting _ports=test_ in the pattern file the option can be used to test regular expressions in pattern files.

**-i**, **-\-info**

:    List all the configuration names and settings

**-o**, **-\-option** OPTION

:     OPTION is keyword=value and may be comma separated list of configuration options. The values override any settings in the configuration file.

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

**nft(1)**, **nftfwls(1)**,  **nftfwedit(1)**, **nftfwadm(1)**,  **nftfw-config(5)**, **nftfw-files(5)**
