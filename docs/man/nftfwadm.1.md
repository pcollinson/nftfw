% NFTFWADM(1) | Nftfw documentation

NAME
====

**nftfwadm** \- support for installation of the Nftfw firewall generator

SYNOPSIS
======

| **nftfwadm** \[**-h**\] \[**-c** _config_] \[**-o** _option_] \[**-x | -f | -i | -q | -v **] \[**_save|restore|clean_**]


DESCRIPTION
=========

**nftfw(1)** generates firewalls based on information derived from control files. It creates a new set of command files ready for loading in the kernel and tests them using _nft(1)_. If the test succeeds, it makes a backup of the kernel settings before installing the new rule set into the kernel. If installation fails, **nftfw** loads the kernel tables from the backup and deletes it, restoring the running system to the known safe version. **nftfw** deletes the backup file if installation succeeds.

 When testing a new firewall setup, it can be useful to be able to backtrack to a known working version, so **nftfw** will not create a new backup file if one already exists. The **nftfwadm** command provides the **save** action to preload the backup file so that **nftfw** can revert to a known working version on any failure.  The **restore** action  reloads the saved backup settings into the kernel and deletes the backup file. The **clean** command  deletes the backup file.

These are the available options to the program:

**-h**, **-\-help**

:   Prints brief usage information.

**-c**, **-\-config** CONFIG

:   Supply a alternate configuration file, overriding any values from the default system settings.

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

:   Location of control files.

_/usr/local/var/lib/nftfw/_

:   Location of the backup file, *build.d*, *test.d*, *install.d*, lock files and the sqlite3 databases storing file positions and blacklist information


BUGS
====

See GitHub Issues: <https://github.com/pcollinson/nftfw/issues>

AUTHOR
======

Peter Collinson (huge credit to the ideas from Patrick Cherry's work for the firewall for the Symbiosis hosting system).

SEE ALSO
========

**nft(1)**, **nftfwls(1)**, **nftfwedit(1)**, **nftfw-config(5)**, **nftfw-files(5)**
