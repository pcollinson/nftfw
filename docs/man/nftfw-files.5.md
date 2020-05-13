% NFTFW-FILES(1) | Nftfw documentation

NAME
====

**nftfw-files** — documentation of file formats used in nftfw

DESCRIPTION
=========

This page documents the file formats used in the **nftfw** firewall system.  The system stores various control files in _/etc/nftfw_ or _/usr/local/etc/nftfw_ depending on the installation. You can find a manual page for the configuration file _config.ini_ living in the directory in nftfw-config(5).

The _etc/nftfw_ directory contains:

-  _incoming.d_ -   contains rules controlling  access to services on the system;
-  _outbound.d_ - sets any rules controlling packets leaving the system;
-  _whitelist.d_ - contains IP addresses that have full access to the system;
-  _blacklist.d_ - specifies IP addresses and ports in the inbound packets that should not have access;
-  _patterns.d_ - contain pattern files for matching lines in log files for blacklist; and
-  _rule.d_  - hold  files for generating **nft** commands from rule names.

Distributed files can be found in _etc/nftfw/original_.

incoming and outbound
----------------------
Files in these directories specify rules for the firewall. File names have the format:

> number-description

where 'number' is a pair of digits used as a sequence number and 'description' specifies the action name needed to created the nftables commands for the rule.

Descriptions can be:

-  a port number inserted into the firewall rule
-  the name of a service found in _/etc/services_.
-  the name of a rule found in the rules directories (with the .sh suffix removed)

When port numbers appear in the filename, the directory name dictates the action file applied for the rule. The _config.ini_ file contains variables that select the default rule based on the directory name (see nftfw-config(1)).

To allow rules to have the same name as services and replace the default action, **nftfw** searches the rule directory for name matches  before querying the service file.

Files are usually empty, but can contain a list of IP addresses (one per line) that **nftfw** uses to specify the source IP or IPs for an incoming rule, or the destination IP or IPs for the outbound rule. For example,  supplying a list of known IP addresses  for the standard ssh(1) service will prevent tiresome exhaustive attempts to get passwords.  Local users can access ssh(1) from unknown addresses using the knowledge of a random port number given by another rule.

blacklist and whitelist
--------------------
Files in these directories make nftables rules permitting access in the whitelist or blocking access in the blacklist. Whitelisted rules appear before blacklisted ones in the firewall.

Filenames are simply IP addresses. The whitelist or blacklist scanners will create files in these directories, and will add a suffix of _.auto_.  Files added 'by hand' should just be the IP address.

IPv6 addresses are added in /64 form, with the '/'  replaced by a vertical bar '|'.  Install  IPv4 address groups with network masking using the same convention.

Empty files mean that the rule applies to all ports. File contents are lists, one per line, with the following contents:

-  all - a 'special' keyword meaning that the rule  applies to all ports.
-  a numeric port number

Firewall rules with 'all' ports appear in the ruleset before any rules containing specific ports.

The system has no way of distinguishing between TCP and UDP protocols and the system generates two rules for each rule it finds.

Administrators can disable the  blacklist and whitelist systems separately by creating a file called 'disabled' in the relevant directory.

When building the firewall from these two directories, **nftfw** writes the IP addresses into nftables sets. The program writes the information into two separate files and uses file comparison with the last loaded files to see If it can update the sets of IP addresses without reloading the whole firewall.

patterns.d
---------
Patterns define rules for the **blacklist** module containing the log file (or files) for scanning, the port numbers for the blocking firewall rules, and a list of regular expressions matching lines in the log file.

Pattern files are text files named _name.pattern_. The files support comments when the first character of the line contains '#'.

The files contain two 'equals' statements that should always be present:

>  file = filename
>  ports = port specification

Filename is the full path to a logfile that the pattern will used to scan. The filename can also contain shell 'glob' characters ('*', '?' and single character ranges) allowing for the rule set to match a range of files.  The blacklist system will ignore the pattern file (and complain) if the file (or files) that it nominates doesn't exist.

The port specification is usually a comma separated list of port numbers. A firewall rule uses the port list to ban access to specific services on the system.  The ports statement has three 'special' values:

- 'all' will ban access to all ports for  any matching IP;
- 'update' allows us to get feedback from the firewall.  The 'update' value will not create any firewall rules, it will only  increment counts in the system's sqlite3(1) database for any IP that matches. The option provides feedback from the firewall that log continued attempts to access the machine from blocked IP addresses.
- 'test' marks the file as a testing pattern file. The normal scan from the blacklist system will ignore  files with _ports=test_. Using the **-p** _patternname_ option  with the blacklist command will consider  only files with _ports=test_ and the pattern file name without the _.pattern_ suffix must match _patternname_.

The remainder of the pattern file is a set of regular expressions, placed one per line, that match offending lines in the log files. The rules all contain the string ```__IP__``` (two underscores at end) used to match and capture the IPv4 or IPv6 address from the line. Non-empty lines that don't contain ```__IP__``` are flagged as errors.

The expressions support Python's standard regular expression syntax but must only have one matching 'capturing group' which is the ```__IP__``` expansion. It is safe to use non-capturing expressions, for example to match _word1_ or _word2_ in the line, use ```(?:word1|word2)```.

Lines are flagged in the logs and ignored if the compilation of the regular expression fails, or if there is more than one matching group.

The **blacklist** action for **nftfw** uses the patterns to scan log files for matching lines using case-independent matching by the regex and finds IP addresses that it adds to an sqlite3(1) database. IP addresses exhibiting activity levels over a threshold will cause the script to add the IP address file to the blacklist directory (see nftfw(1)).

Setting _ports=test_ in a pattern file enables testing to see if regular expressions pick up offending IP addresses. Set up a pattern test file pointing to the file you want to scan, and set _port=test_, add the regular expression you wish to test. Then running

> sudo nftfw -x -p pattern-test blacklist

will use data from _pattern-test.pattern_  and will scan the named log file (or files).  The *-x* flag scans the log file from the beginning and will not update the stored file position.  The command will print a table with any matching IP addresses, along with a match count. The command can be re-run if matches fail after adjusting the regular expression in the pattern file.

rule.d
-----
The _rule_ directory contains small shell scripts that translate firewall actions named in the _incoming.d_ and _outgoing.d_ directories into nftables command lines. Default rules are also used for the whitelist and blacklist generation. Note the coding and management of these files are different from Symbiosis, but the same idea is there, a shell file allows easy additions by users. The files do not run any commands, they output _nftables_ statements to _nftfw_ which stores them and passes the file into the _nft_ command.

Filenames have the format:

> actionname.sh

**nftfw** runs the scripts though the shell and captures the output text, appending it  to an nftables command file. The system calls each action file twice, once for IPv4 and again for IPv6. The processing script uses environment variables to pass parameters into the shell. The parameters are:

>DIRECTION - incoming | outgoing
>PROTO - values ip|ip6
>TABLE - usually filter
>CHAIN - table to add the rule to
>PORTS - ports to use (can be empty)
>COUNTER - set to counter or empty
>IPS - ip addresses (can be empty, single, ranges, named sets, unnamed sets)
>LOGGER - logger statement

The pattern script uses the DIRECTION parameter in both incoming and outgoing contexts and  must set directional keywords in **nft** commands correctly.  For an incoming rule, an IP address (if present) will be a 'source' address.  For an outgoing rule, an IP address (if present) will be a 'destination' address.

A rule script will usually create a simpler version of the command when called with no ports.

Other files in _etc/nftfw_
---------------------

The _etc_ directory contains the config.ini file for **nftfw**. nftfw_config(5) contains a description

The file _nftfw_init.nft_ contains the basic rule set for nftables, it's used to establish the firewall framework and finally uses several include statements to pull in the files created by the system. **nftfw** copies the file into the build directory at the start of the build process. The basic setup assumes that it's running on a system with a single network connection attached to the internet, however, it's been successfully changed to support a router system with local and remote networks attached.

Finally, the _original_ directory contains the starting point for all control files, and some examples.

Files in _var/lib/nftfw_
---------------------

The _lib/nftfw_ directory provides working space for the system. It contains three directories and several working files.

-   _build.d_ - The _build_ directory provides an initial build space for **nftfw**, it creates a new file set in the directory from the information available to it. The **nft** checking function validates the newly installed files, and the update process will stop for any errors.
-   _install.d_ - The _install_ directory is the source for the **nft** command to load the tested file set into the system. On the next run, **nftfw** will compare the newly generated files in _build_ with that last used set in _install_. The comparison determines whether to run a complete or partial reinstall, or perhaps whether there has been no change. The intention is to only update blacklist and whitelist set information if this is possible.
-   _test.d_ - **nftfw -x** runs the build process up to the point of validating the files and will use this directory as a target for the build.
-  _firewall.db_  - is an sqlite3(1) database used by the blacklist command to store state on the IP's it detects, when and why. The nftfwls(1) command prints  its contents.
-  _filepos.db_  - is an sqlite3(1) database used by the blacklist command to store the last known position in the log files that it scans.
-  _whitelist_scan_ - is an empty file, the whitelist command sets its modification date registering the last run time that the system was run. The command uses the time to skip over processed entries in the _wmtp_ file
-  _sched.lock_ - is a lock file used as master lock. **nftfw** locks the file to prevent other instances from running. If another instance of the command starts, it will fail to get the lock, and the queues the intended action before exiting.
-  _sched.queue_ -  stores queued actions. The queuing system permits the storage of only one action of any one type (load, blacklist, whitelist or tidy). When the master lock owner finishes its task, it inspects the queue file and performs the job without relinquishing the master lock. On the last action, lock owner deletes the queue file.
- _queue.lock_ - is a lock file controlling access to the queue file.

Contents of build etc

FILES
=====

Files can be located in _/usr/local_.

_/etc/nftfw_

:   Location of  control files


BUGS
====

See GitHub Issues: <https://github.com/pcollinson/nftfw/issues>

AUTHOR
======

Peter Collinson (huge credit to the ideas from Patrick Cherry's work for the firewall for the Symbiosis hosting system).


SEE ALSO
========

**nft(1)**, **nftfw(1)**, **nftfwls(1)**, **nftfwadm(1)**, **nftfw-config(5)**
