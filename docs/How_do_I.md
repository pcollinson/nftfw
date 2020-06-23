% How Do I...  or a User's Quick Guide
# How Do I...  or a User's Quick Guide

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [How Do I...  or a User's Quick Guide](#how-do-i--or-a-users-quick-guide)
    - [How do I: Allow access to a service on my machine?](#how-do-i-allow-access-to-a-service-on-my-machine)
    - [How do I: Deny access to a service?](#how-do-i-deny-access-to-a-service)
    - [How do I: Allow access to a service from a restricted list of machines?](#how-do-i-allow-access-to-a-service-from-a-restricted-list-of-machines)
    - [How do I: Give full access my server to known set of machines?](#how-do-i-give-full-access-my-server-to-known-set-of-machines)
    - [How do I: Restrict the services accessed by a whitelisted address?](#how-do-i-restrict-the-services-accessed-by-a-whitelisted-address)
    - [How do I: Block access to abusive sites?](#how-do-i-block-access-to-abusive-sites)
    - [How do I: See what the firewall is doing?](#how-do-i-see-what-the-firewall-is-doing)
    - [How do I: Check what the blacklist scanner is doing?](#how-do-i-check-what-the-blacklist-scanner-is-doing)
    - [How do I: Find the country sending me blacklisted packets?](#how-do-i-find-the-country-sending-me-blacklisted-packets)
    - [How do I: Remove a good IP address from the blacklist?](#how-do-i-remove-a-good-ip-address-from-the-blacklist)
    - [How do I: Add a new reason for blacklisting?](#how-do-i-add-a-new-reason-for-blacklisting)
    - [How do I: Debug my new blacklisting expression?](#how-do-i-debug-my-new-blacklisting-expression)
    - [How do I: Change the settings for _nftfw_?](#how-do-i-change-the-settings-for-nftfw)
    - [How do I: do without _incron_?](#how-do-i-do-without-incron)
    - [How do I: Get more information on _nftfw_?](#how-do-i-get-more-information-on-nftfw)
    - [Acknowledgement](#acknowledgement)

<!-- markdown-toc end -->


## How do I: Allow access to a service on my machine?

Change directory into _/usr/local/etc/nftfw/incoming.d_

You'll see something like

``` sh
$ ls
05-essential-icmpv6  10-http   30-imaps  50-smtps
05-ping              10-https  40-pop3   50-submission
06-ftp-helper        20-ftp    40-pop3s  60-sieve
07-ssh               30-imap   50-smtp   99-reject

```

Each file makes a rule for the firewall, and starts with a two digit number that supplies the ordering of the rules. A new entry needs to be adding before the _99-reject_ rule. So let's pick '70' for that.

The rest of the filename can be a port number or the service name, but that must be in _/etc/services_. Let's say we want to add access to our name server, and that's on port 53, called _domain_ in _/etc/services_. We can either add _70-domain_ or _70-53_. The easiest way to do this is to use the _touch_ command (you may have to use _sudo_):

``` sh
$ touch 70-domain
```

because the file is empty, connections from any IP address may access this service.

Some of the filenames in the directory access 'rules' in the _rule.d_ directory. There's more information on the manual page in [_nftfw_files_](man/nftfw-files.5.md) in man section 5.

## How do I: Deny access to a service?

By default, the incoming firewall will reject advances from IP addresses. To permit access, you must create a rule as above. You can remove the files in this directory for services you don't need. For example, If you don't need to use the POP service, you can simply delete _40_pop3_ and _40_pop3s_ in the incoming directory. You should delete any file that names a service you don't want to allow people to have access to.

## How do I: Allow access to a service from a restricted list of machines?

If you want to only allow access to say _ssh_ to a known set of IP addresses, then you can add those IP addresses into the _07-ssh_ file, one per line. Only the addresses found in the file can access the_ssh_ service. You can add the domain name of system to the file, and that will include both their IPv4 and IPv6 addresses, if they have both. It's probably a good idea to run a caching domain name server on your machine if you use names in the files.

## How do I: Give full access my server to known set of machines?

First you need to find the IP addresses of the machines, the easiest way is to use the _host_ command:

``` sh
$ host notarealmachine.co.uk
notarealmachine.co.uk has address 203.0.113.134
notarealmachine.co.uk has IPv6 address 2001:db8::a676:7186
```

Armed with the IP addresses, create a file in _whitelist.d_ using the address as the name.

```
$ touch 203.0.113.134
```

If you want to allow all the addresses from the network, allowing 1-254 in the last section of the address, you can add a 'CIDR' mask of 24 bits to match the first three sections of the address. CIDR addresses are usually written with '/', in this case 203.0.113.0/24, but we cannot use / in a filename, so replace it by the vertical bar symbol:

``` sh
$ rm 203.0.113.134
$ touch '203.0.113.0|24'
```

If you put the full address from the _host_ command into the directory, *nftfw* will 'normalise' the address to replace the 134 by zero.

For IPv6 addresses we always match the first 64 bits of the address. IPv6 addresses are abbreviated by writing '::' for any sequences of  zeros in the address, so to allow their IPv6 address you can write:

``` sh
$ touch '2001:db8::|64'
```

You may find some files ending with _.auto_ in the directory, the whitelist scanner has installed these when it's found that a user has logged in from the address. The scanner will look after these, and will expire them automatically after 90 days.

## How do I: Restrict the services accessed by a whitelisted address?

The files in the _whitelist.d_ directory are empty to allow access to all services, but can contain a list of port numbers, one per line, restricting access from the named address to only those ports. For example, restricting access to _ssh_ is done by:

``` sh
$ echo 22 >> '203.0.113.0|24'
```

## How do I: Block access to abusive sites?

The _blacklist.d_ directory uses the same convention for files used for the whitelist. Simply create a file named for the IP address in the directory.

The blacklist scanner will automatically create files in the directory ending in _.auto_ when it finds sites that are misbehaving. The scanner uses files in the _patterns.d_ directory to find log files to scan, and how to interpret lines in the log files as bad.

## How do I: See what the firewall is doing?

The _nft_ command prints the contents of the firewall with the command:

``` sh
$ sudo nft list ruleset
```

You can print just the IPv4 and IPv6 sets separately with

``` sh
$ sudo nft list ruleset ip
$ sudo nft list ruleset ip6
```

This is too much typing, so I alias these commands in my shell startup files:

``` sh
alias nfl='sudo nft list ruleset ip|less'
alias nfl6='sudo nft list ruleset ip6|less'
```

You'll see that most rules have counters, so you can see what has happened in the past, what's busy and what's in use.

## How do I: Check what the blacklist scanner is doing?

The blacklist scanner uses files in the _patterns.d_ directory. Each file here supplies a file (or files) processed  by the scanner, a port number (or a comma-separated list) used for blocking and a set of regular expressions that match the lines in the log files indicating bad behaviour.

You can find out what's blocked on your system by using:

``` sh
$ nftfwls
```

This will print a table of the IP addresses the scanner has found, the number of matches, the number of 'incidents' - each incident is a separate run of the scanner, when it happened first, the last time a match happened, and the name of the pattern that triggered the event.

If the command says nothing, then possibly the scanner hasn't detected enough events for the match count to exceed the threshold where it creates blacklist file. The **-a** flag to the program prints all the entries in its database.

## How do I: Find the country sending me blacklisted packets?

If you install the geoip2 country database on your system, and its python interface, then _nftfwls_ will show the country of origin when it displays its output. Access to the geoip2 databases is free, but MaxMind who produce it ask you to sign up. See the document [Installing Geolocation](Installing-GeoLocation.md) for installation and signup information.

The _nftfwedit_ command also allows you to ask questions about any IP address, including the country of origin and whether the IP address is in selected DNS blacklist sites.

## How do I: Remove a good IP address from the blacklist?

If an IP address has found its way into the blacklist in error,  then you can delete it using

``` sh
$ sudo nftfwedit -d IP.ADD.RE.SS
```
this will remove the address from the blacklist database and also delete the entry in the _blacklist.d_ directory. If you just remove the address from the directory, _nftfw_ will reinstate it because it's in the database.

## How do I: Add a new reason for blacklisting?

If you've spotted a line in a logfile that you want to use to blacklist a site, then first see if the logfile is already scanned by the system and just add a new regular expression to the file. You can create a new pattern file if needed, calling it anything, but it must end in _.pattern_. Do beware that some log entries can appear in several log files.

The regular expression doesn't need to match the whole line, you need to identify where the IP address is in the line and use the string ```__IP__``` (that's two underscores at each end) to pick it out. There should be enough information on the regular expression to make it only select one line. Look in the pattern files for examples. There's also a section in the [User's Guide](Users_Guide.md#blacklist).

## How do I: Debug my new blacklisting expression?

You can use the _nftfw_ command to see if your expression works. Create a new pattern file and set

``` sh
ports = test
```
and add your regular expression. Now say:

``` sh
$ sudo nftfw -x -p PATTERN blacklist
```
and this will print a table showing the number of matches that the expression has detected. The PATTERN is the name of your file but without the _.pattern_ appended. The _-x_ option makes the program print a table, and also starts scanning the file from the beginning and doesn't record where it found the end of the file, so using this command will not interfere with normal processing.

The blacklist scanner normally ignores pattern files with _ports=test_, so it's safe to leave these files in place.

## How do I: Change the settings for _nftfw_?

The file _/usr/local/etc/nftfw.ini_ is a readable configuration file that contains all the settings that can be changed. As distributed all the values are commented out, each line starts with a semi-colon. There are many comments in the file explaining what each setting does.

See the manual page [_nftfw-config_](man/nftfw-config.5.md) for a description.

## How do I: do without _incron_?

It's perfectly possible to run the firewall system without having _incron_ installed on your machine.

Ensure that the config file entry for incron is set to No:

``` sh
using_incron = No

```
When you make manual changes to any of the control files, make sure you run

``` sh
$ sudo nftfw -f load
```
after you've changed the directory contents, or wait for the next automatic update.

## How do I: Get more information on _nftfw_?

The [User's Guide to nftfw](Users_Guide.md) documents the system and there are also [UNIX manual pages](man/index.md).

## Acknowledgement

All of this is made possible by shamelessly borrowing ideas from Patrick Cherry who created the Symbiosis hosting package for Bytemark of which the firewall system is part.
