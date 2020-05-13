% User's Guide to nftfw
# User's Guide to nftfw

## What does nftfw do?

_nftfw_ provides a simple-to-use framework generating rules for the latest flavour of packet filtering for Linux, known as _nftables_. It generates a set of incoming rules, outgoing rules, supports a whitelist for 'friends' and a blacklist for miscreants. _nftfw_  glues these rules together and loads them into the system's kernel to act as your firewall.

There are four control directories in _/usr/local/etc/nftfw_ (or it may be _/etc/nftfw_ on your machine). You tell _nftfw_ to make a rule by adding a file, that's often empty, to one of these directories. _nftfw_ uses the file name to understand what you are asking, and if needed, will use the file contents to configure the rules it makes.

Here are the directories:

- _incoming.d_
The incoming directory provides information to permit selected inbound connections through the firewall. It contains files that add rules giving the ports that should be available to external users. When a file has no content, its rule applies to all comers. Adding IP addresses into the file constrains the rule to apply only to those addresses.

- _outgoing.d_
The outgoing directory behaves in the same way as the incoming rule set except that it's designed to filter outbound connections. When a file has no content, its rule applies to all destination IP addresses. If needed, adding specific destination addresses as content to the file modifies the rule.

- _whitelist.d_
The whitelist directory contains files named for IP addresses, it makes rules to inspect inbound connections to the system. Packets from these addresses can always access the machine. Adding port numbers as contents to the a file modifies the rules allowing the IP address to only access certain services. There's also an automatic scanner looking for successful logins into your machine that will create files in this directory.

- _blacklist.d_
The blacklist directory has similar contents to the whitelist but will block any attempt to access the system from the IP address. Adding port numbers as contents to the files modifies the rules to only block access to those services. There's an automatic system that looks in log files for people doing bad things and adds their IP address into this directory.

All of these directories create a list of rules. The order of the list is important. The firewall passes each packet  from one rule to the next trying to match the data in the packet with the tests in the rule. Some rules will be looking for matching IP addresses, some for ports and some for both addresses and ports. When the firewall finds a match, the rule tells it to make one of two decisions: accept the packet or reject it.

The firewall is a filter, continuing with testing until it finds a decision. For inbound packets, the firewall passes the packet into:

- the whitelist rules that will accept good guys, then
- the blacklist rules that will reject bad guys
- and finally the incoming rules that will make decisions about all others.
- If the packet falls out the bottom, then it's automatically rejected.

 For outbound packets, the firewall will accept packets that have no match with any rule.

If you consider the volume of packets travelling through any machine, firewall testing seems to be placing a lot of processing between the inbound network interface and the program ready to receive the next packet for that port. Processing is considerably reduced by knowing whether the packet is already part of a conversation or is just starting one. An early rule in the firewall accepts packets that are part of a conversation, applying the testing only when the conversation starts. The firewall filters out most packets before starting testing against the rules from the directories.

### incoming.d

Here's what is present in the _incoming.d_ directory for a standard installation:

``` sh
$ ls incoming.d
05-essential-icmpv6  10-http   30-imaps  50-smtps
05-ping              10-https  40-pop3   50-submission
06-ftp-helper        20-ftp    40-pop3s  60-sieve
07-ssh               30-imap   50-smtp   99-reject
```

None of these files have any content, they are just a filename. Each filename is a two digit number, a minus sign and a name. The number provides sorting value for the files and firewall entries made from this setup will appear in the order that you see. As we've seen, order is important.

There are three possible types for 'name' section of the filename:

-  A port number;
- the name of the service in _/etc/services_;
- the name of an action file found in the directory _rule.d_.

If the name part is a port number or a service name, then *nftfw* uses the default _accept_ action from _rule.d_ to make the necessary rules. The action is given the port number from the name or from the matching entry in _/etc/services_. For example, the file _10-http_ will create an accept rule for port 80, _10-https_ will create an accept rule for port 443.

It could be that you are not using the POP protocol for inbound mail delivery and you can remove _40-pop3_ and _40-pop3s_. These services will still be available, but perhaps you don't want to offer them to the world.

If you want a service only to work for a limited number of specific IP addresses, just add the addresses one per line to the file in _incoming.d_. You may add a domain name instead of an IP address, and _nftfw_ will lookup the name, translating it to actual IP addresses (both types of address: IPv4 and IPv6 if available). It's a good idea to run a caching nameserver on your machine if using names, to prevent slower offsite lookups.

The _05-essential-icmpv6_ is not a service name. It's an action file in _rule.d_  named _essential_icmpv6.sh_. Like all the files in _rule.d_, it's a shell script, and in this case give some firewall rules that IPv6 uses to make things work.

The _07-ftp-helper_ file adds in essential glue that makes the _ftp_ server work. It's not needed it you don't support _ftp_.

If you need to create a special script for a standard service, then you can do so. _nftfw_ gives precedence to action files in _rule.d_ with the same name as a service.

There are several unused rules in the _rule.d_ directory, a text file called _README_ lists them.

### An example for incoming.d

[Skip this example](#outgoingd)

As an _ssh_ user, I frequently install support for a private port for the ssh protocol which helps to keep the script kiddies away.

Let's say we pick port 516 for this, it's not assigned to anything in _/etc/services_. To enable port 516 in the firewall, I'd use _touch_ to make a zero length file:

``` sh
$ cd incoming.d
$ touch 07-516
```

It may be that you don't have access to write in the directory, on Symbiosis the directory belongs to the 'admin' user, on Sympl it's the 'sympl' user. Make sure you log in as the right user, or use _sudo_ to get access.

Now if you _ls -l_, you'll see the empty file. If you are using _incron_, _nftfw_ will run in the background and will add a new rule to the firewall enabling access via port 516. Otherwise you'll need to run:

``` sh
$ sudo nftfw load
```

We now need to convince the _sshd_ process which is listening on port 22  that it should also listen for port 516. Change directory to _/etc/ssh_ and edit the _sshd_config_ file. At the top of the file you'll see:

``` sh
Port 22
```

and you need to edit that to read:

``` sh
Port 22
Port 516
```
You now need to restart the sshd service. If you are on a remote machine and are using *ssh* to connect, this can be somewhat scary to restart the program you need to run to talk to the system. Firewalls will allow current connections to continue, so login using the Port 22 connection in a separate window and stay logged in until you are happy that things are working.

Restart the _sshd_ service and find out what happened:

``` sh
$ sudo systemctl restart sshd
$ sudo systemctl status sshd
```
If all is well, the status should show lines like 'Listening on port 516' and 'Listening on port 22'. Now open a new window on your machine and try it.

``` sh
$ ssh -p 516 MACHINE_NAME
```
and hopefully it should connect. Incidentally if you use _scp_ to copy into the system, you need to enter a capital _-P_ to use the port number.

We have _ssh_ running on a new port, what about port 22? It's still open to the world. You can delete it, or you can add one or more fixed IP addresses into the contents of that file to force it only to work for the addresses that it contains. If you don't have the need for fixed IP addresses, one strategy is to remove it from _incoming.d_ but leave it active. You can use the whitelist system to permit selected users from known IP addresses into the system using _ssh_.

### outgoing.d

Here's what is present in the _outgoing.d_ directory for a standard installation:

``` sh
$ ls outgoing.d
05-essential-icmpv6  50-reject-www-data
```

Files in the directory behave the same as those in _incoming.d_, except that when they contain IP addresses, then those addresses will match the  destination IP address of the packet that's tested.

The default setting _outgoing.d_ is:  if no rule matches the filtered packet then it's accepted and passed on. Adding a file that uses a service name or a port number will load a 'reject' rule, for example (you may not want to do this):

``` sh
40-ssh
42-80
```

will block your machine from sending to an external _sshd_ server, and also to any external websites. If you want to block access to a specific site offering these services, then you can add IP addresses to the file.

The _reject-www-data_ rules is taken from Symbiosis and restricts all outgoing packets owned by the user running the web server to the world, unless the server is looking up a name in a remote DNS server. This is a special rule, and adding IP addresses to the file will whitelist them for the web server. The idea is to prevent any possible malicious actor who has taken over your webserver from talking to the outside world.

### blacklist.d

To blacklist an address, create a file in _blacklist.d_  named by the IP address to add the address into the firewall. The _touch_ command is a simple way to make an empty file.

``` sh
$ touch 198.51.100.40 '2001:db8::6|64'
$ ls blacklist.d
198.51.100.40   2001:db8::6|64  203.0.113.204.auto

```

The first IP address is a version 4 address, and the second a version 6 address. It's usual to match only the top half of an IPv6 address, this is normally written ```2001:db8::6/64```  but we can't use '/' in a Linux file system, and the convention is to replace this by the vertical bar '|' symbol. Note we have to quote the address when used on the command line. The blacklist scanner (see below) creates files ending in _.auto_, you should leave these alone, the scanner will take care of them.

An empty blacklist file will block access to all ports to the IP address given by the name. Adding port numbers into the file, one per line, will restrict access to only those port numbers. The word 'all' can also be added, blocking all incoming ports. If a file contains 'all', other port numbers are ignored.

If your system doesn't have incron installed, you will need to run

``` sh
$ sudo nftfw load
```
after you've changed the directory contents, or wait for the next automatic update.

### whitelist.d

The whitelist directory follows the same basic pattern used to manage the blacklist directory. To whitelist an address, create a file named by the IP address.  The file content can hold ports if you only want to allow access to specific services.

The whitelist scanner will create files ending in _.auto_. See below.

If your system doesn't have incron installed, you will need to run

``` sh
$ sudo nftfw load
```
after you've changed the directory contents, or wait for the next automatic update.

## Starting with _nftfw_

The root user runs_nftfw_ from the command line to create the firewall:

``` sh
$ sudo nftfw load
```

Mostly it's run from the _incron_ daemon which triggers a call to _nftfw_ when files change in one of the action directories. As a catch-all, _cron_ will run the command once an hour.

The _load_ command tries not to make changes to the kernel's tables unless it has to. It creates a set of files that are needed for the complete ruleset and then compares those files with the set that was made on the last run. If the files are identical, no change is needed. The blacklist and whitelist rule sets can be replaced without changing the whole ruleset. The blacklist rules change most frequently, and an update to the blacklist is done without disturbing the remainder of the firewall. In general, all the rules maintain counts of matches, and these counts are reloaded when the complete firewall is replaced. By updating only parts of the firewall, these counts become a good indicator of activity on your system.

The _-f_ or _--full_ flag to the _load_ command forces the new files to be loaded without reference to the last run.

_nftfw_ uses a configuration file in _/usr/local/etc/nftfw/config.ini_ to supply tailoring of various aspects of its operation. The distributed version contains a complete set of the default settings, with the values commented out. The _-i_ flag to _nftfw_ lists all the values that are in force.

_nftfw_ will write error messages into _/var/log/syslog_ using the standard _syslog_ mechanism. To get an listing of what _ntfw_ is doing, set _loglevel_ in the config file to _INFO_.

There are various manual pages - see [Manual page index](man/index.md).

 If you are migrating from another firewall system to _nftfw_, now's the time to look at the [Migrating to nftfw](Installation.md#migrating-to-nftfw) section of the Installation document.

## Blacklist

_nftfw_ contains a scanner whose job is to watch log files and add offending IP addresses into _blacklist.d_. The scanner is started by:

``` sh
$ sudo nftfw blacklist
```
and that's usually run from _cron_ every 15 minutes.

The rules for scanning are supplied by a set of files in _/usr/local/etc/nftfw/patterns.d_. Files here are named by _'pattern-name'.pattern_. Here's part of my _apache2.pattern_ file:

``` sh
#
#  The file we scan for patterns
file  = /var/log/apache2/access.log
# the ports we block, can be the word all
ports = 80,443

#
#  The patterns we use
__IP__.*wget%20http
__IP__.*XDEBUG_SESSION_START=phpstorm.*$
__IP__.* CONNECT .*$
__IP__.*%20UNION.*$
```

Comments are useful, and comment lines are shown by putting a # at the start of the line.

The file is split into two sections. The first couple of statements set the file to be scanned and the ports to be blocked if this pattern is matched. The rest of the file contains several regular expressions that match lines in the logfile.

The file statement can contain shell 'glob' patterns, for example on a Symbiosis/Sympl system, you can scan all the website log files by using:

``` sh
file=/srv/*/public/logs/access.log
```

When scanning files, _nftfw_ remembers the last position it reached in the a file and restarts from that position. When adding a new expression to capture some bad line you've spotted in a log, it can sometimes be confusing that the bad guy doesn't suddenly appear in the blacklist. _nftfw_ supplies a way round this using the 'ports' statement, see below.

The regular expressions contain the 'magic' string ```__IP__``` (two underscores at each end) matching an IPv4 or IPv6 address in the line. If you are a _regex_ novice, then ```.*``` matches 'anything' and the ```$``` matches the end of the line. Most matches can be specified using these simple constructs. Character case is ignored when the expression is matched against lines from the file.

Regular expressions use several characters to mean something special, and if you want to match these characters in a line from a log then they must be preceded by a back-slash (\). The characters are:

``` text
\ . ^ $ * + ? ( ) { } [ ] |

```
It's important to use backslash before these characters to ensure that the expression means what you want it to mean. You can use any of the Python regular expression syntax to match lines, but _nftfw_ will complain if unescaped (..) strings appear, these indicate a 'match group', there should only be one - the ```__IP__``` . You _can_ use 'non-capturing groups'. For example,  to provide alternation,  an expression containing ```(?:word1|word2)```  will match 'word1' or 'word2' at that position in the line.

_nftfw_ will ignore matched addresses that are not 'global', so if your system is a gateway with a local network running from it,  local network addresses are not blacklisted. It also ignores addresses found in the _whitelist.d_ directory. Using the whitelist avoids any entry for 'good' addresses appearing in the blacklist database.

When  _nftfw_ finds a match, it stores the IP address, the ports, the time of first encounter, the time of last encounter and the matching pattern name in a database. It also stores a running count of matches found and the number of 'incidents', the latter is the number of runs of the scanner it has taken to make the match count.

If the match count is over a threshold number, defaulting to 10, and settable in the _config.ini_ file, the scanner will add a file to the _blacklist.d_ directory, triggering a run of _nftfw load_ to put the ip address into the blacklist blocking against the nominated ports. When the match count gets over a second threshold, default 100, and also settable in _config.ini_, the blacklist entry is promoted to blocking all ports.

The current state of the blacklist can be seen by using

``` sh
$ nftfwls
```

and the _-a_ option to this command lists all the entries in the database. _nftfwls_ has a manual page, see the [Manual page index](man/index.md).

### The ports=update option

Once in the firewall, miscreant sites will continue to knock at the door. They are generally robots, and it's good to know if they are still knocking so we can keep them in the firewall. A firewall rule with logging will write a record into _/var/log/syslog_ and the database is updated using the special port value of _update_. Here's _blacklist-update.pattern_:

``` sh
#  Blacklist feedback pattern
#
#  The file we scan for patterns
#
file  = /var/log/syslog
#  Just update the database
ports = update

#
#  The patterns we use
#  depends on Blacklist Logging in place
.*kernel.*Blacklist.*SRC=__IP__.*$
```
when detected, the port action just updates the database counts and time, so you can track if the bad sites have really gone away.

### Testing regular expressions

It's often the case that you see a line in a logfile and think 'I ought to have a rule for that'.  Testing the new line you've just added can be difficult because the logfile reader remembers file positions and won't see the line again unless the action re-occurs.

_nftfw_ can use a special pattern file, setting _ports=test_, that allows you to test the regular expression against some known content to see if it matches. Copy the pattern file that you want check out to a new file, here's a copy of _apache2.pattern_ in _apache2-test.pattern_.

``` sh
#
#  The file we scan for patterns
file  = /var/log/apache2/access.log
# the ports we block, can be the word all
ports = test

#
#  The patterns we use
__IP__.*TESTING EXPRESSION
```

The blacklist scanner will ignore any pattern file with _ports=test_, but it can be used with the single package selection option to _nftfw_. Here's the testing command:

``` sh
$ sudo nftfw -x -p apache2-test blacklist
```

will use data from _apache2-test.pattern_  and will scan the named log file.  The *-x* flag scans the log file from the beginning and will not update the stored file position.  The command will print a table with any matching IP addresses, along with a match count. The command can be re-run if matches fail after adjusting the regular expression in the pattern file.

## Whitelist

The whitelist scanner is started by

``` sh
$ sudo nftfw whitelist
```

and is usually run from _cron_ every 15 minutes, usually 5 minutes after the blacklist run.

It's job is a little simpler than the task faced by the blacklist, it adds the IP addresses used by users of the machine that have logged in from a global IP address into the _whitelist.d_ directory. The _whitelist.d_ directory is tracked by _incron_ and _nftfw load_ will be run to set any changed addresses into the firewall.

The whitelist command looks in the system's _wtmp_ file that records all user logins and system reboots. It can be set to look in the _wtmp_ file that just contains today's activity by changing the _wtmp_ value in _config.

## Rules - rule.d

The _rule_ directory contains small shell scripts that translate firewall actions named in the _incoming.d_ and _outgoing.d_ directories into nftables command lines. Default rules are also used for the whitelist and blacklist generation. Note the coding and management of these files are different from Symbiosis, but the same idea is there, a shell file allows easy additions by users. The files do not run any commands, they output _nftables_ statements to _nftfw_ which stores them and passes the completed file into the _nft_ command.

**nftfw** runs the scripts though the shell and captures the output text, appending it to a file holding  nftables commands. The system calls each action file twice, once for IPv4 and again for IPv6. The processing script uses environment variables to pass parameters into the shell. The parameters are:

- DIRECTION - is set to either 'incoming' or 'outgoing'. The value is most often used to select whether the rule should apply to source or destination IP addresses.
- PROTO - is set to either 'ip' or 'ip6'. These names not only supply the protocol type, but also are the names of the two main tables that form the basic framework, one for each protocol type.
- TABLE - is the name of the table, this is usually 'filter', again defined by the basic framework.
- CHAIN - the chain used to add the rule to.
- PORTS - selects the ports that the rule should apply to, the value can be empty, a single port, or  an _nftables_ anonymous set, several ports separated by commas and wrapped in {} braces.
- IPS - where the rule needs to apply to specific IP addresses, the command will have IPS set. Like the PORTS value, ir can be empty, a single port, or an _nftables_ anonymous set, several ports separated by commas and wrapped in {} braces.
- COUNTER - adds the 'counter' statement to the rule. The value is usually empty, or the word 'counter'
- LOGGER - Finally the LOGGER value is either empty or contains ‘log prefix “String ”’, adding a space after any supplied string from _nftfw_.

There are several examples of these scripts in the _/usr/local/etc/nftfw/rule.d_ and the README file in that directory explains what they do.

## Acknowledgement

All of this is made possible by shamelessly borrowing ideas from Patrick Cherry who created the Symbiosis hosting package for Bytemark of which the firewall system is part.
