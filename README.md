# nftfw - nftables firewall builder for Debian

The **nftfw** package builds firewalls for _nftables_. The system replaces the _iptables_ based firewall package supplied as part of Bytemark's Symbiosis hosting package and also for Sympl, a fork of Symbiosis. **nftfw** copies the simple configuration model for firewall management created for Symbiosis. For example, adding a new IP address to the whitelist simply involves creating a file named for the IP address in a control directory. Adding a new rule permitting access to a port just takes the addition of a suitably named file in another directory. As far as possible, **nftfw** follows the easy-to-use file based user interface designed for Symbiosis and may run using the same control files, making it a viable drop-in choice.

Most hosted systems consist of a server with a single network interface attached to the internet. **nftfw** adds its automatically generated rules to an _nftables_ template file that provides a framework. The template is intentionally accessible and can be changed to support more complex network structures. The distribution provides an example.

_nftfw_ makes extensive use of _nftables_ sets supplying lists of IP addresses for packet matches. It also tries hard to only change the sets when updating content, minimising total reloads of the firewall, allowing effective monitoring of counts.

The **nftfw** package, developed on Debian Buster, is stand-alone, and should work on other Linux distributions. The package is written in Python 3 and needs at least the 3.6 release.

## What's in the System?

The system consists of a single Python package and creates four user commands:

- **nftfw**: The main active script loading the firewall from the control files, with arguments selecting the blacklist and whitelist scanners providing input to the firewall.

- **nftfwls**: The system stores blacklist state in an sqlite3 database, this script lists its data. The default is to display only the installed IP addresses, but the entire database can also be listed. There's an HTML interface for plumbing into a webpage.

- **nftfwedit**: provides a command line interface to inspect IP addresses (both in and not in the blacklist database). Tools provided by options add and delete IP addresses in the database, and additionally will add them to the active blacklist (removal uses the _rm_ command).

- **nftfwadm**: provides some admin tools useful for managing the system installation and firewall testing.

The system comes with a default setup for its control files, and a script installs files on your machine in _/usr/local/_. Files can be placed relative to the root. There is some, hopefully intelligible, documentation and guides.

## Controlling the firewall

Files in directories situated in _/usr/local/etc/nftfw_ (or optionally _/etc/symbiosis/firewall_ or _/etc/sympl/firewall_) control the firewall. _/usr/local/etc/nftfw_ also contains an ini style config file read at startup, optionally changing locations of various files and other program settings.

The control directories are:

- _incoming.d_
Files in the incoming directory provides information to allow or deny inbound connections through the firewall. The file name format is _number-description_ where number is a two digit sequence number providing order to the rules. The _description_  can be a port number, a service name from _/etc/services_ or an action name.

   FIles whose description is a port number or service name use a default action to create the necessary rules for the firewall, for _incoming.d_ the default is to accept the connection.

  Actions are small shell scripts stored in _rule.d_  generating _nftables_ commands appended to setup files. Some actions are default rules like 'reject' or 'drop'. Some actions provide specific settings, for example, _ftp_helper_ adds the necessary extra rules to include the _ftp_ connection helper. The use of shell scripts makes it easy to add local action rules.

  A file in _incoming.d_ is usually empty, but can contain a list of IP addresses to restrict the scope of the rule set it contains.

- _outgoing.d_
  The outgoing directory behaves in the same way as the incoming rule set except that the default action is to reject the matching pattern.

- _whitelist.d_
  The whitelist directory contains files named for IP addresses. IPv6 addresses are usually expressed using /64, with | replacing the / character.

  The files are also generally empty, but can contain specific ports used in the rules. The system provides a whitelist scanner that looks in the system's _wtmp_ file for logins and automatically whitelists the IPs of the users fortunate enough to have a login. Automatically generated files have _.auto_ appended that flags the rule for expiry after some period.

- _blacklist.d_
  The blacklist directory has similar contents to the whitelist. It allows blocking of access to IP addresses and as above, ports can be specified. The system provides an automatic log scanner used to create blacklist files based on frequency of abuse.

- _patterns.d_
  The patterns directory drives the blacklist scanner. It contains a set of files, each file names a log file for scanning and the specific ports placed in the firewall for the pattern. The file statement can specify several files using shell _glob_ syntax. Most of the file contains a set of regular expressions used to match lines in the log file, ```__IP__``` (two underscores at each end) in the regex picks out the IP address. When the scanner finds a match, it records the IP address in a database. When taking a decision whether to blacklist the IP, it compares the total number of matches with a threshold value, and if greater, creates a file in the _blacklist.d_ directory.

## Other documents

See documents in the _docs_ directory:

- [Installing _nftfw](docs/Installation.md)
- [How do I.. or Quick User's Guide](docs/How_do_I.md)
- [User's Guide](docs/Users_Guide.md)
- [Manual Page index](docs/man/index.md)

## Update your mail system

I've add a repository that steps through the changes I make to the standard exim4/dovecot systems on Sympl to improve feedback and detection of bad IPs. Find that here:

- [sympl-email-changes - changes to Sympl buster email installation](https://github.com/pcollinson/sympl-email-changes)

## Request for help

I wanted to do this because I like the simplicity and ease of controlling the firewall. The control system lacks danger,  messing with complex tables isn't needed to add or remove a rule, you just create or delete a file.  Controlling things using the file system is very much part of the UNIX ethos that I embraced willingly many years ago. The user interface to this system is entirely down to the efforts of Patrick Cherry who ran Bytemark, a hosting company in the UK who I used for many years.

Most of what I understand about firewalls has been picked up over the years, largely from folklore. Mine seem to work. However, there may be glaring errors in what this system delivers, helpful suggestions are always welcomed.

If this project is useful to you, and you want to assist, then please do. It would be good to have someone who understands Python and/or Debian packing to assist with what needs to be done to make it more accessible and directly installable. The code is reasonably well commented largely because I need to remember how it works.  I do suspect that the code may offend some Python devotees, since I have only recently converted to the cult.
