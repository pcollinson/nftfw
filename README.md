# Nftfw - Nftables firewall builder for Debian

The _nftfw_ package builds firewalls for _nftables_. The system creates a simple and easy-to-use configuration model for firewall management. The model was created for the _iptables_ based firewall package supplied as part of Bytemark's Symbiosis hosting package and also for Sympl, a fork of Symbiosis. The firewall is controlled using files in a directory structure that maps onto the parts of the firewall. To add a rule, you just add a file. To block an IP address with a specific set of ports, you just add a file.

_nftfw_ doesn't need Sympl or Symbiosis, it's stand-alone and will run on any Debian Buster system or later. It should also work on other Linux distributions derived from Debian. The package is written in Python 3 (version 3.6). These days it's being maintained using Python 3.11, and it now requires at least Python 3.9.

_nftfw_ can be installed from a Debian binary package, there is a zip file called _nftfw_current.zip_ in the [package directory](https://github.com/pcollinson/nftfw/blob/master/package) containing the most recent version. For safety, _nftfw_ needs some configuration after installation. See the installation document [Install _nftfw_ from Debian package](docs/Debian_package_install.md) for a how-to guide.

## New in current release

For full update information see the [Changelog](https://github.com/pcollinson/nftfw/blob/master/ChangeLog). The current release moves from v0.9.16 to v0.9.20.

The v0.9.20 release depends on the Debian version of the Python _nftables_ module. Before running ```dpkg -i``` on the package, do execute:
``` sh
apt install python3-nftables
```
to make the update of _nftfw_ painless. If you don't, dpkg will stop, and you will need to take remedial action to install things. See above (and below) for a link to the Installation document that explains how to extract yourself from this problem.

In addition, there is a change to the default settings for the _nftfw_ file in _cron.d_. When installing _dpkg_ will query whether you want to keep your value or take the released one - use the 'D' option to see the differences. You probably want to keep your version, but make the suggested change by hand.

Main changes:

v0.9.17: The _systemd_ path and service have been told not to worry about ratelimiting starts and restarts. This can happen if _nftfwedit_ is used in a loop to remove or add several ips. _nftfw_ will manage and delay multiple starts.

v0.9.18: Add a flag (-g) to _nftfwls_ to remove GeoIP output. Previously GeoIP information was always shown if the geoip package was installed.

The packaging system for building the debian package has been changed to use the more up-to-date _pyproject.toml_ configuration file.

v0.9.19: Add additional technique for cleaning firewall database of old values. The existing system expires IP addresses after some longish period if they haven't been back to annoy the system. The idea here is to continue to block active sites, but slowly delete ones that have stopped. This system is retained.

However, we now have the rise of botnets, cloud computing and the presence of many hosting companies who simply don't care about what their customers do. The firewall database can get filled with IP addresses that have triggered a pattern match a few times but have never been back to do it again. _nftfw_ counts 'incidents' and 'matchcounts'. Incidents are the number of times an ipaddress has triggered a match in one scan of the log files, and matchcounts record how many abuse patterns have appeared during that scan. It seems sensible to delete these addresses rather sooner than the normal long timeout period.

The new feature is run before the extant removal system. By default, it's not activated and can be turned on from _config.ini_. The new default settings can be found in the default _config.ini_ file under the [Blacklist] section.

v0.9.19: I've removed my version of nftables.py from the distribution. When I started _nftfw_ the standard library was unable to access the full capabilities of _nftables_ so I added some code and included it in the distribution.  The version supplied with python3-nftables now does what was missing and more. I've included this as a requirement for the package, but you may need to use ```apt install python3-nftables```.

v0.9.19: Finally, I've updated documentation and done a pylint sweep using pylint for python 3.11.2, which has changed some minor bits of coding.

v0.9.20: The default time to run the database tidy code in _/etc/cron.d/nftfw_ was incorrectly specified. It was always the intention to run it overnight. The 'doh' moment was to put the time into cron as hh mm, when it should be mm hh. This is now changed.

Add a new tool _nftnetchk_ that compares the current firewall database IPs with the networks found in _blacknets.d_. If any of the IPs are part of a network that's blocked in _blacknets.d_ , then they are not needed in the database. The manual page for _nftnetchk_ supplies a recipe for deleting the IPs.

## Features

- **Easy-to-use firewall admin**.  Five directories control the firewall. Placing files in the directories create firewall rules configured from the file names. Two directories, _incoming.d_ and _outgoing.d_, supply rules allowing access to ports for incoming and outgoing connections. These files are usually empty, but can contain IP addresses to make the rule more specific. Two more directories, _blacklist.d_ and _whitelist.d_, contain IP addresses, blocking or allowing access for named addresses. These files can contain ports, modifying the action of the rule. The final directory, _blacknets.d_ can contain files with lists of IP address ranges and makes rules that block access to all the addresses. Changing the firewall is simply a matter of making or removing a file in one of these directories. The directory contents are described in detail in the [User's Guide](docs/Users_Guide.md), while the [How do I... or Quick Users' Guide](docs/How_do_I.md) gives a more task oriented description.

- **Automatic blacklisting**. The system contains a log file scanner that uses regular expressions to detect unwanted access and then creates files in the _blacklist.d_ directory to block access to any matched IP address. Files to scan, the relevant ports to block for the file and the regular expressions for matching are all contained in a set of files in _patterns.d_. Pattern files are small text files, easy to add and edit,  and the system contains a method of testing them. The _nftfw_ configuration file controls the number of matched lines needed for blocking and how long to wait before removing the IP address from the blacklist.

- **Blacklisting by address range**. The system may be supplied with lists of IP address ranges used to block all the addresses in the ranges. This can be used to block access to specific countries, or unwanted access from organisations.

- **Firewall feedback**.  The blacklist scanner can be told how to scan the _syslog_ file looking for log entries from _nftables_ and updates the blacklist database when a blocked IP address returns, keeping it in the firewall until it stops being active.

- **Automatic whitelisting**. The whitelist scanner looks in the system's _wtmp_ file for logins from users and automatically whitelists their IP address.

- **Full use of _nftables_ sets**. Blacklist and whitelist rules use _nftables_ sets, and _nftfw_ tries not to perform a full firewall reload until it's needed. If just the blacklist or whitelist sets alter, then only the changed sets are reloaded.

- **Configurable _nftables_ template**. A user editable template provides the framework for _nftables_. _nftfw_ uses the template on every firewall build, using 'includes' to pull in its own rules. The use of a template allows for local changes, perhaps to support internal LAN interfaces on a gateway machine. A sample version of the template file used on my gateway machine is supplied in the source distribution.

- **Editable _nftables_ commands**.  Rules in _incoming.d_ and _outgoing.d_ use small action files that are shell scripts to create commands for _nftables_ rules. The scripts are called with a defined set of environment variables and generate output using _echo_. The idea is that local tailoring should be possible and easy.

- **Blacklist monitoring**. The system provides a tool listing the current blacklist status. For each live entry it shows: the IP address and optionally the country of origin, the blocked ports, the date and time of the first and last access and the difference between the two times. HTML output can be generated so the data can be seen from the web. A sample PHP webpage is provided.

- **Admin editing**. A database editor allows admins to add and delete entries from the blacklist database.

- **Initial configuration**. The system comes with a fully configured set of firewall rules and is supplied with some working pattern files that are  in use now keeping the bad guys out.

## Other documents

All documents can be found on the web from the [_nftfw_ website](https://nftfw.uk).

See documents in the _docs_ directory:

- [Install _nftfw_ from Debian package](docs/Debian_package_install.md)
  - Installation from the Debian package found in the package directory.
- [Installing _nftfw manually_](docs/Installation.md)
  - Full installation of the system for Debian Buster or later.
- [Manual Installation Instructions](docs/Installation-Instructions.md)
  - For those who want a bare bones list of tasks.
- [Installing Geolocation](docs/Installing-GeoLocation.md)
  - Installing Geolocation, adding country detection to _nftfwls_, which is optional but desirable.
- [Getting CIDR lists](docs/Getting-cidr-lists.md)
  - How to get CIDR files for use with the _blacknet_ feature.
- [Using fail2ban with nftfw](docs/Using-fail2ban-with-nftfw.md)
  - How to configure _fail2ban_ to use nftfw as its firewall.
- [sympl-email-changes - changes to Sympl bullseye email installation](https://github.com/pcollinson/sympl-email-changes)
  - I've added a repository that steps through the changes I make to the standard _exim4_/_dovecot_ systems on Sympl to improve feedback and detection of bad IPs.
- [Updating _nftfw_](docs/Updating-nftfw.md)
  - How to update a manual installation of _nftfw_.
- [User's Guide](docs/Users_Guide.md)
  - The full User guide, the first section explains how the system is controlled.
- [How do I.. or Quick User's Guide](docs/How_do_I.md)
  - Answers a bunch of questions about the system.
- [Manual Page index](docs/man/index.md)
  - Manual Page index


## Request for help

I wanted to do this because I like the simplicity and ease of controlling the firewall. The control system lacks danger,  messing with complex tables isn't needed to add or remove a rule, you just create or delete a file.  Controlling things using the file system is very much part of the UNIX ethos that I embraced willingly many years ago. The user interface to this system is entirely down to the efforts of Patrick Cherry who ran Bytemark, a hosting company in the UK who I used for many years.

Most of what I understand about firewalls has been picked up over the years, largely from folklore. Mine seem to work. However, there may be glaring errors in what this system delivers, helpful suggestions are always welcomed.
