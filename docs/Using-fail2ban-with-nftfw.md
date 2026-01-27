% Using fail2ban with nftfw
# Using fail2ban with nftfw

The 0.9.7 and later releases of _nftfw_ contains a new directory _fail2ban_  installed in _/usr/share/doc/nftfw_. The directory contains two action files for _fail2ban_ allowing the system to use _nftfw_ as its firewall. The ban action interface for _fail2ban_ uses expanded editing functions in the _nftfwedit_ command to add an IP address into _nftfw_. It will create a file in _/etc/nftfw/blacklist.d_  and add  the IP to _nftfw_'s database. The unban action will remove the file but will leave the IP address information in  the database.

## Installation

Install the action files:

``` sh
$ cd /usr/share/doc/nftfw/fail2ban
$ sudo cp *.conf /etc/fail2ban/action.d
```

Setup the _fail2ban_ configuration to use the new action files. It's probably wise to stop _fail2ban_ while doing this.

``` sh
$ sudo systemctl stop fail2ban
```

We need to make a change to _fail2ban_'s main configuration file, as distributed it's in _/etc/fail2ban/jail.conf_.  The file should not be edited, instead it's conventional to make a copy called  _jail.local_ and edit that.

If you don't have _/etc/jail.local_:

``` sh
$ cd /etc/fail2ban
$ sudo cp jail.conf jail.local
```

If you do:

``` sh
$ cd /etc/fail2ban
$ sudo cp jail.local jail.local.bak

```
Then edit (use  _sudo_  before your edit command)  the _jail.local_ file  changing these lines to read:

``` text
banaction = nftfw-multiport
banaction_allports = nftfw-allports
```

You are now set. Restart _fail2ban_:

``` sh
$ sudo systemctl start fail2ban
```

## Testing

The _fail2ban_ client can test the ban and unban actions.

``` sh
$ sudo fail2ban-client set JAIL banip IP
```

You need to replace JAIL with a jail that is configured in _jail.d_, and IP by an IP address that will be banned.

The results should be:

- Look in _/etc/nftfw/blacklist.d_ and see that a file named _IP.auto_ has been created.

- The _nftfwls_ command will show you that the IP is in _nftfw_'s database. The pattern used to identify the reason of the ban will be _f2b-JAIL_ where JAIL is the name of the jail used in the test.

- The nftables firewall will have been reloaded, assuming that you have actioned _nftfw.path_  in _systemd_ running _nftfw_'s _blacklist_ command when files are changed on the _blacklist.d_ directory. See 'Start the active control directories' in [Install _nftfw_ from Debian package](Debian_package_install.md).

To undo this test, use:

``` sh
$ sudo fail2ban-client set JAIL unbanip IP
```

## Is it working?

_fail2ban_ logs the ban action and the IP that it used but says nothing about the action that is executed.  The action will create a file named _ipaddress.auto_ in _/etc/nftfw/blacklist.d_ and the IP address will be entered into _nftfw_'s database. Database entries are accompanied by a 'pattern' which indicates the source of the ban. The _fail2ban_ actions for _nftfw_ set the pattern to be _f2b-_ followed by the name of the Jail.

Use the _nftfwls_ command to see the current state of _nftfw_.  It uses the contents of _/etc/nftfw/blacklist.d_ to select only active blacklisted IPs. To show all the entries in the database use _nftfwls -a_. You should see some _f2b_ entries in the database.

Alternatively you can use the _nftfwedit_ command to look at one of  the  IP's that _fail2ban_ has logged.

``` sh
$ nftfwedit IPADDRESS
```

Will tell you if the IP is in the database, and if so, whether it's active (i.e. in _/etc/nftfw/blacklist.d_).

## What to do for _fail2ban_ unban

As distributed, the two _fail2ban_ action files will act on _fail2ban_ unban actions by removing the IP from the _/etc/nftfw/blacklist.d_ directory but not from the _nftfw_ database. It's not clear whether this is the right thing to do, it may be better to just ignore the unban instruction and let _nftfw_ time out the IP address. If you would like to try this, cd to _/etc/fail2ban/action.d_ and use sudo with your editor to modify each of _nftfw-allports.conf_ and _nftfw-multiport.conf_. Change

``` text
actionunban = /usr/bin/nftfwedit -r <ip>

```
to
``` text
# actionunban = /usr/bin/nftfwedit -r <ip>
actionunban =
```

The # is a comment so you can put it back later if  needed. Now restart _fail2ban_.

## Caveat

I have tested the two actions included with a _fail2ban_ installation, using the _fail2ban-client_ commands above. Initial results from the user that asked for this capability show that this is working as expected.

## Thanks

Thanks to the _nftfw_ user who asked me for assistance with _fail2ban_.
