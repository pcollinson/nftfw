% Using fail2ban with nftfw
# Using fail2ban with nftfw

The 0.9.7 and later releases of _nftfw_ contains a new directory _fail2ban_  installed in _/usr/share/doc/nftfw_. The directory contains two action files for _fail2ban_ allowing the system to use _nftfw_ as its firewall. The ban action interface for _fail2ban_ uses expanded editing functions in the _nftfwedit_ command to add an IP address into _nftfw_. It will create a file in ```/etc/nftfw/blacklist.d```  and add  the IP to _nftfw_'s database. The unban action will remove the file but will leave the IP address information in  the database.

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

We need to make a change to ```fail2ban```'s main configuration file, as distributed it's in ```/etc/fail2ban/jail.conf```.  The file should not be edited, instead it's conventional to make a copy called ```jail.local``` and edit that.

If you don't have ```/etc/jail.local```:

``` sh
$ cd /etc/fail2ban
$ sudo cp jail.conf jail.local
```

If you do:

``` sh
$ cd /etc/fail2ban
$ sudo cp jail.local jail.local.bak

```
Then edit (use  _sudo_  before your edit command)  the ```jail.local``` file  changing these lines to read:

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

- Look in _/etc/nftfw/blacklist.d_ and see that a file named ```IP.auto``` has been created.

- The ```nftfwls``` command will show you that the IP is in _nftfw_'s database. The pattern used to identify the reason of the ban will be ```f2b-JAIL``` where JAIL is the name of the jail used in the test.

- The nftables firewall will have been reloaded, assuming that you have actioned _nftfw.path_  in _systemd_ running _nftfw_'s _blacklist_ command when files are changed on the _blacklist.d_ directory. See 'Start the active control directories' in [Install _nftfw_ from Debian package](Debian_package_install.md).

To undo this test, use:

``` sh
$ sudo fail2ban-client set JAIL unbanip IP
```

## Is it working?

_fail2ban_ logs the ban action and the IP that it used but says nothing about the action that is executed.  The action will create a file named ```ipaddress.auto``` in ```/etc/nftfw/blacklist.d``` and the IP address will be entered into _nftfw_'s database. Database entries are accompanied by a 'pattern' which indicates the source of the ban. The _fail2ban_ actions for _nftfw_ set the pattern to be ```f2b-``` followed by the name of the Jail.

Use the _nftfwls_ command to see the current state of _nftfw_.  It uses the contents of ```/etc/nftfw/blacklist.d``` to select only active blacklisted IPs. To show all the entries in the database use ```nftfwls -a```. You should see some ```f2b``` entries in the database.

Alternatively you can use the _nftfwedit_ command to look at one of  the  IP's that _fail2ban_ has logged.

``` sh
$ nftfwedit IPADDRESS
```

Will tell you if the IP is in the database, and if so, whether it's active (i.e. in ```/etc/nftfw/blacklist.d```).

## What to do for _fail2ban_ unban

As distributed, the two _fail2ban_ action files will act on _fail2ban_ unban actions by removing the IP from the ```/etc/nftfw/blacklist.d``` directory but not from the _nftfw_ database. It's not clear whether this is the right thing to do, it may be better to just ignore the unban instruction and let _nftfw_ time out the IP address. If you would like to try this, cd to ```/etc/fail2ban/action.d``` and use sudo with your editor to modify each of ```nftfw-allports.conf``` and ```nftfw-multiport.conf```. Change

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
