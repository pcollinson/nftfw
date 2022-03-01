% Using fail2ban with nftfw
# Using fail2ban with nftfw

The 0.9.7 release of _nftfw_ contains a new directory _fail2ban_  installed in _/usr/share/doc/nftfw_. The directory contains two action files for _fail2ban_ allowing the system to use _nftfw_ as its firewall. The action interface for _fail2ban_ uses expanded editing functions in the _nftfwedit_ command.

## Installation

Install the action files:

``` sh
$ cd /usr/share/doc/nftfw/fail2ban
$ sudo cp *.conf /etc/fail2ban/action.d
```

Setup the fail2ban configuration to use the new action files. It's probably wise to stop _fail2ban_ while doing this.

``` sh
$ sudo systemctl stop fail2ban
```

Set up a copy of the main configuration file:

``` sh
$ sudo copy jail.conf jail.local
```

Then edit the ```jail.local``` file changing these lines to read:

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

## Caveat

I have tested the two actions included with a _fail2ban_ installation, using the _fail2ban-client_ commands above. However, I have not used the rules on an active installation.

## Thanks

Thanks to the _nftfw_ user who asked me for assistance with _fail2ban_.
