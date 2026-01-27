% Getting CIDR lists
#  Getting CIDR lists

The _blacknets_ feature of _nftfw_ allows you to block access from ranges of IP addresses. The ranges might come from the various organisations that perpetually scan the internet for their own purposes (some not reading _robots.txt_), or you might want to ban entire countries known for unhelpful activity. To use _blacknets_, you need a file or files containing lists of single IP addresses or networks, one address per line. The network  addresses will use 'CIDR' notation. See [Wikipedia](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation) if you need more information on CIDR.

_nftfw_ will access all the files and create a single _nftables_ set.  This set is used to make a lookup table, any inbound address that is found in the set is blocked by the firewall.  The lists can be very large, and to reduce the lookup work, _nftables_ is able optimise the values in the set. It will ignore duplicates and merge separate definitions for adjacent ranges into a single entry. This feature needs to be activated by providing the _auto-merge_ option to the set definition. There were problems with _auto_merge_ in the early versions of _nftables_, and it was prudent to not use this option as a default.  Debian versions from Bullseye fixed the problem, and  the _nftfw_ _config.ini_ file was provided with options to control the use of _auto-merge_. It's now recommended that the configuration entries in _config.ini_ should be:
```
blacklist_set_auto_merge = True
whitelist_set_auto_merge = True
blacknets_set_auto_merge = True
```

There are several sources for lists of networks by suitable for _blacknets.d_ use. The ones that I use are described below.

## Spamhaus Don't Route Or Peer (DROP) lists

What is Spamhaus DROP? To quote from the [spamhaus web page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/):

> Don't Route Or Peer (DROP) lists the worst of the worst IP traffic. It is an advisory “drop all traffic”, containing IP ranges which are so dangerous to internet users that Spamhaus provides access to anyone who wants to add this layer of protection, free of charge.

In recent times, my web servers have been under constant and frequent 'attacks', pretty much from all over the world. It can look like a botnet attack, but is thought to be rogue AI scrapers, wild in the world, moving from machine to machine, looking for unblocked access. Many of these sites seem to be in the Spamhaus lists, over 75% of all my inbound traffic is blocked from blacknets using DROP.

Spamhaus generate two files, one for IPv4 and one for IPv6. The _nftfw_ distribution supplies a script called _getdrop_ in _/usr/share/doc/nftfw/spamhais_drop_. It can pull the data, extract the IP addresses and make a file called _spamhaus_drop.nets_ placed in _nftfw's_ _/etc/blacknets.d_ directory. The directory also contains a _cron_ entry so the file can be updated on a daily basis.

For more information find the file locally stored on your machine in _/usr/share/doc/nftfw/spamhaus_drop/README.md_ or the  [README file](https://github.com/pcollinson/nftfw/blob/master/spamhaus_drop/README.md).

## Maxmind Geolocation

If you've installed the GeoLite2 database from Maxmind to assist with identifying countries with _nftfwls_, then with some little work you can access their country database to make country specific block files and also have your system refresh them once a week.

### Step 1 - Getting the Maxmind database

The script you are about to install looks for your MaxMind license information in _/etc/GeoIP.conf_, so you need to install the Geolocation system first, see [Installing Geolocation](Installing-GeoLocation.md).

You'll need _wget_, so
``` sh
$ sudo apt install wget
```
Navigate to _/usr/share/doc/nftfw_ (or look in the _nftfw_ release) and find the _cidrlists_ directory. Install the shell script _getgeocountry_ that pulls the database from MaxMind:
``` sh
$ sudo cp getgeocountry /var/lib/GeoIP
$ cd /var/lib/GeoIP
$ sudo chown root.root getgeocountry
$ sudo chmod +x getgeocountry
```
run it
``` sh
$ sudo getgeocountry
```
The script does not use the standard  MaxMind _.mmdb_ files, it loads data in the alternative CSV format and will have created several files in _/var/lib/GeoIP_, culminating in  _GeoLite2-Country.db_ containing an _sqlite3_ database made from the downloaded information.

Make this script run once a week by placing a line in the _cron_ file provided as part of the _geoipupdate_ package. Edit _/etc/cron.d/geoipupdate_ adding:
``` sh
30 7    * * 3   root	/var/lib/GeoIP/getgeocountry
```
I run mine an hour after the weekly run of _geoipupdate_, Do choose the hour and minute to be different from the world.

As a side note, Debian has legacy versions of the MaxMind data that may be installed on your machine. Its data lives in _/usr/share/GeoIP_. The _getgeocountry_ script can be installed in that directory but needs changes to some of the locations given in its shell variable defines to work there.

### Step 2 - Creating the country CIDR file

Find the _cidrlist_ directory again. The ```getcountrynet``` script uses the _sqlite3_ database installed in Step 1 to create a country CIDR file. Install the script:
``` sh
$ sudo cp getcountrynet /etc/nftfw
$ cd /etc/nftfw
$ sudo chown USER:USER getcountrynet
$ sudo chmod +x getcountrynet
```
The USER:USER here should be whoever owns the _/etc/nftfw_ directory. I've installed my command file in this directory on the grounds of 'keeping everything together', but you can put it anywhere that's convenient.

Now run the script as the owner of the directory or use sudo and change ownership afterwards. To run, you can give it any number of two letter ISO country codes and it will create a matching file in _blacknets.d_.
``` sh
$ getcountrynet GB fr
```
will create files called _GB.nets_ and _fr.nets_ in _blacknets.d_. Remember that file systems are case-dependent, so choose your capitalisation and stick with it. THIS IS AN EXAMPLE — I'm assuming that you will replace the arguments with a country or countries that you want to block. It's unwise to add your country to the _blacknets_ list.

If you've enabled the _systemd_ _nftfw.path_ so that any change in _blacknets.d_ will be actioned immediately, then your firewall will now contain these block lists. If you have, skip to [Finally](#Finally) below

If you haven't, then you need to install the new tables:

``` sh
$ sudo nftfw -x load
```
All being well, you can then install the new tables:
``` sh
$ sudo nftfw -f load
```

### Finally

You can check on _nftfw_ status using _systemctl_:
``` sh
sudo systemctl status nftfw
```
which will show the last few actions from _nftfw_.   If you want to see all the log entries then:

``` sh
sudo journalctl -u nftfw
```
will do the trick. You might want to pipe that into _less_. You can check the contents of the _nftables_ _ipv4_ table by using:

``` sh
sudo nft list ruleset ip | less
```

Finally tell _cron_ to run the ```getcountrynet``` script. Again, I've added a new line to the _/etc/cron.d/geoipupdate_ adding:
``` sh
55 7 	* * 3	USER /etc/nftfw/getcountrynet COUNTRIES
```
the USER should be whoever owns the files, and the arguments should match the ones you typed in earlier. Remember to comment this line out if you remove any of the country files from _blacknets.d_, otherwise they will magically re-appear.


## General notes

You can create as many files as you like in _blacknets.d_ as long as they are in the correct format. To remove a set from the firewall, simply remove the file.

The files can contain a lot of IP addresses, and processing them can take some time. The reader will cope with automatic detection of IPv4 and IPv6, the conversion of IPv4 addresses when expressed in IPv6 format, and the removal of some addresses that look like networks but are not. It will also remove duplicates and compresses the IP list down to a set of unique networks. It's possible to run CIDR files from both of the sources shown in this document, and reduce them to a minimal set.

Generally, the files in _blacknets.d_ change rarely, so _nftfw_ will cache processed information on the first reading of the files and will read from the cache when it needs the data to build the firewall. The cache is always reloaded when files in _blacknets.d_ alter or come and go. In addition, the ```-f``` flag to _nftfw_ will clear the cache and start again.
