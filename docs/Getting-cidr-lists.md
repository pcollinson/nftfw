% Getting CIDR lists
#  Getting CIDR lists

You will want to get hold of lists of IP addresses if you want to use the _blacknets_ feature of _nftfw_ (v0.7.0 or later) to block access from certain countries or IP address ranges. If you want to use this system, check the version of _nftfw_ you have installed, see [How to check on your _nftfw_ version](#how-to-check-your-nftfw-version) at bottom of this page.

To use _blacknets_, you need a file or files containing IP networks, one per line, using 'CIDR' notation. See [Wikipedia](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation) if you need more information on CIDR.

There are several sources for this information, I've used two. There are undoubtedly others.

## ip2location.com

This company, based in the Isle of Man, has been collating IP addresses for many years. They offer a free download of IP addresses per country in several formats aimed at different applications. Visit their page [Block Visitors by Country Using Firewall](https://www.ip2location.com/free/visitor-blocker) and scroll to the bottom of the page for the form.

There are three drop-down menus: choose the country, select IPv6, and CIDR and click DOWNLOAD. The file will be downloaded to your machine.

Place the file in _blacknets.d_, remembering to add _.nets_ as the file suffix.

The IPv6 file contains all the IPv4 addresses, and _nftfw's_ reader will convert the addresses into the correct format.

The downside of this is that you have to download the file by hand, but it's easy to use as a starter.

## Maxmind Geolocation

If you've installed the GeoLite2 database from Maxmind to assist with identifing countries with _nftfwls_, then with some little work you can access their country database and also have your system refresh it once a week.

### Step 1 - Getting the Maxmind database

The script you are about to install looks for your MaxMind license information in _/etc/GeoIP.conf_, so you need to install the Geolocation system first, see [Installing Geolocation](Installing-GeoLocation.md).

You'll need ```wget```, so
``` sh
$ sudo apt install wget
```
Navigate to the _nftfw_ release and find the _cidrlist_ directory. Install the shell script ```getgeocountry``` that pulls the database from MaxMind:
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
The script will have created several files, culminating in  _GeoLite2-Country.db_ containing an _sqlite3_ database made from the downloaded information.

Make this script run once a week by placing a line in the _cron_ file provided as part of the _geoipupdate_ package. Edit _/etc/cron.d/geoipupdate_ adding:
``` sh
30 7    * * 3   root	/var/lib/GeoIP/getgeocountry
```
I run mine an hour after the weekly run of _geoipupdate_, so please do choose the hour and minute to be different from the world.

### Step 2 - Creating the country CIDR file

Return to the _nftfw_ distribution and find the _cidrlist_ directory again. The ```getcountrynet``` script uses the database installed in Step 1 to create a country CIDR file. Install the script:
``` sh
$ sudo cp getcountrynet /usr/local/etc/nftfw
$ cd /usr/local/etc/nftfw
$ sudo chown USER.USER getcountrynet
$ sudo chmod +x getcountrynet
```
The USER.USER here should be whoever owns the _/usr/local/etc/nftfw_ directory. I've installed my command file in this directory on the grounds of 'keeping everything together', but you can put it anywhere that's convenient.

Now run the script as the owner of the directory or use sudo and change ownership afterwards. To run, you can give it any number of two letter ISO country codes and it will create a matching file in _blacknets.d_.
``` sh
$ getcountrynet GB fr
```
will create files called _GB.nets_ and _fr.nets_ in _blacknets.d_. Remember that file systems are case-dependent, so choose your capitalisation and stick with it. I'm assuming you replace the arguments with a country or countries that you want to block.

If you are confident that you've got an appropriate version of _nftfw_ (see below), you can now install the new tables, prudently running a test first:
``` sh
$ sudo nftfw -x load
```
All being well, you can then install the new tables:
``` sh
$ sudo nftfw -f load
```
Finally tell _cron_ to run the ```getcountrynet``` script. Again, I've added a new line to the _/etc/cron.d/geoipupdate_ adding:
``` sh
55 7 	* * 3	USER /usr/local/etc/getcountrynet COUNTRIES
```
the USER should be whoever owns the files, and the arguments should match the ones you typed in earlier.

## How to check  your _nftfw_ version

The _blacknets_ feature from v0.7.0 of _nftfw_ requires a change in the firewall template file _/usr/local/etc/nftfw/nftfw_init.nft_. You may need to check you've updated the _nftfw_init.nft_ file before running _nftfw_ with the CIDR files. This file requires updating by hand, and you may have not installed it.

It the file doesn't contain the string _blacknets_, then you need to update it.
``` sh
$ cd /usr/local/etc/nftfw
$ grep blacknets nftfw_init.nft
```
If the command gives no output, check the copy of the file in the _etc_nftfw_ directory using _grep_.
``` sh
$ grep blacknets etc_nftfw/nftfw_init.nft
```
If this gives output, then copy the _originals_ file over your running version, carefully re-applying any changes you've made.

If there is no output from _grep_ on the copy in _etc_nftfw_, you need to update your _nftfw_ installation to a version after v0.7.0. See [Updating _nftfw_](Updating-nftfw.md).


## General notes

You can create as many files as you like in _blacknets.d_ as long as they are in the correct format. To remove a set from the firewall, simply remove the file.

The files can contain a lot of IP addresses, and processing them can take some time. The reader will cope with automatic detection of IPv4 and IPv6, the conversion of IPv4 addresses when expressed in IPv6 format (which _ip2location.com_ uses), and the removal of some addresses that look like networks but are not. It will also remove duplicates and compresses the IP list down to a set of unique networks. It's possible to run CIDR files from both of the sources shown in this document, and reduce them to a minimal set.

Generally, the files in _blacknets.d_ change rarely, so _nftfw_ will cache processed information on the first reading of the files and will read from the cache when it needs the data to build the firewall. The cache is always reloaded when files in _blacknets.d_ alter or come and go. In addition, the ```-f``` flag to _nftfw_ will clear the cache and start again.
