% Manual Installation Instructions
#  Manual Installation Instructions

This document and its actions has been superseded by the [Install _nftfw_ from Debian package](Debian_package_install.md). Users are recommended to use that route to install and update _nftfw_.

For those of you who just want to follow a list of instructions without any verbiage, this document lists all the steps in the [Installing nftfw](Installation.md) document. There are links, shown as 'Explanation', to the Installation document.

## Basic package installations

### _nftables_
([Explanation](Installation.md#nftables))

``` sh
$ sudo apt install nftables
```
Optional: If this installs a version less than 0.9.3, then edit ```/etc/apt/sources.d``` and add

``` sh
# backports
deb <YOUR SOURCE> buster-backports main contrib non-free
```
and then

``` sh
$ sudo apt update
$ sudo apt upgrade
$ sudo apt -t buster-backports install nftables
```

Raspberry Pi OS doesn't support buster-backports at the time of writing.

### Python
([Explanation](Installation.md#python))

``` sh
$ sudo apt install python3-pip python3-setuptools python3-wheel
$ sudo apt install python3-prettytable
```

## Check on iptables
Check on the state of _iptables_, and set things up to use the _nftables_ compatibility mode ([Explanation](Installation.md#ive-got-a-live-iptables-installation))

``` sh
$ sudo iptables -V
iptables v1.8.2 (nf_tables)
```
If the output looks like this, then skip to 'Installing _nftfw_'. This is the most likely scenario. If the word in brackets is 'legacy', do the following

``` sh
$ sudo iptables-save > ipsaved
$ sudo ip6tables-save > ip6saved
$ sudo update-alternatives --config iptables
# select selection 0, /usr/sbin/iptables-nft, auto mode
$ sudo update-alternatives --config ip6tables
# select selection 0, /usr/sbin/iptables-nft, auto mode
```
Run the ```sudo iptables -V``` again, to check things have switched, and

``` sh
$ sudo iptables-restore < ipsaved
$ sudo ip6tables-restore < ip6saved
$ sudo iptables-legacy -F
$ sudo ip6tables-legacy -F
```

## Installing _nftfw_
Get _nftfw_ installation and install ([Explanation](Installation.md#nftfw-installation))

``` sh
# Change to a suitable directory, perhaps
$ cd /usr/local/src
$ sudo apt install git
$ sudo git clone https://github.com/pcollinson/nftfw
```
Change into the _nftfw_ directory you've just installed and:

``` sh
$ sudo pip3 install .
...
Successfully installed nftfw-<version>
```
_pip3_ may complain about being run as the superuser, it's safe to ignore that warning.

Install _nftfw_ infrastructure,  without any user interaction:

``` sh
$ cp Autoinstall.default Autoinstall.conf
```
edit the _AUTO_USER_ line to the user you want to use own the files in _etc/nftfw_. The _Autoinstall.conf_ file will be ignored by _git_ so this script can be used to update any future releases.

Install _nftfw_ infrastructure:

``` sh
$ sudo sh Install.sh
```

If you've not created _Autoinstall.conf_, the Install.sh will ask some
questions. Answers for default installation:
- _Install under /usr/local?_ yes
- _See the files installed?_ your choice
- _Install?_ yes
- _User to replace root?_ 'admin' for Symbiosis, 'sympl' for Symbl, 'return' for root on other systems
- _Install Manual pages?_ yes

## Disable cron and incron actions for Sympl or Symbiosis

On Symbiosis move _/etc/cron.d/symbiosis-firewall_ to a safe place.
On Symbiosis move _/etc/incron.d/symbiosis-firewall_ to a safe place.
On Sympl move _/etc/cron.d/sympl-firewall_ to a safe place.

##  Test that nftfw doesn't complain

``` sh
$ sudo nftfw -x -v load
nftfw[15264]: Loading data from /usr/local/etc/nftfw
nftfw[15264]: Creating reference files in /usr/local/var/lib/nftfw/test.d
nftfw[15264]: Test files using nft command
nftfw[15264]: Testing nft rulesets from nftfw_init.nft
nftfw[15264]: Determine required installation
nftfw[15264]: No install needed
```
The number in the log is the process id, so will be different for you.

## Taking precautions if you have a live firewall

If you don't have a running _nftables_ or _iptables_ firewall, then [skip to 'Run a test...'](#run-a-test-if-you-dont-have-a-live-firewall).

If you DO carry on here ([Explanation](Installation.md#installation))

If you have a running firewall, save its rules first:

``` sh
$ sudo nftfwadm save
$ sudo nftfw -f -v load
```
Output should end with 'Install rules in ...' - wherever the _config.ini_ file tells _nftfw_ to store the _nftables.conf_ file.

``` sh
$ sudo nft list ruleset
```
will list the ruleset.

If you have a problem, revert to old rules:

``` sh
$ sudo nftfwadm restore
```
if not
``` sh
$ sudo nftfwadm clean
```

## Run a test if you don't have a live firewall

If you DON'T have a running _nftables_ or _iptables_ firewall ([Explanation](Installation.md#installation))
If you DO then you've done this bit above.

``` sh
$ sudo nftfw -f -v load
```
to test installation. Output should end with 'Install rules in ...' - wherever the _config.ini_ file tells _nftfw_ to store the _nftables.conf_ file.

``` sh
$ sudo nft list ruleset
```

will list the ruleset.

## Final steps
([Explanation](Installation.md#final_steps))

Edit _/usr/local/etc/nftfw/config.ini_ to put the _nftables.conf_ file in the right place

``` text
#  Location of system nftables.conf
#  Usually /etc/nftables.conf
nftables_conf = /etc/nftables.conf
```
run to write it there
``` sh
$ sudo nftfw -f load
```
Tell _systemctl_ to enable and start its _nftables_ service.

``` sh
$ sudo systemctl enable nftables
$ sudo systemctl start nftables
$ sudo systemctl status nftables
```

On a Symbiosis system -

``` sh
$ cd /etc/network
# put into a safe place - in case you want to revert
$ sudo mv if-up.d/symbiosis-firewall ~/up-symbiosis-firewall
$ sudo mv if-down.d/symbiosis-firewall ~/down-symbiosis-firewall
```
On a Sympl system -

``` sh
$ cd /etc/network
# put into a safe place - in case you want to revert
$ sudo mv if-up.d/sympl-firewall ~/up-sympl-firewall
$ sudo mv if-down.d/sympl-firewall ~/down-sympl-firewall
```

This turns out to be an important step, rebooting without having this done results in a bad combination of two firewalls, because the _nftables_ settings  are loaded before the Symbiosis/Sympl ones.

## Installing cron
([Explanation](Installation.md#setting-up-cron))

Change into the _cronfiles_ directory in the distribution.

``` sh
$ cd cronfiles
# check that the paths used in cron-nftfw are correct for you
$ sudo cp cron-nftfw /etc/cron.d/nftfw
# cron wants the file to be writeable only by owner
$ sudo chmod g-w /etc/cron.d/nftfw
$ cd ..
```

## Active control directories
([Explanation](Installation.md#making-nftfw-control-directories-active))

Make _nfwfw_ update the firewall when files in the control directories change. If you don't do this, then you will need to run

``` sh
$ sudo nftfw -f load
```
when you make a change by hand.

Install _systemd_ control files from _systemd_ in the _nftfw_ distribution:

``` sh
$ cd systemd
# check nftfw.path and nftfw.service have correct paths
$ sudo cp nftfw.* /etc/systemd/system
$ cd ..

# start the path unit only
$ sudo systemctl enable nftfw.path
$ sudo systemctl start nftfw.path
$ sudo systemctl status nftfw.path

# DON'T start or enable nftfw.service
# it will be started when needed by nftfw.path
```

Stop incron if it's running and you no longer need it
``` sh
$ sudo systemctl stop incron
$ sudo systemctl disable incron
```

Finally a tip that's hard to find: reload  _systemd_ if you change the _nftfw_ files after installation and starting:

``` sh
$ sudo systemctl daemon-reload
```
## Installing Geolocation

This will add country detection to _nftfwls_, which is optional but desirable. See the [document](Installing-GeoLocation.md). If you plan on blocking addresses by country, then the Geolocation system from Maxmind can provide tools to generate lists of IP addresses in the correct format.

## Configuring the firewall

_nftfw_ is distributed with no rules specified for outbound packets (the _nftfw_init.nft_ file has some builtin default rules. The set of inbound rules are aimed at permitting access to _ssh_, _http_ and _https_, _ftp_ and various email ports. The incoming _ftp_ rules are designed to support _Pure FTP_. Firewall configuration is a matter of creating or deleting files in the various directories in _/usr/local/etc/nftfw_. You probably need to change settings for your system. Scan through the  [How do I.. or a User's Quick Guide](How_do_I.md) document for a quick start on setting up access for your needs.


## Sympl users: Update your mail system after installation

 A repository that steps through the changes I make to the standard _exim4_/_dovecot_ systems on Sympl to improve feedback and detection of bad IPs - see  [Sympl mail system update](https://github.com/pcollinson/sympl-email-changes).

## You Are There

Now look at:

-  [Updating _nftfw_](Updating-nftfw.md)
   - How to update _nftfw_.
- [Installing Geolocation](Installing-GeoLocation.md)
   - How to install GeoIP2
- [Getting CIDR lists](Getting-cidr-lists.md)
   - How to obtain blocking lists for countries
-  [User's Guide to nftfw](Users_Guide.md)
   - The full User guide, the first section explains how the system is controlled.
-  [How do I.. or a User's Quick Guide](How_do_I.md)
   - Answers a bunch of questions about the system.
- [_nftfw_ web site](https://nftfw.uk)
   - All documents are available on the _nftfw_ web site.

## Acknowledgement

All of this is made possible by shamelessly borrowing ideas from Patrick Cherry who created the Symbiosis hosting package for Bytemark of which the firewall system is part.
