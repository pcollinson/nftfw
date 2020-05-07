% Installation Instructions
#  Installation Instructions

For those of you who just want to follow a list of instructions without any verbiage, this document lists all the steps in the [Installing nftfw](Installation.md) document. There are links, shown as 'Explanation', to the Installation document.

## Basic package installations

([Explanation](Installation.md#nftables))
``` sh
$ sudo apt install nftables
```
If this installs a version less than 0.9.3, then edit ```/etc/apt/sources.d``` and add

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

Install _incron_ ([Explanation](Installation.md#incron))

``` sh
$ sudo apt install incron
```
Install Python packages ([Explanation](Installation.md#python))

``` sh
$ sudo apt install python3-pip
$ sudo apt install python3-prettytable
```

## Check on iptables
Check on the state of _iptables_, and set things up to use the _nftables_ compatibility mode ([Explanation](Installation.md#ive-got-a-live-iptables-installation))

``` sh
$ sudo iptables -V
iptables v1.8.2 (nf_tables)
```
If the output looks like this, then skip to 'Installing _nftfw_. If the word in brackets is 'legacy', do the following

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
$ cd /usr/local/source
$ sudo apt install git
$ sudo git clone https://github.com/pcollinson/nftfw
```
Change into the _nftfw_ directory you've just installed and:

``` sh
$ sudo pip3 install .
...
Successfully installed nftfw-<version>
```

Install _nftfw_ infrastructure:

``` sh
$ sudo sh Install.sh
```
Answers for default installation:
- _Install under /usr/local?_ yes
- _See the files installed?_ your choice
- _Install?_ yes
- _User to replace root?_ 'admin' for Symbiosis, 'sympl' for Symbl, 'return' for root
- _Install Manual pages?_ yes

## Setting up _config.ini_
Edit _/usr/local/etc/nftfw/config.ini_. Change: ([Explanation](Installation.md#paying_attention_to_configini))

``` text
[Owner]
;owner=
```
remove the semi-colon and after the = add the user you selected when installing the files.

Change the logging level for now: Change

``` text
#  what level are we logging at
#  needs to be a level name not a value
#  CRITICAL, ERROR, WARNING, INFO, DEBUG
;loglevel = ERROR
```

remove the semi-colon, and change ERROR to INFO.

If you have a file in _/etc/nftables.conf_ (use _ls_) and you've installed _nftfw_ in the root of the file system, then in the _Locations_ section change

``` text

#  Location of system nftables.conf
#  Usually /etc/nftables.conf
;nftables_conf = /etc/nftables.conf

```
remove the semi-colon, and replace ```/etc/nftables.conf``` by ```/etc/nftables.conf.new```. This avoids writing over the current _/etc/nftables.conf_.

## Disable cron and incron actions

([Explanation](Installation.md#installation))

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

If you don't have a running _nftables_ or _iptables_ firewall, then skip to next section.

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
to test installation. Output should end with 'Install rules in ...' - wherever the _config.ini_ file tells _nftfw_ to store the _nftables.conf_ file. Now skip to next section.
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

## Installing cron and incron
See README in the _cronfiles_ directory.

## Installing Geolocation

This will add country detection to _nftfwls_, which is optional but desirable. See the [document](Installing-GeoLocation.md).

### Sympl users: Update your mail system after installation

 A repository that steps through the changes I make to the standard _exim4_/_dovecot_ systems on Sympl to improve feedback and detection of bad IPs - see  [Sympl mail system update](https://github.com/pcollinson/sympl-email-changes).

## You Are There

Now look at:

-  [Updating _nftfw_](Updating-nftfw.md)
   - How to update _nftfw_.
-  [User's Guide to nftfw](Users_Guide.md)
   - The full User guide, the first section explains how the system is controlled.
-  [How do I.. or a User's Quick Guide](How_do_I.md)
   - Answers a bunch of questions about the system.

## Acknowledgement

All of this is made possible by shamelessly borrowing ideas from Patrick Cherry who created the Symbiosis hosting package for Bytemark of which the firewall system is part.
