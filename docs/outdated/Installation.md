% Installing nftfw manually
# Installing nftfw manually

## Prerequisites

This document and its actions has been superseded by the [Install _nftfw_ from Debian package](Debian_package_install.md). Users are recommended to use that route to install and update _nftfw_.

This document assumes that you are installing on Debian Buster (and possibly later Debian systems). The manual installation places files under /usr/local and not /. However, all the documentation (apart from the two documents on manual instllation) now assumes that the system is installed under the root of the file system, so some mental translation might be needed.

You will need root access to the machine to install this package.

This system is provides a firewall, and it would not be sensible to implement the installation of a fully installed and working system that might contain rules that would block you from your machine. After installation, a small amount  configuration is needed to place the system into action.

### nftables

``` sh
$ sudo apt install nftables
```
The standard version of _nftables_  for Buster at the time of writing is: 0.9.0-2. Buster backports (sadly not available on Raspberry Pi OS, previously known as Raspian) has a more recent version - 0.9.3-2~bpo10+1, and it's a good idea to upgrade to that. Look in _/etc/apt/sources.list_, and if necessary append:

``` sh
# backports
deb <YOUR SOURCE> buster-backports main contrib non-free
```

then

``` sh
$ sudo apt update
...
$ sudo apt upgrade
...
$ sudo apt -t buster-backports install nftables
```
will upgrade your system to the most recent _nftables_ release.

The _install_ action will tell you that a library is not needed before it installs things. There is a _systemctl_ entry for _nftables_, that  will probably be disabled now. Check with:

``` sh
$ sudo systemctl status nftables
```

If you are not running _iptables_ or _nftables_, it's suggested that _nftables_ service stays off until later in the installation process.

### I've got a live iptables installation

Well, what you need to do depends on what's running in your system. Buster comes ready installed with two flavours of _iptables_: the legacy version and a bridging version using the _iptables_ API,  which maps and loads the _iptables_ formatted rules into _nftables_. You can tell which one you are using by:

``` sh
$ sudo iptables -V
iptables v1.8.2 (nf_tables)
```
If your version output looks like that, then you are OK and can just skip over what follows to **[Python](#python)**.

If the words in brackets says _legacy_ then you need to swap to the _nf_tables_ version. Here's what you do:

FIrst, save the current _iptables_ settings, you'll need to put the settings into the kernel's _nftables_ system when you switch.

``` sh
$ sudo iptables-save > ipsaved
$ sudo ip6tables-save > ip6saved
```

Now change iptables and ip6tables to use the _nftables_ versions:

``` sh
$ sudo update-alternatives --config iptables
# select selection 0, /usr/sbin/iptables-nft, auto mode
$ sudo update-alternatives --config ip6tables
# select selection 0, /usr/sbin/iptables-nft, auto mode
```
Each gives you a menu of options: select  the _nftables_ compatible version. I used option 0 - auto.  Check your _iptables_ command is now at the correct version using _-V_. Finally, reload the _iptables_ data you saved earlier.

``` sh
$ sudo iptables-restore < ipsaved
$ sudo ip6tables-restore < ip6saved
```

You now have two sets of rules loaded into the kernel, the new ones using _nftables_ and the previous _iptables_ set. The kernel will use the new rules but will complain. To remove the old rules:

``` sh
$ sudo iptables-legacy -F
$ sudo ip6tables-legacy -F
```

All done, and it's painless. You have a system that works for both _iptables_  commands and _nftables_ _nft_ command.

### Python

_nftfw_ is coded in Python 3 and the standard Python version on Buster is 3.7.  The _nftfw_ package was developed in part using Python 3.6, and so the _nftfw_ package may run using that version.

We will use _pip3_ to install the _nftfw_ package.

``` sh
$ sudo apt install python3-pip python3-setuptools python3-wheel
```
You may find that ```python3-setuptools``` and ```python3-wheel``` are already installed.

The _nftfwls_ command uses Python's _prettytable_, which may not be installed:

```
 $ sudo apt install python3-prettytable
```

## _nftfw_ Installation

You now need the _nftfw_ distribution. I put mine into _/usr/local/src_, but it can be your home directory.

``` sh
$ sudo apt install git
...
$ cd /usr/local/src
$ sudo git clone https://github.com/pcollinson/nftfw
```
which will create a directory called  _nftfw_.

Change into the _nftfw_ directory and use _pip3_ to install the package. _pip3_ will allow you to uninstall the package at a later date, if you wish.

``` sh
$ sudo pip3 install .
...
Successfully installed nftfw-<version>
```

_pip3_ may complain about access to files because it's being run as the superuser, it's safe to ignore that warning. To uninstall, ```sudo pip3 uninstall nftfw```.

_pip3_ installs four commands: _nftfw_, _nftfwls_, _nftfwedit_ and _nftfwadm_ in _/usr/local/bin_. Since these are system commands, they ought to be in _/usr/local/sbin_, but the Python installation system doesn't allow that.

Take a moment to see if the installation worked by asking _nftfw_ for help:

``` sh
$ nftfw -h
...
```

The next step is to install the basic control files in _/usr/local/etc/nftfw_, the working directories in _/usr/local/var/lib/nftfw_, and the manual pages in _/usr/local/share/man_.

The _Install.sh_ script is interactive, but can be run using a configuration file that provides sensible defaults. You may want to install the firewall control directories and files ( _/usr/local/etc/nftfw_ ) owned by a non-root user to allow for easy alteration without invoking _sudo_. I use my login on my local machine, you may want to use 'admin' for Symbiosis or 'sympl' for Sympl. _nftfw_ will create files in _/usr/local/etc/nftfw_ based on the ownership of that directory. Copy _Autoinstall.default_ to _Autoinstall.conf_, edit the ```AUTO_USER``` to the user you want to use, and then run the script _Install.sh_ script. _Autoinstall.conf_ will be ignored by _git_, so this file can be used for later automated runs.

``` sh
$ sudo sh Install.sh
...
```
The _Install.sh_ script will copy files from the distribution into their correct places. It's safe to run the script again, it will not replace the contents of any directory ending with _.d_, or the two control files in _/usr/local/etc/nftfw_.  The script uses the standard system _install_ program to do its work.

The _Install.sh_ script can also be run interactively, it will offer explanations and ask questions allowing you to control the installation phases. For a default installation, use these answers:

- _Install under /usr/local?_ yes
- _See the files installed?_ your choice
- _Install?_ yes
- _User to replace root?_ 'admin' for Symbiosis, 'sympl' for Sympl, 'return' for root on other systems
- _Install Manual pages?_ yes

In _/usr/local/etc/nftfw_, you will find two files: _config.ini_ and _nftfw_init.nft_. _config.ini_ provides configuration information overriding coded-in settings in the scripts. All entries in the distributed _config.ini_ are commented out using a semi-colon at the start of the line. _nftfw_init.nft_ is the framework template file for the firewall. It's copied into the build system whenever a _nftfw_ creates a firewall. Also, you'll find the  _etc_nftfw_ directory holding all the original settings for the files. The intention is to provide a place for later updates to supply new and fixed default files.

_Install.sh_ also creates the necessary directories into _/usr/local/var/lib/nftfw_.

The final stage of the installation is to copy manual pages into _/usr/local/share/man_.  There are six pages:

- [_nftfw(1)_](man/nftfw.1.md) - manage the Nftfw firewall generator. Describes the main command that creates and manages firewall tables.
- [_nftfwls(1)_](man/nftfwls.1.md) - list the sqlite3 database used for storing IP addresses that have shown themselves to be candidates for blocking.
- [_nftfwedit(1)_](man/nftfwedit.1.md) - provides a command line interface to inspect IP addresses (both in and not in the blacklist  database), and tools to add and delete IP addresses in the database, optionally adding them to the active blacklist.
- [_nftfwadm(1)_](man/nftfwadm.1.md) - provides some tools that may be useful when installing the system.
- [_nftfw-config(5)_](man/nftfw-config.5.md) - describes the contents of the ini-style config file tailoring settings in _nftfw_.
- [_nftfw-files(5)_](man/nftfw-files.5.md) - the format, names and contents of the files used to control the system.

The _man_ command may need '5' in the command line to display the section 5 manual pages. Incidentally, the distribution also has these manual pages in HTML format (see [_man/index.md_](man/index.md)).

You are now ready to create a firewall to suit your needs.

### Paying attention to _config.ini_

The values in the distributed_config.ini_ are all commented out by starting the line with a semi-colon. The value shown is the default value, and won't need changing if the default suits your system.

The _nftables_ _systemd_ service uses a control file (_/etc/nftables.conf_) to reload its tables when the system is rebooted. It's the job of _nftfw_ to create this file, but for safety, the distributed system has to be configured to install it.  By default, the file is written in _/usr/local/etc/nftfw_. Before going live, you will need to edit _nftables\_conf_ setting in _config.ini_ to create the file in _/etc/nftables.conf_.

### Logging

All _nftfw_ programs will write logging message to syslog, and also to the terminal. Error messages are output using logging level ERROR, and information messages using INFO. The scripts turn off direct printing output unless they are talking to a terminal. The scripts all have a _-q_ (_quiet_) flag suppressing terminal output.

The logging level displayed by the scripts is set by a value in the configuration file _config.ini_, and this defaults to INFO, so all messages are displayed. The scripts have a _-v_ (_verbose_) flag that raises the output level to INFO, showing the information messages. To see less information, you may wish to reduce the level to ERROR.

``` sh
;loglevel = INFO
```
to

``` sh
loglevel = ERROR
```

## Using Symbiosis/Sympl control files

_nftfw_ uses the same format for the control files found in the Symbiosis/Sympl firewall directory. There are some differences in the firewall control files that are needed. The distribution offers the same functionality that you would get on a newly installed Sympl/Symbiosis system.

There are some changes in rules needed for firewalls, some of the functionality is now in the _nftables_init.nft_ file, meaning that some entries are not needed. The scanning pattern files in _patterns.d_ have been enhanced to offer new functionality. Look in the manual page for more details [man/nftfw-files.5](nftfw-files - documentation of file formats used in nftfw),

There is a python script in the distribution that will migrate Symbiosis/Sympl settings into the _nftfw_ control files. See _import_tool/_. There's a README file, and running the script _import_to_nftfw.py_  with no arguments provides help on how to use it. It's designed to do nothing unless you ask it to.

## Migrating to nftfw

The distributed _nftfw_ command builds the firewall, installs it in the kernel and saves a copy of what it has created in _/usr/local/etc/nftables.conf_.  The Debian _nftables_ service expects to reload _nftables_ from the file in  _/etc_ on a reboot.

If your system has a running firewall that's not _nftfw_ then you probably don't want to be too hasty about installing the system. I have no expectation that things *will* go wrong, but the ability to go back is important. The steps below provides ways to revert, and explain how to do the installation safely.

First, make sure you open another window to the system and login to the machine with it, this will keep the connection open and you can recover if something goes wrong.

Let's look at where you might be now:

- The system runs a Symbiosis or Sympl system using _iptables_.  In this case, the running firewall can be re-installed using the _{symbiosis|sympl}-firewall_ command. You  should move _/etc/cron.d/symbiosis-firewall_ and  _/etc/incron.d/symbiosis-firewall_ (or equivalent _sympl_ files if present) to a safe place to stop their firewalls from running for now.
- _Or_: The system runs a different firewall system using _iptables_, you can usually use _iptables_save_ to save the settings somewhere, and _iptables_restore_ to put the old rules back.
- _Or_: Your system already runs an _nftables_ based firewall, and you want to try _nftfw_ out. In this case, do make sure that _nftfw_ won't overwrite your _/etc/nftables.conf_ file.
- _Or_: There may be other options.

If you have a live _iptables_ system, check the information about _iptables_ versions and how to set things up at the [top of this document](#ive_got_a_live_iptables_installation).

Having set up the directories in _/usr/local/etc/nftfw_ and the working directories in _/usr/local/var/lib/nftfw_, you can run:
``` sh
$ sudo nftfw -x -v load
```
The _-x_ flag makes _nftfw_  compile the files used in setting up the firewall,  tests their syntax using the _nft_ command, but doesn't install them. The _-v_ flag prints information messages, and is a good idea if you've not altered logging levels in _config.ini_.

Assuming the tests show that the installation is OK,  then you will have a working firewall to install. At this point, if you want to know what will happen, you can change to _/usr/local/var/lib/nftfw/test.d_ and look at the files. The starting point for the firewall is _nftfw_init.nft_, which then includes further files.  We cannot get a fully compiled set without loading the actual kernel tables, and you could do that if you are feeling confident, but not until you've taken the next step.

### Installing

If you are on a Symbiosis or Sympl system, I recommend at this point that you move _/etc/cron.d/{symbiosis|sympl}-firewall_ to a safe place. You don't want this firing when you are doing the next sequence of commands, so remove it from _cron_. On a Symbiosis system, you also need to move _/etc/incron.d/symbiosis-firewall_ to a safe place, you don't want this starting Symbiosis if files in _/etc/symbiosis/firewall.d_ change.

If you have a running _nftables_ or _iptables_ installation, now is the time to run:

``` sh
$ sudo nftfwadm save
```

this saves your _nftables_ settings into _nftfw_'s backup system, so if the  install does fail, it will revert to what you had there before you started meddling. If you are using an _iptables_ based system, fear not, the _nft_ command doing the work will save the _iptables_ settings in _nftables_ format, assuming you have the _nftables_ version of _iptables_ installed and have working tables.

If all is well, you can try loading the rules made by _nftfw_.

``` sh
$ sudo nftfw -f -v load
```

The _-f_ forces a full load and you'll need it if you've run the test. The point of saving the original settings will be apparent if something bad happens on this load, _nftfw_ will reload the kernel state from your saved settings.

If there was no error, you can now see all the tables using:

``` sh
$ sudo nft list ruleset
```

If you need to revert, then now's the time.

``` sh
$ sudo nftfwadm restore
```

replaces the newly installed rules with the tables you saved. The restore command will delete the backup file you stored, so you will need to run _save_  again if you plan to change things and try again.

If you are happy with _nftfw_, then you are nearly all set. If you've used the _save_ command to _nftfwadm_, then you need to remove the backup version of your old settings from the system.

``` sh
$ sudo nftfwadm clean
```
simple deletes the backup file. Don't leave it installed, _nftfw_ makes a backup file on every run so it can backtrack. However, it doesn't create a new file if it exists, and you need to remove your original settings from the system. If you don't remove the file and there's a problem some time in the future, you may find yourself wondering why the firewall in the system is an ancient version. Just where did _that_ come from?

### Final steps

To tidy up, check that the setting of _nftables_conf_ in _nftfw_'s config file _/usr/local/etc/nftfw/config.ini_ reads:

``` text
#  Location of system nftables.conf
#  Usually /etc/nftables.conf
nftables_conf = /etc/nftables.conf
```
and rerun

``` sh
$ sudo nftfw -f load
```
to make sure that the new rules are written into _/etc/nftables.conf_.

Tell _systemctl_ to enable and start its _nftables_ service, if that's needed.

``` sh
$ sudo systemctl enable nftables
$ sudo systemctl start nftables
$ sudo systemctl status nftables
```

On a boot of a Symbiosis or Sympl system, the firewall starts at network up time and closes at network down time. Change into _/etc/network_ and delete _if-up.d/{symbiosis|sympl}-firewall_ and _if-down.d/{symbiosis|sympl}-firewall}_. The file is a symbolic link to the firewall script. This turns out to be an important step, rebooting without having this done results in a bad combination of two firewalls, because the _nftables_ settings  are loaded before the Symbiosis/Sympl ones.

### Setting up _cron_

Like Symbiosis/Sympl, _nftfw_ uses _cron_ to drive regular polls by the firewall loader, and blacklist and whitelist scanners. You'll find a sample _cron_ control file in the _cronfiles_ directory in the distribution. Hopefully, by now, you've moved the Symbiosis or Sympl versions to somewhere where they are not active.

Check _cron-nftfw_ in the _cronfiles_ directory. The file contains _/usr/local/_ as a pathname, if your system is installed from root, you'll need to edit the file to point to the correct location.

Install _cron-nftfw_ in _/etc/cron.d/nftfw_.

``` sh
# go to the nftfw distribution to find cronfiles
$ cd cronfiles
$ sudo cp cron-nftfw /etc/cron.d/nftfw
# cron wants the file to be writeable only by owner
$ sudo chmod g-w /etc/cron.d/nftfw
$ cd ..
```

### Making _nftfw_ control directories 'active'

The original Symbiosis system used the _incron_ system to make the _nftfw_ control directories active, ensuring firewall updates when files alter, appear or disappear. Sympl stopped using _incron_ because it's poorly maintained and buggy. Without automatic updates, the system needs reloading whenever a user changes the contents of one of the directories, and forgetting to run the reload command is a source of errors. _nftfw_ will work  happily without active directories, but it makes the life of the system admin easier.

_nftfw_ supplies control files for _systemd_ using its ability to track file changes and starting a firewall reload when a change is detected in one of the control directories.

To install the files and start the system:

``` sh
# go to the nftfw distribution to find systemd files
$ cd systemd

# check that the nftfw files contain the correct paths, edit if necessary
# install the files
$ sudo cp nftfw.* /etc/systemd/system
$ cd ..

# start the units
$ sudo systemctl enable nftfw.path
$ sudo systemctl start nftfw.path
$ sudo systemctl status nftfw.path
```
The last command should show that the unit is active.

You can test this by going to the _whitelist.d_ directory and adding and removing 8.8.8.8 while monitoring _/var/log/syslog_. The _nftfw_ command should run and update the firewall.

Finally, you can turn off _incron_, if it's running:

``` sh
$ sudo systemctl stop incron
$ sudo systemctl disable incron
```

Finally a tip that's hard to find: reload  _systemd_ if you change the _nftfw_ files after installation and starting:

``` sh
$ sudo systemctl daemon-reload
```

### Configuring the firewall

_nftfw_ is distributed with no outbound packet control except for essential IPV6 rules (that are in _/usr/local/etc/nftfw/nft_init.nft_. The set of inbound rules are aimed at permitting access to _ssh_, _http_ and _https_, _ftp_ and the various email subsystems. The incoming _ftp_ rules are designed to support _Pure FTP_. Firewall configuration is a matter of creating or deleting files in the directories in _/usr/local/etc/nftfw_. You probably need to change settings for your system. Scan through the  [How do I.. or a User's Quick Guide](How_do_I.md) document for a quick start on setting up access for your needs.

### Geolocation

The listing program _nftfwls_ will print out the country that originated packets in the firewall using the _geoip2_ country database available from MaxMind. MaxMind don't charge but want you to create an account with them to access their files.

See  [Installing Geolocation](Installing-GeoLocation.md).

If you want to use the _blacknets_ feature of _nftfw_ to block countries, then _geoip2_ can be used to supply lists of IP networks.

See [Getting CIDR lists](Getting-cidr-lists.md).

### Sympl users: Update your mail system after installation

 A repository that steps through the changes I make to the standard _exim4_/_dovecot_ systems on Sympl to improve feedback and detection of bad IPs - see  [Sympl mail system update](https://github.com/pcollinson/sympl-email-changes).

## You Are There

Now look at:

-  [Updating _nftfw_](Updating-nftfw.md)
   -  How to update _nftfw_.
- [Installing Geolocation](Installing-GeoLocation.md)
  - Installing Geolocation, adding country detection to _nftfwls_, which is optional but desirable.
- [Getting CIDR lists](Getting-cidr-lists.md)
  - How to get CIDR files for use with the _blacknet_ feature..
-  [User's Guide to nftfw](Users_Guide.md)
   -  The full User guide, the first section explains how the system is controlled.
-  [How do I.. or a User's Quick Guide](How_do_I.md)
   -  Answers a bunch of questions about the system.
- [_nftfw_ web site](https://nftfw.uk)
   - All documents are available on the _nftfw_ web site.

All documents can be found on the web from the [_nftfw_ website](https://nftfw.uk).

## Acknowledgement

All of this is made possible by shamelessly borrowing ideas from Patrick Cherry who created the Symbiosis hosting package for Bytemark of which the firewall system is part.
