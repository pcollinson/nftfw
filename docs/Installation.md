% Installing nftfw
# Installing nftfw

## Prerequisites

This document assumes  that you are installing on Debian Buster.

### nftables

``` sh
$ sudo apt install nftables
```
The standard version of _nftables_ at the time of writing is: 0.9.0-2. Buster backports has a more recent version - 0.9.3-2~bpo10+1, and it's a good idea to upgrade to that. Look in _/etc/apt/sources.list_, and if necessary append:

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
which will upgrade your system to the most recent _nftables_ release. The install action will tell you that a library is not needed before it installs things. There is a _systemctl_ entry for _nftables_, that will probably be disabled now. Check with

``` sh
$ sudo systemctl status nftables
```

### I've got a live iptables installation

Well, what you need to do depends on what's running in your system. Buster comes ready installed with two flavours of _iptables_: the legacy version and a bridging version using the _iptables_ API,  which maps and loads the _iptables_ formatted rules into _nftables_. You can tell which one you are using by:

``` sh
$ sudo iptables -V
iptables v1.8.2 (nf_tables)
```
if your version output looks like that, then you are OK and can just [skip over](#incron) what follows.

If the words in brackets says _legacy_ then you need to swap to the _nf_tables_ version. Here's what you do:

FIrst, save the current _iptables_ settings, you'll need to put the settings into the kernel's _nftables_ system when you switch.

``` sh
$ sudo iptables-save > ipsaved
$ sudo ip6tables-save > ip6saved
```

Now change iptables and ip6tables to use the _nftables_ versions:

``` sh
$ sudo update-alternatives --config iptables
$ sudo update-alternatives --config ip6tables
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

### incron

_nftfw_ uses incron. It monitors files on the file system and triggers events when the files change. If you don't have it:

``` sh
$ sudo apt install incron
```

As I write, the available version of _incron_ is 0.5.12-1. It has a nasty bug where it will leave processes hanging around on the system. On a busy system, dormant processes can cause problems. There is a fixed version 0.5.12-2, stuck in the Debian testing system. It apparently has a bug which doesn't affect system use, but as a consequence is not released for mortals at the time of writing. If it is now available, I suggest you install it.

I am using a work-around. I have an entry for _cron_ which restarts the program every 24 hours. This removes all the dormant processes. See the sample _cron_ entry in the _cronfiles_ directory.

_nftfw_ doesn't need_incron_, see the note [How do I: do without _incron_?](How_do_I.md#how-do-i-do-without-incron) in the How do I document.

_sympl_ no longer installs _incron_, but I think I like the idea of instant actions when the _nftfw_ control directories change.

### Python

_nftfw_ is coded on Python 3 and the standard Python version on Buster is 3.7.  The _nftfw_ package was developed in part using Python 3.6, and so the _nftfw_ package may run using that version.

We will use pip3 to install the _nftfw_ package.

``` sh
$ sudo apt install python3-pip
```
The _nftfwls_ command uses Python's _prettytable_, which may not be installed:

```
 $ sudo apt install python3-prettytable
```

## _nftfw_ Installation

You now need the _nftfw_  distribution. I put mine into _/usr/local/src_. Change to the directory and unpack the file, or better use

``` sh
$ sudo apt install git
# then cd to one level above where you want to install and
$ git clone https://github.com/pcollinson/nftfw
```
which will create an _nftfw_ directory for you.

Now change into the directory and use _pip3_ to install the package. _pip3_ will allow you to uninstall the package at a later date, if you wish.

``` sh
$ sudo pip3 install .
...
Successfully installed nftfw-<version>
```
To uninstall, ```sudo pip3 uninstall nftfw```.

_pip3_ installs four commands: _nftfw_, _nftfwls_, _nftfwedit_ and _nftfwadm_ in _/usr/local/bin_. Since these are system commands, they ought to be in _/usr/local/sbin_, but the Python installation system doesn't allow that.

Take a moment to see if  the installation worked by asking _nftfw_ for help:

``` sh
$ nftfw -h
...
```

The next step is to install the basic control files in _/usr/local/etc/nftfw_, the working directories in _/usr/local/var/lib/nftfw_, and the manual pages in _/usr/local/share/man_.

The _Install.sh_ script will copy files from the distribution into their correct places. It asks several questions and permits you to control the installation phases. It's safe to run the script again, it will not replace the contents of any directory ending with _.d_, or the two control files in _/usr/local/etc/nftfw_.  The script uses the standard system _install_ program to do its work.

It's a good idea to make files in _/usr/local/etc/nftfw_ owned by a non-root user, so they  are easier to change without using _sudo_. For Symbiosis, the user should be _admin_, for Sympl it will _sympl_. The script asks for a user name and will create these files owned by that user. Later, it's important to edit _/usr/local/etc/nftfw/config.ini_ to tell _nftfw_ the user that you selected.

Take care, and slowly...

``` sh
$ sudo sh Install.sh
...
```
In _/usr/local/etc/nftfw_, you will find two files: _config.ini_ and _nftfw_init.nft_. _config.ini_ provides configuration information overriding coded settings in the scripts. All entries in the distributed files are commented out using a semi-colon at the start of the line. _nftfw_init.nft_ is the framework template file for the firewall. It's copied into the build system whenever a _nftfw_ creates a firewall. Also, you'll find the  _original_ directory holding all the original settings for the files. The intention is to provide a place for later updates to supply new and fixed default files.

_install.sh_ also creates the necessary directories into _/usr/local/var/lib/nftfw_.

The final stage of the installation is to copy manual pages into _/usr/local/share/man_.  There are six pages:

- [_nftfw(1)_](man/nftfw.1.md) - manage the Nftfw firewall generator. Describes the main command that creates and manages firewall tables.
- [_nftfwls(1)_](man/nftfwls.1.md) - list the sqlite3 database used for storing IP addresses that have shown themselves to be candidates for blocking.
- [_nftfwedit(1)_](man/nftfwedit.1.md) - provides a command line interface to inspect IP addresses (both in and not in the blacklist  database), and tools to add and delete IP addresses in the database, optionally adding them to the active blacklist.
- [_nftfwadm(1)_](man/nftfwadm.1.md) - provides some tools that may be useful when installing the system.
- [_nftfw-config(5)_](man/nftfw-config.5.md) - describes the contents of the ini-style config file tailoring settings in _nftfw_.
- [_nftfw-files(5)_](man/nftfw-files.5.md) - the format, names and contents of the files used to control the system.

The _man_ command may need '5' in the command line to display the section 5 manual pages. Incidentally, the distribution also has these manual pages in HTML format (see _docs/man_).

As distributed, Debian Buster comes out of the box using _nfttables_ as the basic firewall with a compatibility mode for _iptables_ installed. Your system may vary. _nftfw_ introduces specific _nftables_ constructs, perhaps adding sets into the mix, the _iptables_ interface will break down. You may have listed the kernel firewall with:

``` sh
$ sudo iptables -L -v -n
```
and now you need to re-educate yourself to run:

``` sh
$ sudo nft list ruleset
```
You are now ready to create  firewall to suit your needs.

### Paying attention to _/usr/local/etc/nftfw/config.ini_

Find the _Owner_ section in the file and change settings for owner and group to fit the user you selected when installing the _etc/nftfw_ files.

If you are running _nftables_, you may need to alter the _nftables\_conf_ setting in _config.ini_ and please read on.  If not, [skip to next section](#logging).

Debian expects systems using _nftables_ to keep a configuration file in _/etc/nfttables.conf_. The file sets up _nftables_ when the system reboots, or when _systemctl_ restarts the _nftables_ service. _nftfw_ will write this file after creating its rule set but depends on configuration in its _config.ini_ file to set its location. As distributed, the value of _nftables_conf_ in _config.ini_ is relative to the installation root. This means you need to take different actions depending on where your _nftfw_ is installed:

- For _nftfw_ installed  in _/usr/local_:
  The default setting of _nftables\_conf_ will be _/usr/local/etc/nftables.conf_, which is the 'wrong' location, but is safe for now.
   You will eventually need to change the _nftables_conf_  setting in _config.ini_ to _/etc/nftables.conf_. Once you are happy with _nftfw_, you will then change the setting to its correct location in _/etc_.

- For _nftfw_ installed in _/_:
  The default setting of _nftables\_conf_ will be _/etc/nftables.conf_, which is the 'right' location, but maybe dangerous now.
  You probably should change the default setting in _nftfw/config.ini_ to prevent it writing or installing _/etc/nftables.conf_ until you are happy. Change the setting to place the file in perhaps _/etc/nftfw/nftables.conf.new_ for now, and change it back later.

### Logging

All _nftfw_ programs will write logging message to syslog, and also to the terminal. Error messages are output using logging level ERROR, and information messages using INFO. The scripts turn off direct printing output unless they are talking to a terminal. The scripts all have a _-q_ (_quiet_) flag suppressing terminal output.

The logging level displayed by the scripts is set by a value in the configuration file _config.ini_, and this defaults to ERROR, so only error messages are displayed. The scripts have a _-v_ (_verbose_) flag that raises the output level to INFO, showing the information messages. Alternatively, the _loglevel_ setting can be set in _config.ini_ to always show these messages.

``` sh
;loglevel = ERROR
```
to

``` sh
loglevel = INFO
```

## Using Symbiosis/Sympl control files

_nftfw_ uses the same format for the control files found in the Symbiosis/Sympl firewall directory _/etc/symbiosis/firewall.d_ or _/etc/sympl/firewall.d_. There is a setting in _config.ini_ which tells _nftfw_ where to look for these files, and this may point at the current directory. The five directories, _incoming.d_, _outgoing.d_, _blacklist.d_, _whitelist_.d and _patterns.d_ are usable by _nftfw_.

_nftfw_ makes three changes to the file format for patterns that make _nftfw_ pattern files incompatible with those used by Symbiosis.

- It's possible to set the _ports=_ value in a pattern file to the word 'update'. The idea is to use the pattern scanning system to look in _/var/log/syslog_ for messages logged by the firewall and use that information to update counts in the blacklist database. The 'update' action doesn't create a new record, it simply updates counts. A blacklisted site will often continue to hammer at the closed door, and the 'update' scan keeps the blacklisting from timing out until the site stops sending packets.

- It's possible to set the _ports=_ value in a pattern file to the word 'test'. See [Testing regular expressions](Users_Guide.md#testing_regular_expressions) in the Users Guide.

- It's possible to use shell-style 'glob' expressions in the _file=_ statement,  enabling the scanning of several related log files by the same set of regular expressions. This is useful for writing one set of rules for several websites whose log files are in separate files.

_nftfw_ has its own set of rules used by actions to create control lines in the firewall. Symbiosis keeps its rules in _/usr/share/lib/symbiosis/firewall/rule.d_ and _nftfw_ has moved its files to its own directory in _/usr/local/etc/nftfw/rule.d_. Several of _nftfw_'s rules are there to provide compatibility with Symbiosis and some of these return nothing because the functionality has migrated into the firewall framework provided by _nftfw_init.nft_.

## Migrating to nftfw

The _nftfw_ command builds the firewall, installs it in the kernel and saves a copy of what it has created in _/etc/nftables.conf_.  Debian expects to reload _nftables_ from the file in  _/etc_ on a reboot.

If your system has a running firewall that's not _nftfw_ then you probably don't want to be too hasty about installing the system. I have no expectation that things *will* go wrong, but the ability to go back is important. Following the steps below provides backup steps and will not take too long.

First, make sure you open another window to the system and login to the machine with it, this will keep the connection open and you can recover if something goes wrong. See the Users Guide for  [An example of incoming.d](Users_guide.md#an_example_of_incoming.d) to see how to do that.

Let's look at where you might be now:

- The system runs a Symbiosis or Sympl system using _iptables_.  In this case, the running firewall can be re-installed using the _{symbiosis|sympl}-firewall_ command. You  should move _/etc/cron.d/symbiosis-firewall_ and  _/etc/incron.d/symbiosis-firewall_ (or equivalent _sympl_ files if present) to a safe place to stop their firewalls from running for now.
- _Or_: The system runs a different system using _iptables_, you can usually use _iptables_save_ to save the settings somewhere, and _iptables_restore_ to put the old rules back.
- _Or_: Your system already runs an _nftables_ based firewall, and you want to try _nftfw_ out. In this case, do make sure that _nftfw_ won't overwrite your _/etc/nftables.conf_ file.
- _Or_: There may be other options.

If you have a live _iptables_ system, check the information about _iptables_ versions and how to set things up at the [top of this document](#Ive_got_a_live_iptables_installation ).

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

this saves your _nftables_ settings into _nftfw_'s backup system, so if the  install does fail, it will revert to what you had there before you started meddling. If you are using an _iptables_ based system, fear not, the _nft_ command doing the work will save the _iptables_ settings in _nftables_ format, assuming you have the _nf_tables_ version of _iptables_ installed and have working tables.

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

``` sh
#  Location of system nftables.conf
#  Usually /etc/nftables.conf
nftables_conf = /etc/nftables.conf
```
and run

``` sh
$ sudo nftfw -f load
```
again to make sure that the new rules are written into _/etc/nftables.conf_.

Tell _systemctl_ to enable and start its _nftables_ service.

``` sh
$ sudo systemctl enable nftables
$ sudo systemctl start nftables
$ sudo systemctl status nftables
```

On a boot of a Symbiosis or Sympl system, the firewall starts at network up time and closes at network down time. Change into _/etc/network_ and delete _if-up.d/{symbiosis|sympl}-firewall_ and _if-down.d/{symbiosis|sympl}-firewall}_. The file is a symbolic link to the firewall script. This turns out to be an important step, rebooting without having this done results in a bad combination of two firewalls, because the _nftables_ settings  are loaded before the Symbiosis/Sympl ones.

### Setting _cron_ and _incron_

Like Symbiosis/Sympl, _nftfw_ uses _cron_ to drive regular polls by the firewall loader, and blacklist and whitelist scanners. _nftfw_ will rebuild its tables when triggered from _incron_ monitoring the four control directories in _/usr/local/etc/nftfw_. You'll find sample _cron_ and _incron_ control files in the _cronfiles_ directory in the distribution. Hopefully, by now, you've moved the Symbiosis or Sympl versions to somewhere where they are  not activ4.

Look in _cronfiles_ in the _nftfw_ distribution. The files there have _/usr/local/_ in them, if your system is installed from root, you'll need to edit both files to point to the correct locations. Install _cron.d-nftfw_ in _/etc/cron.d/nftfw_, and if you are using _incron_, install _incron-nftfw_ in _/etc/incron.d/nftfw_ (if not, remember to edit _config.ini_ to tell _nftfw_).

### Geolocation

The listing program _nftfwls_ will print out the country that originated packets in the firewall using the _geoip2_ country database available from MaxMind. MaxMind don't charge but want you to create an account with them to access their files.

See  [Installing GeoLocation](Installing-GeoLocation.md).

## You Are There

Now look at:
- [Installing GeoLocation](Installing-GeoLocation.md)
- [User's Guide to nftfw](Users_Guide.md)
- [How do I.. or a User's Quick Guide](How_do_I.md)



## Acknowledgement

All of this is made possible by shamelessly borrowing ideas from Patrick Cherry who created the Symbiosis hosting package for Bytemark of which the firewall system is part.
