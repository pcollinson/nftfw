% Updating nftfw manual installations
# Updating nftfw manual installations

## Get current version

If you've installed _nftfw_ from a zip or tar file, then revisit the github pages and pull the current version. Unpack and install the files.

If you used _git_, then change to the your _nftfw_ source directory and

``` sh
$ git pull
```
which will pull the files that have changed, and will also tell you if you are up-to-date.

If you've run the _nftfw_ system tests, _git_ will complain about some new files. In the _nftfw_ directory:

``` sh
$ cd tests
$ make clean
```
will remove the files created by the tests, and the _pull_ should now work.

To use _git_ in future:

``` sh
$ sudo apt install git
..
# I put my copy in /usr/local/src, and need to be root to install
$ cd /usr/local/src
$ sudo git clone https://github.com/pcollinson/nftfw
```

## Re-install the _nftfw_ Python modules & programs

``` sh
# cd into the installed nftfw directory
$ sudo pip3 install .
# will uninstall the old version say
Successfully installed nftfw-<version>
```

## Re-run the Install.sh script

Will update files in your _etc/nftfw_ directory, but will not touch any working files. The _original_ directory may contain changes that are useful to you. You can use _diff_ to compare your working versions with files in the _original_ directory.

The [Incron] section in the _config.ini_ file can be deleted as it's no longer used.

## Changes for _nftfw_ version 0.8 and onwards

Summary of changes from 0.7 requiring some reconfiguration:

 - Edit config.ini to remove:
    [Owner] section - ownership of files created in etc/nftfw now taken from owner of that directory
    nftfw_base - nftfw now uses it's own control files exclusively.
 - _etc/nftfw/original_ renamed _etc/nftfw/etc_nftfw_
 - Change to nftfw_init.nft to include essential ipv6 icmp coding. Change to _rule.d/essential-icmpv6.sh_. Can remove reference to this rule in incoming.d and outgoing.d.
 - Updated regular expressions in exim4.patterns - now find IP addresses correctly
 - Local action rules should be placed in _/etc/nftfw/local.d_, so that _/rule.d_ can be updated by distributions.

Other changes:

 - New import_tool to import Symbiosis/Sympl configs
 - New Uninstall.sh to remove manual installation
 - Many documentation changes - example files now shown relative to filesystem root - e.g _/etc/nftfw_ rather than _/usr/local/etc/nftfw_.

## Changes for _nftfw_ version 0.7 and onwards

_nftfw_ has gained a new control directory _etc/nftfw/blacknets.d_ which allows you to install files of IP address ranges coded as using CIDR notation. The _blacknets_ system provides blocking of a large number of IP networks based on lists of addresses. It can be used to keep whole countries out, or stop access from large organisations with complex address ranges. There's a document [Getting CIDR lists](Getting-cidr-lists.md) explaining how to get the country lists onto your system. There are other sources of bulk blacklists.

To support the new category of blocking there are some changes to _etc/nftfw/nftfw_init.nft_ that need to be installed, when updating - remember to run the _Install.sh_ script and then copy _etc/nftfw/originals/nftfw_init.nft_ to _etc/nftfw/nftfw_init.nft_. If you've made changes to the installed file, you'll need to edit them in again. It's wise then run

``` sh
$ sudo nftfw -f load
```
to ensure that you have a clean installation.

If you've installed the _systemd_ based active file system, then you will need to update _/etc/systemd/system/nftfw.path_ to include the new _blacknets.d_ directory. Copy the _nftfw.path_ from the _systemd_ directory in the release to _/etc/systemd/system/nftfw.path_, the file contains the five lines that are needed. Then tell _systemd_ to reload:

``` sh
# sudo systemctl daemon-reload
```

## Changes for _nftfw_ version 0.6 and onwards

_ntftw_ no longer recommends the use of _incron_ to provide a 'active' directory so changes in directories in_/usr/local/nftfw_ cause automatic running of the _nftfw load_ command. A _systemd_ unit that watches directories and calls the command replaces _incron_. If you've installed a previous version then you need to unwind parts of the _incron_ support system.

Take these steps if you ran versions of _nftfw_ before 0.6 and used _incron_. These steps are shown in other files, but it seems sensible to emphasise them here. These can be done before or after you install the new version. The _systemd_ can run with version before 0.6, but 0.6 contains some coding changes to make it work a little better.

First, move to the _nftfw_ distribution and replace the _cron.d_ file
``` sh
$ cd cronfiles
# check that the paths used in cron-nftfw are correct for you
$ sudo cp cron-nftfw /etc/cron.d/nftfw
$ cd ..
```

then stop _incron_ from running _nftfw_:
``` sh
$ sudo rm /etc/incron.d/nftfw
```

Install _systemd_ control files from _systemd_ in the _nftfw_ distribution:
``` sh
$ cd systemd
# check nftfw.path and nftfw.service have correct paths
$ sudo cp nftfw.* /etc/systemd/system
$ cd ..

# start the path unit only
$ sudo systemctl enable nftfw.path
$ sudo systemctl start nftfw.path
$ sudo systemctl status

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
