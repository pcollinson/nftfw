% Debian Package Installation
# Install _nftfw_ from the Debian Package

_nftfw_ can be installed from a Debian binary package, there is a zip file called _nftfw_current.zip_ in the [package directory](https://github.com/pcollinson/nftfw/blob/master/package) containing the most recent version. For safety, _nftfw_ needs some configuration after installation. See the installation document [Install _nftfw_ from Debian package](Debian_package_install.md) for a how-to guide.

Following Debian practice, the system is installed in the root of the file system, so the control files will be in _/etc/nftfw_ with the library files in _/var/lib/nftfw_.

## Getting started

This section presents the bare bones of installing the _nftfw_ package on a vanilla system. To cope with some special circumstances, links in this document jump to sets of instructions which start after the main installation documentation.

### Iptables check

First check that you can upgrade your system to run _nftables_:

``` sh
$ sudo iptables -V
iptables v1.8.2 (nf_tables)
```

If the output doesn't say _nf_tables_, then you need to swap your _iptables_ version. See [Switching iptables](#switching-iptables)  below, then come back here when you've done that.

### Download the package

Download the zipfile containing the most recent debian binary package from [nftfw github site](https://github.com/pcollinson/nftfw/package/nftfw_current_deb.zip). This will download a file (_nftfw_current_deb.zip_) used to hide the version number and running _unzip_ on the file will yield the package. The  filename of the package contains a version number and ends in _.deb_, for example _nftfw_1.0.0-1_all.deb_.

### What to do if you are running a manually installed _nftfw_ version

See [Manually installed nftfw](#manually-installed-nftfw) below, and return here when done.

### Install the package

``` sh
$ sudo dpkg -i nftfw_XXXXX_all.deb
```

where XXXXX is the version number of the file you downloaded. _dpkg_ doesn't install dependencies and may complain and stop. If this happens run:

``` sh
$ sudo apt-get --fix-broken install
```
which will install the dependencies and then install _nftfw_.

The ```dkpg -i``` command can also be used to update a previously installed package to a new version.

When installing _nftfw_, you will be asked if you want to change the ownership of the _/etc/nftfw_ directory to allow configuration by a non-root user. When _nftfw_ writes files under the directory it will take the ownership from the owner of _/etc/nftfw_. Debian's _debconf_ is used to remember this setting for later updates, and you can change ownership after installation using:

``` sh
$ sudo dpkg-reconfigure nftfw
```

### What is installed?

The package will install:

- the Python commands in _/usr/bin_: _nftfw_, _nftfwls_, _nftfwedit_ and _nftfwadm_.
- Control files in _/etc/nftfw_, unless they exist. The _rule.d_ directory will be updated. The firewall is populated to permit access to commonly used services.
- Basic directory structure in _/usr/var/lib/nftfw_.
- Manual pages for the commands above, and section 5 manual pages for _nftfw_config_ and _nftfw_files_.
- Documentation and examples in _/usr/share/doc/nftfw_.
- A cron file in _/etc/cron.d/nftfw_, this will need editing to make active.
- _systemd_ path file to enable monitoring of the directories in _/etc/nftfw_.

Many directories have _README_ files explaining what is there and why.

### Check _nftfw_ is running

Check that it's running:

``` sh
$ sudo nftfw -x -v load
nftfw[15264]: Loading data from /etc/nftfw
nftfw[15264]: Creating reference files in /var/lib/nftfw/test.d
nftfw[15264]: Test files using nft command
nftfw[15264]: Testing nft rulesets from nftfw_init.nft
nftfw[15264]: Determine required installation
nftfw[15264]: No install needed
```

The number in the log is the process id, so will be different for you.

## On first installation

See [Taking precautions if you have a live firewall](#precautions-for-a-live-firewall) if your system is running a live _iptables_ or _nftables_ firewall, and you want to keep that active until _nftfw_ is live and configured.

If you are running _nftfw_ on a Sympl or Symbiosis system then you might want to migrate your current firewall settings into _nftfw_ - see [Migrating a Sympl or Symbiosis firewall](#migrating-a-sympl-or-symbiosis-firewall) below. It's a good idea to do this now, before starting systems that run _nftfw_ automatically.

### Loading the rules

Load the rules into the kernel:

``` sh
$ sudo nftfw -f -v load
```
_nftfw_ will tell you what it's done.

### Look at the nftables rules

``` sh
$ sudo nft list ruleset ip | less
```
for ipv4 and

``` sh
$ sudo nft list ruleset ip6 | less
```
for ipv6. Hint: this is a lot to type and you may want to use the commands again, so create and store shell aliases in your shell's _.rc_ file for them.

``` sh
alias nfl='sudo nft list ruleset ip|less'
alias nfl6='sudo nft list ruleset ip6|less'

```

In extremis, you can clear the rules with

``` sh
$ sudo nft flush ruleset
```

### Changing _config.ini_

The _nftables.conf_ file is the input file for the _nftables_ system and is what _nftfw_ creates.  For safety, the distributed version writes the file in _/etc/nftfw/nftables.conf_. The file here can be deleted. You need to tell _nftfw_ to write the file in the correct place - in _/etc_.

Edit _/etc/nftfw/config.ini_ to correctly site the _nftables.conf_  file:

``` text
#  Location of system nftables.conf
#  more comments...
#  Usually /etc/nftables.conf
nftables_conf = /etc/nftables.conf
```
run _nftfw_ to write the file, and also to load the kernel's _nftables_:

``` sh
$ sudo nftfw -f -v load
```

### Start the _nftables_ service

Check that _nftables.service_ is running:

``` sh
$ sudo systemctl status nftables
```
and if not:

``` sh
$ sudo systemctl enable nftables
$ sudo systemctl start nftables
```

### Changing _/etc/cron.d/nftfw_

Edit the _/etc/cron.d/nftfw_ file to make the working lines active, removing the '#' from the start of the lines containing cron commands.

### Start the active control directories

``` sh
$ sudo systemctl enable nftfw.path
$ sudo systemctl start nftfw.path
```

making _nftfw_ run when anything changes in the _incoming.d_, _outgoing.d_, _blacklist.d_, _whitelist.d_ and _blacknets.d_ directories in _/etc_.

### Running on Sympl/Symbiosis?

Sympl has a cron job to reload its firewall and this must be removed. Move _/etc/cron.d/sympl-firewall_ to a safe place, so you can re-install it if you want to revert to the distributed firewall system.

Also for Sympl, remove or move two links to _/usr/sbin/sympl-firewall_ under _/etc/network_:


``` sh
$ cd /etc/network
# put into a safe place - in case you want to revert
$ sudo mv if-up.d/symbiosis-firewall ~/up-symbiosis-firewall
$ sudo mv if-down.d/symbiosis-firewall ~/down-symbiosis-firewall
```

Symbiosis has similar files prefixed by _symbiosis_ that should be removed or saved.

### You are done

If you are new to _nftfw_, look at the [How do I...](How_do_I.md) document which has sections on how to add or remove firewall controls. It should get you going on how to configure the firewall. As distributed, _nftfw_ allows access to most of the usual services supplied by a LAMP system.

You now have an active _nftfw_ system and should look in _/etc/nftfw_ to configure the various control directories to your system needs.

## More complex scenarios

This section contains extra command sequences and information, that are referenced above for special circumstances.

### Switching iptables

Here is what to do if ```iptables -V``` says 'legacy' and not 'nf_tables':

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
The last two commands are very important to clear out the old tables.

[Back to Install the package](#install-the-package)

### Precautions for a live firewall

If have a running _nftables_ or _iptables_ firewall, then it's a good idea to save its rules in _nftfw_'s internal backup system so that the system will revert to your working firewall on a problem.

If you have a running firewall, save its rules first, and then load the _nftfw_ rules:

``` sh
$ sudo nftfwadm save
$ sudo nftfw -f -v load
```

Output should end with 'Install rules in ...' - wherever the _config.ini_ file tells _nftfw_ to store the _nftables.conf_ file. The new rules will be installed in the kernel tables:

``` sh
$ sudo nft list ruleset
```
will list the ruleset which will have been changed by _nftfw_.

If you have a problem, revert to old rules:

``` sh
$ sudo nftfwadm restore
```
if not
``` sh
$ sudo nftfwadm clean
```

What's happening here? The first ```nftfwadm save``` saves the current settings into _nftfw's_ backup file. In the event of _nftfw_ failing, it will revert to the saved information. You can make this happen by using ```restore.``` When testing is over, it's also important to run the ```clean``` command, because _nftfw_ won't create a safety backup file if one exists.

[Back to Loading the rules](#loading-the-rules)

### Migrating a Sympl or Symbiosis firewall

If you are installing _nftfw_ on a Sympl or Symbiosis system then read this section.

The Debian package is supplied with a python script in _/usr/share/doc/nftfw/import_tool_. It can import all the firewall settings from _incoming.d_, _outgoing.d_, _blacklist.d_ and _whitelist.d_ into _nftfw_. The script contains a lot of built-in information and sample commands. The script is also available in the _import_tool_ directory in the _nftfw_ source release.

``` sh
$ cd /usr/share/doc/nftfw/import_tool
$ ./import_to_nftfw.py | less
```

will give you  the basic information.  Running the output through _less_ will help with seeing the output. When run with action arguments, the script will tell you what it intends to do. Arguments are needed to force it to write files. The idea is look and check, then write files by adding an argument. You'll need to use _sudo_ to update things.

Try:
``` sh
$ ./import_to_nftfw --rules
```
to see what rules will be used by the new firewall files. The script understands about the _local.d_ directory and will flag up any local scripts that will need porting into the _nftfw_ system.

Once you've updated the firewall, run _nftfw_ to load the new settings:

``` sh
$ sudo nftfw -f -v load
```
you can check the rules using the _nft_ commands

If are are here from the text above, [return to Loading the rules](#loading-the-rules). Otherwise, if you are upgrading a manually installed firewall, complete the end of Section 3 below.

### Manually installed _nftfw_

There have been some small changes in the way that _nftfw_ works that have been developed to make things simpler for users, and also to remove some of the lesser used features. Mostly, the package installs and expects its control files in _/etc/nftfw_ and will use working files in _/var/lib/nftfw_.

There are a small number of steps that are needed to switch to the package version, the idea here is to retain a working firewall while you are upgrading.

#### 1. Stop cron and systemd

The first thing to do is to stop the background processes that will fire up _nftfw_ in the background.

First cron:
``` sh
$ sudo rm /etc/cron.d/nftfw
```
and then if you've loaded the _systemd_ files as per the installation instructions:

``` sh
$ sudo rm /etc/systemd/system/nftfw.path /etc/systemd/system/nftfw.service
$ sudo systemctl daemon-reload
```

#### 2. Update your source distribution

You are going to need some scripts to help you to migrate and also later to remove the installed source distribution. You don't need (and shouldn't) install or update anything.

#### 3. Are you using part of the Sympl/Symbiosis firewall?

The latest version of _nftfw_ does not support _nftfw_base_ in _config.ini_ that used to point to _/etc/{sympl,symbiosis}/firewall_. If you are not using this feature, then skip to section 4.

Otherwise you need to unwind the linkage and ensure that all the _nftfw_ information is derived from files in _/usr/local/etc/nftfw_. This can be done with the _import_to_nftfw.py_ tool. The command will work to move the current settings from _firewall_ into the directories in _/usr/local/etc/nftfw_. The help information in the tool talks about moving files into _/etc/nftfw_, but the tool will work to install files in _/usr/local/etc/nftfw_ as long as _/etc/nftfw_ doesn't exist. When using the tool, you won't need to update the database. See [Migrating a Sympl or Symbiosis firewall](#migrating-a-sympl-or-symbiosis-firewall) above, then return to complete the para below.

Copy the new version of _nftfw_init.nft_ from _etc_nftfw_ in the source directory to _/usr/local/etc/nftfw_. There are some recent changes in this file. Having updated _/usr/local/etc/nftfw_, you can edit _config.ini_ to remove or comment out the definition for _nftfw_base_ and your current version of _nftfw_ can be used to update the firewall. If you want to check that it's all working as expected:

``` sh
$ sudo nftfw -x -f load
```
can be used to test loading from the source files  without affecting the firewall.

#### 4. Delete the nftfw_ installation

Return to the source distribution and run:

``` sh
$ cd _your source_
$ sudo ./Uninstall.sh
```

It will search for what's installed and where on your system, and ask if you want to delete it.

- On the first run, say 'y' to the dry-run question, it will print the commands that it intends to run.
- To retain the control directories, answer 'no' to 'Remove nftfw controls'. Cautious people may like to backup the two control directories to say _/tmp_ before running the script.
- Say 'yes' to all the other questions.

The script will ask you to confirm your selection before actually doing the deletion deed.

#### 5. Move your directories

``` sh
$ sudo mv /usr/local/etc/nftfw /etc
$ sudo mv /usr/local/var/lib/nftfw /var/lib
```
_nftfw_ will find the files the next time it's run.

#### 6. Ready for package installation now

The package will install several new and amended rules in _/etc/nftfw/rule.d_. It's also a good idea to remove _/etc/nftfw/config.ini_ and _/etc/nftfw/nftfw_init.ini_ before installing the package. They will be reinstalled from up-to-date versions.

The new versions ensure that the rules match the _nftfw_init.nft_ template. Also, importantly, the installed _config.ini_ will not make _nftfw_  write into _/etc/nftables.conf_ until you edit the value. The installation will write its versions in _/etc/nftfw/nftables.conf_, which can be deleted later. The _config.ini_ file will need editing as part on the commissioning process to make _nftfw_ install the file in _/etc_.

If  things go wrong, you can always load the firewall settings from _/etc/nftables.conf_ using:

``` sh
$ sudo nft -f /etc/nftfables.conf
```

Return to [Install the package](#install-the-package).
