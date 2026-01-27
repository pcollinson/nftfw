# Using Spamhaus DROP

What is SpamHaus DROP? To quote from the [spamhaus web page](https://www.spamhaus.org/blocklists/do-not-route-or-peer/):

> Don't Route Or Peer (DROP) lists the worst of the worst IP traffic. It is an advisory “drop all traffic”, containing IP ranges which are so dangerous to internet users that Spamhaus provides access to anyone who wants to add this layer of protection, free of charge.

In recent times, my webservers have been under constant and frequent 'attacks', pretty much from all over the world. It looks like a botnet attack, but is thought to be rogue AI scrapers, wild in the world and looking for unblocked access. These sites seem to be in the spamhaus lists, around 75% of all my inbound traffic is now blocked from blacknets.

Spamhaus generate two files, one for IPv4 and one for IPv6. I am pulling this data, extracting the IP addresses and making a file called _spamhaus_drop.nets_ placed in _nftfw's_ _/etc/blacknets.d_ directory.

## How it works

The data is installed using a simple shell script - _getdrop_. It is placed in directory _/etc/nftfw/spamhaus_drop.d_, when run it accesses Spamhaus's links to obtain the files. These are encoded using *json*, and I use the _jq_ program to extract the IP addresses. The script creates a new file _spamhaus_drop.nets_ in _spamhaus_drop.d_. This file is installed in _blacknets.d._ It's copied if the file doesn't exist, or it compares the two files and only installs the new file if it is different.

I run _getdrop_ regularily from cron, see below.

## How to install

Step 1: Make sure you have the two applications that are needed by _getdrop_.

``` sh
$ sudo apt install curl
$ sudo apt install jq
```
You may already have these commands.

Step 2: Set up the directory in _/etc/nftfw_.
You need to ensure that any files or directories are owned by the user that owns _/etc/nftfw_.

``` sh
$ cd /etc/nftfw
$ mkdir spamhaus_drop.d
```
Now fix the ownership, if this should be root, then

``` sh
$ sudo chown root spamhaus_drop.d
```

Next, copy _getdrop_ to _/etc/nftfw/spamhaus_drop.d_. Check that it's owned by the _nftfw_ user.

Step 3: Test that it works

``` sh
$ cd /etc/nftfw/spamhaus_drop.d
$ ./getdrop
```

This assumes that you are the user that owns the _/etc/nftfw_ tree. If it's owned by root, you can add  _sudo_ in front of the command.

If all is well, then the script will have created _spamhaus_drop.nets_ and will have copied it into _../blacknets.d_. The _nftfw_ program should have woken up and reloaded the nftables for you. If you don't have automatic execution installed, then you can run _nftfw load_ to make that happen.

Step 3: Install the cron entry

First check that the user that the cron entry uses, it should be the same as the owner of the _/etc/nftfw_ directory. Also, you may want to change the action time. Having done that, you can now install the cron file and remove the _.cron_ from the name.

``` sh
sudo cp spamhaus_drop.cron /etc/cron.d/spamhaus_drop
```

That's it.
