% Updating nftfw
# Updating nftfw

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

Will update files in your _etc/nftfw_ directory, but will not touch any working files. The _original_ directory may contain changes that are useful to you. You can use _diff_ to compare your working versions with the distribution.
