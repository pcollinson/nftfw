% Updating nftfw
# Updating nftfw

## Get current version

If you've installed _nftfw_ from a zip or tar file, then revisit the github pages and pull the current version. Unpack and install the files.

If you used _git_, then change to the source directory and

``` sh
$ git pull
```
which will pull the files that have changed, and will also tell you if you are up-to-date. To use _git_ in future:

``` sh
$ sudo apt install git
# cd to one level above where you want to install
$ git clone https://github.com/pcollinson/nftfw
```

## Re-install the _nftfw_ Python modules & programs

``` sh
# cd into the installed directory
$ sudo pip3 install .
# will uninstall the old version and
Successfully installed nftfw-<version>
```

## Re-run the Install.sh script

Will update files in your _etc/nftfw_ directory, but will not touch any working files. The _original_ directory may contain changes that are useful to you. You can use _diff_ to compare your working versions with the distribution.
