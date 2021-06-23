#!/bin/sh
# Shell script to discover is the nftfw.path service is
# running. It should not be when import is working because
# it will cause nftfw to go into overdrive.
# This is called from import_path to make sure things
# don't completely mad
# Prints status and exits
# 0 for not running
# 1 for running
# 2 if systemctl is not present
if [ -x /bin/systemctl ]; then
    # we have systemd
   ActiveState=$(systemctl show nftfw.path --no-page | grep '^ActiveState=')
    case "$ActiveState" in
	*=inactive)
	    echo 'nftfw.path is not running'
	    exit 0
	    ;;
	*=active)
	    echo 'nftfw.path is running'
	    exit 1
	    ;;
        *)
	    echo 'Cannot find nftfw.path status, assuming not running'
	    exit 0
	    ;;
    esac
fi
exit 2
