#!/bin/sh
# Uninstall nftfw installed from source
#
# This script asks questions every step of the way
# and seeks confirmation before deleting anything
#
# remove the nftfw scripts
# remove the control files in etc and lib
# remove the manual pages
# installed crontab entries
# installed systemd entries installed as files
#
# Safety until it's been tested
# set to '' when when dry-run question is asked.
RUNCMD='echo --- Will execute: '
echon() {
    printf "%s" "$*"
}
# returns 0 if answered 'yes'
# returns 1 if answered 'no'
yesno() {
    while true
    do
	echon "$1" "[y|n|q]? "
	read ans
	case "$ans" in
	    y|Y|yes|YES)
		return 0
		;;
	    n|N|no|NO)
		return 1
		;;
	    q|Q|quit|Quit)
		echo 'Abandoning'
		exit 0
		;;
	    *)
		echo Answer y or n '(or q to exit)'
		;;
	esac
    done
}
# test if a variable is
# Yes - return 0 or
# No - return 1
isyes() {
    [ "$1" = 'Yes' ]
}
iam=$(whoami)
if [ ${iam} != 'root' ]; then
    echo 'This script needs to be run by root'
    exit 1
fi
if [ ! -f setup.py ]; then
   echo 'This script needs to run from the source directory'
   exit 1
fi
# Is Debian package installed?
DEB_INSTALLED=No;           apt show nftfw > /dev/null 2>&1 && DEB_INSTALLED=Yes

# Are scripts in /usr/local installed?
LOCAL_SCRIPTS_INSTALLED=No; [ -f /usr/local/bin/nftfw ] && LOCAL_SCRIPTS_INSTALLED=Yes

# Local control files?
local_etc=/usr/local/etc/nftfw
local_var=/usr/local/var/lib/nftfw
HAS_LOCAL_ETC=No;           [ -d $local_etc ] && HAS_LOCAL_ETC=Yes
HAS_LOCAL_VAR=No;           [ -d $local_var ] && HAS_LOCAL_VAR=Yes
isyes ${HAS_LOCAL_ETC} || local_etc=""
isyes ${HAS_LOCAL_VAR} || local_var=""

# Root control files?
# These MAY have been installed by hand
root_etc=/etc/nftfw
root_var=/var/lib/nftfw
HAS_ROOT_ETC=No;            [ -d $root_etc ] && HAS_ROOT_ETC=Yes
HAS_ROOT_VAR=No;            [ -d $root_var ] && HAS_ROOT_VAR=Yes
isyes ${HAS_ROOT_ETC} || root_etc=""
isyes ${HAS_ROOT_VAR} || root_var=""

# Manual pages
MAN_LOOKUP=/usr/local/share/man/man1/nftfw.1
MAN_PAGES='
/usr/local/share/man/man1/nftfw.1
/usr/local/share/man/man1/nftfwadm.1
/usr/local/share/man/man1/nftfwedit.1
/usr/local/share/man/man1/nftfwls.1
/usr/local/share/man/man5/nftfw-config.5
/usr/local/share/man/man5/nftfw-files.5
'
# Has manual pages?
HAS_MAN=No;                 [ -f ${MAN_LOOKUP} ] && HAS_MAN=Yes
# Has cron file?
HAS_CRON=No;                [ -e /etc/cron.d/nftfw -o -e /etc/cron.d/cron-nftfw ] && HAS_CRON=Yes
# Has Systemd files?
# if these exist?
HAS_SYSTEMD=No;             [ -e /etc/systemd/system/nftfw.path -o -e /etc/systemd/system/nftfw.service ] && HAS_SYSTEMD=Yes
#
#
# Given the scan of the system
# build a plan of action
remove_scripts=""
remove_local=""
remove_root=""
remove_man=""
remove_cron=""
remove_systemd=""

if isyes ${LOCAL_SCRIPTS_INSTALLED} ; then
    remove_scripts='pip3 uninstall nftfw'
fi
# check local etc and var
if isyes ${HAS_LOCAL_ETC} || isyes ${HAS_LOCAL_VAR} ; then
    # may be empty
    remove_local="${local_etc} ${local_var}"
    remove_local=$(echo "$remove_local" | sed -e 's/^ //' -e s'/ $//')
fi
# check if root based etc and var
if isyes ${HAS_ROOT_ETC} || isyes ${HAS_ROOT_VAR} ; then
    # may be empty
    remove_root="${root_etc} ${root_var}"
    remove_root=$(echo "$remove_root" | sed -e 's/^ //' -e s'/ $//')
fi
if isyes ${HAS_MAN} ; then
    for file in ${MAN_PAGES}; do
	[ -f $file ] && remove_man="${remove_man} $file"
    done
fi
if isyes ${HAS_CRON} ; then
    if [ -e /etc/cron.d/cron-nftfw ]; then
       remove_cron=/etc/cron.d/cron-nftfw
    fi
    if [ -e /etc/cron.d/nftfw ]; then
	remove_cron="${remove_cron} /etc/cron.d/nftfw"
    fi
    # for testing for '' later
    remove_cron=$(echo "$remove_cron" | sed -e 's/^ //' -e 's/ $//')
fi
if isyes ${HAS_SYSTEMD} ; then
    for file in /etc/systemd/system/nftfw.path /etc/systemd/system/nftfw.service; do
    	if [ -f $file ]; then
	    remove_systemd="$remove_systemd $file"
	fi
    done
    remove_systemd=$(echo "$remove_systemd" | sed -e 's/^ //' -e 's/ $//')
    if [ "$remove_systemd" != "" ]; then
	if isyes "$DEB_INSTALLED" ; then
	    echo '*** There appear to be nftfw files in /etc/systemd/system.'
	    echo '*** They may be masking the systemd versions for the Debian package'
	    echo '*** We suggest that you remove these by hand, and the run'
	    echo '*** sudo systemctl daemon-reload'
	    remove_systemd=''
	fi
    fi
fi
echo 'This script will remove the components of the nftfw system installed from source.'
echo 'Each step is not reversible, so the script first builds a plan of action and'
echo 'will then ask you to confirm the plan before deleting files and directories.'
echo
if [ "$remove_root" != '' ]; then
    if isyes ${DEB_INSTALLED} ; then
	echo "*** This script will not remove: $remove_root"
	echo "*** because the installed Debian package may be using it."
	echo
	remove_root=""
    fi
fi
if [ "$remove_cron" != '' ]; then
    if isyes ${DEB_INSTALLED}; then
	canremove=""
	showmessage=""
	for file in ${remove_cron}; do
	    case $file in
		/etc/cron.d/nftfw)
		    showmessage=$file
		    ;;
		/etc/cron.d/cron-nftfw)
		    canremove=$file
		    ;;
	    esac
	done
	remove_cron=$canremove
	if [ "$showmessage" != '' ]; then
	    echo "This script will not remove: $showmessage"
	    echo "because the installed Debian package may be using it"
	    echo
	fi
    fi
fi
#
# Having done all that we can ask some questions
echo "Now make a selection of what you would like to happen"
echo "You'll get a chance to review your choices."
echo
echo 'Answer y, n or q to just quit then and there.'
echo
proceed='Yes'
while [ "$proceed" = 'Yes' ]; do
      echo "First, do you want to dry-run? It will show you what the script will do."
      echo "Answering 'n' to this will destroy files."
      if yesno "Do you want to dry-run?"; then
	  :
      else
	  RUNCMD=""
      fi
      if [ "$remove_scripts" != "" ]; then
	  edit_remove_scripts="No"
	  echo
          if  yesno "Remove manually installed nftfw python script" ; then
	      edit_remove_scripts='Yes'
	  fi
      fi
      if [ "$remove_local" != "" ]; then
	  edit_remove_local="No"
	  if ! isyes ${DEB_INSTALLED} ; then
	      echo
	      echo "You may wish to retain the nftfw control files, they can"
	      echo "be imported into a new installation of nftfw."
	  fi
          if  yesno "Remove nftfw controls: $remove_local" ; then
	      edit_remove_local='Yes'
	  fi
      fi
      if [ "$remove_root" != "" ]; then
	  edit_remove_root="No"
	  echo
	  echo "You may wish to retain the nftfw control files installed in /etc, they can"
	  echo "be imported into a new installation of nftfw"
	  echo
          if  yesno "Remove nftfw controls in /etc - $remove_root" ; then
	      edit_remove_root='Yes'
	  fi
      fi
      if [ "$remove_man" != "" ]; then
	  edit_remove_man="No"
	  echo
          if  yesno "Remove installed manual pages" ; then
	      edit_remove_man='Yes'
	  fi
      fi
      if [ "$remove_cron" != "" ]; then
	  edit_remove_cron="No"
	  echo
          if  yesno "Remove from cron: $remove_cron" ; then
	      edit_remove_cron='Yes'
	  fi
      fi
      if [ "$remove_systemd" != "" ]; then
	  edit_remove_systemd="No"
	  echo
          if  yesno "Remove manually installed systemd files: $remove_systemd" ; then
	      edit_remove_systemd='Yes'
	  fi
      fi
      if isyes ${edit_remove_scripts} \
	      || isyes ${edit_remove_local} \
	      || isyes ${edit_remove_root} \
	      || isyes ${edit_remove_man} \
 	      || isyes ${edit_remove_cron} \
	      || isyes ${edit_remove_systemd} ; then
	  echo
	  echo "Your selection is:"
	  isyes ${edit_remove_scripts} && echo '    Remove nftfw python scripts'
	  isyes ${edit_remove_local} && echo '    Remove nftfw controls under /usr/local'
	  isyes ${edit_remove_root} && echo '    Remove nftfw controls under /'
	  isyes ${edit_remove_man} && echo '    Remove installed manual pages'
	  isyes ${edit_remove_cron} && echo '    Remove nftfw files for cron'
	  isyes ${edit_remove_systemd} && echo '    Remove manually installed systemd files'
	  echo
	  if ! yesno 'Happy with your selection'; then
	     continue
	  fi
	  if [ "$RUNCMD" = "" ]; then
	      pr='Confirm that you want to delete the selected files'
	  else
	      pr='Confirm that you want to see the commands that will delete the selected files'
	  fi
	  if yesno "$pr" ; then
	      if [ "$remove_scripts" != '' ] && ! isyes ${edit_remove_scripts} ; then
		  remove_scripts=""
	      fi
	      if [ "$remove_local" != '' ] && ! isyes ${edit_remove_local} ; then
		  remove_local=""
	      fi
	      if [ "$remove_root" != '' ] && ! isyes ${edit_remove_root}  ; then
		  remove_root=""
	      fi
	      if [ "$remove_man" != '' ] && ! isyes ${edit_remove_man} ; then
		  remove_man=""
	      fi
	      if [ "$remove_cron" != '' ] && ! isyes ${edit_remove_cron} ; then
		  remove_cron=""
	      fi
	      if [ "$remove_systemd" != '' ] && ! isyes ${edit_remove_systemd} ; then
		  remove_systemd=""
	      fi
	      proceed='No'
	  else
	      echo 'No removal selected'
	      exit 0
	  fi
      else
	  echo 'No removal selected'
	  exit 0
      fi
done
# if we get here then we have some stuff to do.
if [ "$remove_scripts" != "" ]; then
    echo 'Deleting installed script'
    ${RUNCMD} pip3 uninstall .
fi
if [ "$remove_local" != "" ]; then
    echo "Deleting $remove_local"
    ${RUNCMD} rm -rf $remove_local
fi
if [ "$remove_root" != "" ]; then
    echo "Deleting $remove_root"
    ${RUNCMD} rm -rf $remove_root
fi
if [ "$remove_man" != "" ]; then
    echo "Deleting manual pages"
    ${RUNCMD} rm -f $remove_man
fi
if [ "$remove_cron" != "" ]; then
    echo "Deleting $remove_cron"
    ${RUNCMD} rm -f $remove_cron
fi
if [ "$remove_systemd" != "" ]; then
    echo "Deleting $remove_systemd"
    ${RUNCMD} rm -f $remove_systemd
    echo "Reload systemd"
    ${RUNCMD} systemctl daemon-reload
fi
exit 0
