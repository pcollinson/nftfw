#!/bin/sh
# System installation / update script for nftfw
# Set the destination root for the copy
# Version number for Autoinstall.conf
if [ "$ZSH_VERSION" != "" ]; then
   emulate -L sh
fi
CURRENT_AUTO_VERSION=1

echon() {
    printf "%s" "$*"
}
yesno() {
    auto=$1
    while true
    do
	if [ "$auto" = "" ]; then
	    echon "$2" "[y|n|q]? "
	    read ans
	else
	    ans=$auto
	fi
	case "$ans" in
	    ""|y|Y|yes|YES)
		return 1
		;;
	    n|N|no|NO)
		return 0
		;;
	    q|Q|quit|Quit)
		echo 'Closing'
		exit 0
		;;
	    *)
		echo Answer y or n
		auto=""
		;;
	esac
    done
}
# thanks to stackoverflow
# https://stackoverflow.com/questions/3236871/how-to-return-a-string-value-from-a-bash-function
# function to read new installation name
# called with name of variable to set
# this *may* be bash specific
# getuser outputvariable
getuser() {
    local _outvar=$1
    local newuser
    echo
    echo "The files will be installed in ${DESTROOT}/etc/nftfw owned by ${INSTALLAS}."
    echo "It's probably better to install this as a general user"
    echo "so they can easily alter the files. For example:"
    echo "- for Symbiosis use: admin"
    echo "- for Sympl use: sympl"
    echo "The group of the file will be set the same name as"
    echo "the user, if it exists."
    echo
    echo "Type name of the user you want to use and type return."
    echo "Just type return to leave it as ${INSTALLAS}"
    echo
    echon "Enter user to replace ${INSTALLAS}? "
    read newuser
    if [ "${newuser}" != "" ]; then
	chkline=$(grep '^'"${newuser}"':' /etc/passwd)
	if [ "${chkline}" = '' ]; then
	    echo "${newuser} not found in /etc/passwd"
	    eval $_outvar=Fail
        else
	    eval $_outvar=\$newuser
	fi
    fi
}
ATTFILE=/tmp/nftfwinstall$$
# echo and save attention message for later consumption
attention() {
    echo "$1"
    echo "$1">>$ATTFILE
}
# Mode to use for file installation
FILEMODE='-m 0644'
export FILEMODE

# User to use for etc/nftfw installation
INSTALLAS=root
export INSTALLAS

iam=$(whoami)
if [ ${iam} != 'root' ]; then
    echo 'This script needs to be run by root'
    exit 1
fi

ETCSRC=etc_nftfw
if [ ! -d ${ETCSRC} ]; then
    echo 'Cannot find the source for installation'
    echo 'Run this command in the nftfw source at the top level'
    exit 1
fi
echo
echo '***************************************************'
echo 'Checking on installed programs and python modules'
echo
# Do we have install
INSTALL=/usr/bin/install
if [ ! -x ${INSTALL} ]; then
    echo 'The script needs the install command'
    echo 'Run'
    echo 'sudo apt install coreutils'
    exit 1
fi
# Do we have pip3
PIP3=/usr/bin/pip3
if [ ! -x ${PIP3} ]; then
    echo 'The script needs pip3'
    echo 'Run'
    echo 'sudo apt install python3-pip'
    exit 1
fi
# DESTDIR is a GNU default that might be in the environment
# as the install root
# nftfw itself looks in /usr/local/etc and /etc
# for the nftfw directory
# code in ntftw/config.py needs changing if any other base locations
# are needed.
if [ "$DESTDIR" = '' ]; then
    DESTROOT=/usr/local
else
    DESTROOT=$DESTDIR
fi
if [ "$DESTROOT" = '/' ]; then
   DESTROOT=''
fi
export DESTROOT
HAVEAUTO=N
if [ -f Autoinstall.conf ]; then
    . ./Autoinstall.conf
    if [ "$AUTO_VERSION" -ne $CURRENT_AUTO_VERSION ]; then
	echo "Automatic nftfw installation problem"
	echo "The version number in Autoinstall.conf does not match the expected"
	echo "value. There's probably been a change in this script needing a new"
	echo "value in Autoinstall.default."

	echo "Please recreate Autoinstall.conf from the current Autoinstall.default,"
	echo "or delete the file to run this script interactively."
	exit 0
    else
	HAVEAUTO=Y
    fi
fi

if [ "$HAVEAUTO" = "N" ]; then
   echo "nftfw installation"
   echo "This is designed to run with dash - which is probably"
   echo "the default for sh on your system, it's been tested with bash"
   echo
   echo "Answer questions with"
   echo "y - for yes"
   echo "n - for no - will usually skip that section"
   echo "q - for quit - which will abandon the script"
else
   echo "nftfw installation"
   echo "Using settings from Autoinstall.conf"
fi
echo
echo '***************************************************'
# if DESTDIR is set don't mess with DESTROOT
if [ "$DESTDIR" != '' ]; then
  echo "Installing files in ${DESTDIR}"
else
  if [ "$HAVEAUTO" = 'N' ]; then
	echo
	echo "Choose the base of the installation, answering 'y'"
	echo "will install all files under ${DESTROOT}, answering 'n'"
	echo "will install under the root of the system (i.e starts with /)"
	echo
    fi
    if yesno "$AUTO_DESTROOT" "Install files under ${DESTROOT}?" ; then
	DESTROOT=''
	echo "Installing files under /"
    else
	echo "Installing files under ${DESTROOT}"
    fi
    if yesno "$AUTO_DESTCONFIRM" "Happy with that?" ; then
	echo "Exit"
	exit 0
    fi
fi
echo
echo "Do you want see the directories and files that are installed, or "
echo "do you prefer for it to be quieter?"
if yesno "$AUTO_SEEFILES"  "See the files?" ; then
    echo "Quiet installation selected"
else
    echo "Files will be displayed"
    INSTALL="/usr/bin/install -v"
fi
echo
echo '***************************************************'
echo "File installation in ${DESTROOT}/etc/nftfw"
echo
# Basic directory in /etc
DOINSTALL=Y
# Set to not empty if the distribution has changed the
# config.ini or nftfw_init.nft files
DISTRIBUTION=""
LAST_DIST="etc_nftfw"
if [ -e ${DESTROOT}/etc/nftfw ]; then
    # See if the original directory has migrated to etc_nftfw
    # if not we'll delete it later
   if [ -d ${DESTROOT}/etc/nftfw/original ]; then
	LAST_DIST=original
    fi
    # See if the distribution has changed config.ini or nftfw_init.nft
    if [ -e ${DESTROOT}/etc/nftfw/${LAST_DIST} ]; then
	if [ -f ${DESTROOT}/etc/nftfw/${LAST_DIST}/config.ini ]; then
	    if ! cmp -s etc_nftfw/config.ini ${DESTROOT}/etc/nftfw/${LAST_DIST}/config.ini; then
		DISTRIBUTION="config.ini"
	    fi
	fi
	if [ -f ${DESTROOT}/etc/nftfw/${LAST_DIST}/nftfw_init.nft ]; then
	    if ! cmp -s etc_nftfw/nftfw_init.nft ${DESTROOT}/etc/nftfw/${LAST_DIST}/nftfw_init.nft; then
		DISTRIBUTION="$(echo ${DISTRIBUTION} "nftfw_init.nft")"
	    fi
	fi
    fi
    if [ ${LAST_DIST} = original ]; then
	rm -rf ${DESTROOT}/etc/nftfw/original
	LAST_DIST="etc_nftfw"
    fi
    echo
    echo "Install control files in ${DESTROOT}/etc/nftfw."
    echo "Existing control files and content in '*.d' will not be replaced"
    echo "The distribution files may be updated if they exist."
    if yesno "$AUTO_ETCINSTALL" "Install?"; then
	echo "Installation skipped"
	DOINSTALL=N
    fi
fi
if [ ${DOINSTALL} = 'Y' ]; then

    echo "Installing control files"
    GROUPNAME=''
    # get the user to install as
    if [ "$AUTO_USER" = "" ]; then
	getuser INSTALLAS
    else
	INSTALLAS=$AUTO_USER
	echo "File ownership set to user $AUTO_USER"
    fi
    if [ ${INSTALLAS} = 'Fail' ]; then
	exit 1
    else
	# see if group exists
	chk=$(grep '^'"${INSTALLAS}"':' /etc/group)
	if [ "${chk}" != '' ]; then
	    GROUPNAME=${INSTALLAS}
	fi
    fi
    SETUSER="-o ${INSTALLAS}"
    if [ "${GROUPNAME}" != '' ]; then
	SETUSER="${SETUSER} -g ${GROUPNAME}"
    fi
    # make base directory
    ${INSTALL} ${SETUSER} -d ${DESTROOT}/etc/nftfw
    (
	cd ${ETCSRC}
	DEST=${DESTROOT}/etc/nftfw
	DIRS="blacklist.d blacknets.d incoming.d local.d outgoing.d patterns.d rule.d whitelist.d"
	for name in ${DIRS}; do
	    if [ ! -d ${DEST}/$name ]; then
		${INSTALL} ${SETUSER} -d ${DEST}/$name
		FILES=$(find $name -maxdepth 1 -type f -a \! -name '.empty' -print)
		if [ "$FILES" != "" ]; then
			${INSTALL} ${SETUSER} ${FILEMODE} -t ${DEST}/$name ${FILES}
		fi
		if [ $name = 'local.d' ]; then
		    attention "Warning: new update policy - rule.d contents are now updated automatically."
		    attention "To modify or add rules, please place them in the new directory: local.d"
		    attention
		fi
	    else
		echo "${DEST}/$name exists - not replaced"
	    fi
	done
	# update rule.d
	FILES=$(find rule.d -maxdepth 1 -type f -a \! -name '.empty' -print)
	for file in ${FILES}; do
	    if [ -f ${DEST}/$file ]; then
		if ! cmp -s $file ${DEST}/$file ; then
	    	    ${INSTALL} --suffix=.bak --backup=simple ${SETUSER} ${FILEMODE} $file ${DEST}/$file
		    attention "${DEST}/$file updated, backup in ${DEST}/${file}.bak"
		    attention
		fi
	    else
		${INSTALL} ${SETUSER} ${FILEMODE} $file ${DEST}/$file
		attention "New rule file: $file installed"
		attention
	    fi
	done
	# finally two files
	SRC="config.ini nftfw_init.nft"
	for name in ${SRC}; do
	    if [ ! -e ${DEST}/$name ]; then
		${INSTALL} ${SETUSER} ${FILEMODE} -t ${DEST} $name
	    else
		echo "${DEST}/$name exists - not replaced"
	    fi
	done

	# setup the etc_nftfw directory
        # First: delete any installed files/directories that no longer exist in
        # the distribution
	if [ -e $DEST/${LAST_DIST} ]; then
	    CURRENT=$(cd $DEST/${LAST_DIST}; ls)
	    if [ "$CURRENT" != "" ]; then
		for name in ${CURRENT}; do
		    if [ ! -e $name ]; then
			rm -rf $DEST/${LAST_DIST}/$name 2> /dev/null
		    fi
		done
	    fi
	fi
	# install etc_nftfw from distribution
	${INSTALL} ${SETUSER} -d $DEST/etc_nftfw
	( FILES=$(find . -maxdepth 1 -type f -print)
	  ${INSTALL} ${SETUSER} ${FILEMODE} -t ${DEST}/etc_nftfw ${FILES}
	  DIRS=$(find . -maxdepth 1 -type d -print)
	  for name in ${DIRS}; do
	      ${INSTALL} ${SETUSER} -d ${DEST}/etc_nftfw/$name
	      FILES=$(find $name -maxdepth 1 -type f -a \! -name '.empty' -print)
	      if [ "$FILES" != "" ]; then
		  ${INSTALL} -C ${SETUSER} ${FILEMODE} -t ${DEST}/etc_nftfw/$name ${FILES}
	      fi
	  done
	)

	# check on file ownership
	# a past install may have the wrong person
	CHOWNARGS=${INSTALLAS}
	if [ "$GROUPNAME" != '' ]; then
	    CHOWNARGS=${CHOWNARGS}':'${GROUPNAME}
	fi
	FILES=$(find ${DESTROOT}/etc/nftfw \! -user ${INSTALLAS} -print)
	if [ "$FILES" != "" ]; then
	    chown "$CHOWNARGS" $FILES
	fi
	FILES=$(find ${DESTROOT}/etc/nftfw \! -group ${GROUPNAME} -print)
	if [ "$FILES" != "" ]; then
	    chgrp "$GROUPNAME" $FILES
	fi
    )
fi
echo
echo '***************************************************'
echo "Directory installation in ${DESTROOT}/var/lib/nftfw"
echo
VARINSTALL=N
VARLIB=${DESTROOT}/var/lib/nftfw
DIRS="build.d install.d test.d"
if [ -e ${VARLIB} ]; then
    for name in ${DIRS}; do
	if [ ! -e ${VARLIB}/$name ]; then
	    VARINSTALL=Y
	fi
    done
else
    VARINSTALL=Y
fi
if [ ${VARINSTALL} = 'Y' ]; then
	echo "Installing in ${DESTROOT}/var/lib/nftfw"
	# Now setup var/lib/nftfw
	${INSTALL} -d ${VARLIB}

	DIRS="build.d install.d test.d"
	for name in ${DIRS}; do
	    if [ ! -e ${VARLIB}/$name ]; then
		${INSTALL} -d ${VARLIB}/$name
	    fi
	done
	echo "Installation done"
else
    echo "Installation not needed - all directories are present"
fi
echo
echo '***************************************************'
echo 'Install Manual pages'
echo

if yesno "$AUTO_MANINSTALL" "Install Manual pages in ${DESTROOT}/usr/man?" ; then
    echo "Manual pages not installed"
else
    echo "Installing in ${DESTROOT}/share/man"
    # And the manual pages
    ( cd docs/man/man
      MAN=${DESTROOT}/share/man
      for m in man1 man5; do
	  ${INSTALL} -d $MAN/$m
	  FILES=$(find ${m} -maxdepth 1 -type f -print)
	  ${INSTALL} ${FILEMODE} -t ${MAN}/${m} ${FILES}
      done
    )
fi
if [ ${DOINSTALL} = 'Y' ]; then
    if [ "${DISTRIBUTION}" != "" -o -f $ATTFILE ]; then
	echo
	echo '***************************************************'
	echo ' WARNING - Config changes'
	echo '***************************************************'
	if [ -f $ATTFILE ]; then
	    echo
	    cat $ATTFILE
	fi
	if [ "${DISTRIBUTION}" != "" ]; then
	    echo
	    echo "The update has modified this file or files: ${DISTRIBUTION}"
	    echo "in ${DESTROOT}/etc/nftfw/etc_nftfw"
	    echo
            echo "You need to replace your active version(s) in ${DESTROOT}/etc/nftfw"
	    echo "with updated copies."
	    echo
	    echo  "If you have not changed the active versions you can copy files"
	    echo "from ${DESTROOT}/etc/nftfw/etc_nftfw to ${DESTROOT}/etc/nftfw."
	    echo
	    echo "If you have changed the active versions, then a manual compare"
	    echo "and edit is needed."
	    echo
	    echo '***************************************************'
	    echo ' WARNING - hand update may be needed'
	    echo '***************************************************'
	fi
    fi
fi
rm -f $ATTFILE
echo
echo
echo "End of install script"
if [ "$HAVEAUTO" = 'N' ]; then
    echo
    echo 'You can automate this process, see instructions in Autoinstall.default'
    echo
fi
