#!/bin/sh
# System installation / update script for nftfw
# Set the destination root for the copy
echon() {
    printf "%s" "$*"
}
yesno() {
    while true
    do
	echon "$1" "[y|n|q]? "
	read ans
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
echo "nftfw installation - ensure you are in the directory"
echo "that contains Install.sh"
echo "This is designed to run with dash - which is probably"
echo "the default for sh on your system, it's been tested with bash"
echo
echo "Answer questions with"
echo "y - for yes"
echo "n - for no - will usually skip that section"
echo "q - for quit - which will abandon the script"

export DESTROOT

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
# This looks hopeful
DESTROOT=/usr/local
if [ $DESTROOT = '/' ]; then
   DESTROOT=''
fi
echo
echo '***************************************************'
echo 'Setting things up'
echo
echo "Choose the base of the installation, answering 'y'"
echo "will install all files under ${DESTROOT}, answering 'n'"
echo "will install under the root of the system (i.e starts with /)"
if yesno "Install files under ${DESTROOT}?" ; then
    DESTROOT=''
    echo "Installing under /"
else
    echo "Installing under ${DESTROOT}"
fi
if yesno "Happy with that?" ; then
    echo "Exit"
    exit 0
fi
echo
echo "Do you want see the directories and files that are installed, or "
echo "do you prefer for it to be quieter?"
if yesno "See the files?" ; then
    :
else
    INSTALL="/usr/bin/install -v"
fi
echo
echo '***************************************************'
echo "File installation in ${DESTROOT}/etc/nftfw"
echo
# Basic directory in /etc
DOINSTALL=Y
if [ -e ${DESTROOT}/etc/nftfw ]; then
    echo
    echo "Step 1 is to install ${DESTROOT}/etc/nftfw."
    echo "Existing control files and content in '*.d' will not be replaced"
    echo "The distribution files may be updated if they exist."
    if yesno "Install?"; then
	DOINSTALL=N
    fi
fi
if [ ${DOINSTALL} = 'Y' ]; then

    GROUPNAME=''
    # get the user to install as
    getuser INSTALLAS
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
	DIRS="blacklist.d incoming.d outgoing.d patterns.d rule.d whitelist.d"
	for name in ${DIRS}; do
	    if [ ! -d ${DEST}/$name ]; then
		${INSTALL} ${SETUSER} -d ${DEST}/$name
		FILES=$(find $name -maxdepth 1 -type f -a \! -name '.empty' -print)
		if [ "$FILES" != "" ]; then
		    ${INSTALL} ${SETUSER} ${FILEMODE} -t ${DEST}/$name ${FILES}
		fi
	    else
		echo "${DEST}/$name exists - not replaced"
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

	# setup the original directory
	${INSTALL} ${SETUSER} -d $DEST/original
	( cd original
	  FILES=$(find . -maxdepth 1 -type f -print)
	  ${INSTALL} ${SETUSER} ${FILEMODE} -t ${DEST}/original ${FILES}
	  DIRS=$(find . -maxdepth 1 -type d -print)
	  for name in ${DIRS}; do
	      ${INSTALL} ${SETUSER} -d ${DEST}/original/$name
	      FILES=$(find $name -maxdepth 1 -type f -a \! -name '.empty' -print)
	      if [ "$FILES" != "" ]; then
		  ${INSTALL} -C ${SETUSER} ${FILEMODE} -t ${DEST}/original/$name ${FILES}
	      fi
	  done
	)
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

if yesno "Install Manual pages in ${DESTROOT}/usr/man?" ; then
    :
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
echo "End of install script"
