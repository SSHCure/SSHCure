#!/bin/sh
#
# Script for installing SSHCure from Git.
#
# Author(s):    Rick Hofstede   <r.j.hofstede@utwente.nl>
#               Luuk Hendriks   <luuk.hendriks@utwente.nl>
#
# LICENSE TERMS - 3-clause BSD license
#
# $Id: install-svn-trunk.sh 742 2014-01-26 13:00:16Z rickhofstede $
#

err () {
    printf "ERROR: ${*}\n"
    exit 1
}

# Download files from Web
if [ $(uname) = "FreeBSD" -o $(uname) = "OpenBSD" ]; then
    RETRIEVE_TOOL="fetch"
else
    RETRIEVE_TOOL="wget"
fi

echo "SSHCure (GitHub) installation script"
echo "-------------------------------"

if [ ! "$(which git)" ]; then
    err "Git is not installed on your system. Install it first, or download the latest stable version of SSHCure from http://github.com/sshcure/sshcure"
fi

#echo "Removing previous Git clone"
#rm -rf SSHCure SSHCure_v*.tar.gz install.sh
# TODO should this remove the previous SSHCure-master dir?

echo "Downloading master.zip from GitHub"
$RETRIEVE_TOOL -q https://github.com/SSHCure/SSHCure/archive/master.zip

# Zip file contains subdir "SSHCure-master"
MASTER_ZIP_FILE=master.zip
MASTER_DIR=SSHCure-master
echo "Unpacking $MASTER_ZIP_FILE"
unzip -q $MASTER_ZIP_FILE

if [ ! -f $MASTER_DIR/install.sh ]; then
    err "An error occurred while fetching SSHCure from GitHub!"
fi

echo "Updating installation script for Git install"
cp $MASTER_DIR/install.sh .

#SSHCURE_VER=$(cat $MASTER_DIR/frontend/SSHCure/config/defaults.php | grep -m1 site.version | awk '{ START=index($0,"="); LENGTH=length($0)-START; print substr($0,START,LENGTH) }' | cut -d"'" -f2)
SSHCURE_VER=3.0 #FIXME
sed -i.tmp "s/SSHCURE_VER=.*/SSHCURE_VER=${SSHCURE_VER}/g" install.sh

echo "Creating tar ball"
mv $MASTER_DIR SSHCure # FIXME hack
tar -czf SSHCure_v${SSHCURE_VER}.tar.gz SSHCure

echo "Launching installation script ..."
./install.sh
