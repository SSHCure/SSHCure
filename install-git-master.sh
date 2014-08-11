#!/bin/sh
#
# Script for installing SSHCure from Git.
#
# Author(s):    Rick Hofstede   <r.j.hofstede@utwente.nl>
#
# LICENSE TERMS - 3-clause BSD license
#
# $Id: install-svn-trunk.sh 742 2014-01-26 13:00:16Z rickhofstede $
#

err () {
    printf "ERROR: ${*}\n"
    exit 1
}

echo "SSHCure (GitHub) installation script"
echo "-------------------------------"

if [ ! "$(which git)" ]; then
    err "Git is not installed on your system. Install it first, or download the latest stable version of SSHCure from http://github.com/sshcure/sshcure"
fi

echo "Removing previous Git clone"
rm -rf SSHCure SSHCure_v*.tar.gz install.sh

echo "Cloning Git master"
git clone https://github.com/SSHCure/SSHCure/archive/master.zip SSHCure

if [ ! -f SSHCure/install.sh ]; then
    err "An error occurred while cloning SSHCure from GitHub!"
fi

echo "Updating installation script for Git install"
cp SSHCure/install.sh .

SSHCURE_VER=$(cat SSHCure/frontend/SSHCure/config/defaults.php | grep -m1 site.version | awk '{ START=index($0,"="); LENGTH=length($0)-START; print substr($0,START,LENGTH) }' | cut -d"'" -f2)
sed -i.tmp "s/SSHCURE_VER=.*/SSHCURE_VER=${SSHCURE_VER}/g" install.sh

echo "Creating tar ball"
tar -czf SSHCure_v${SSHCURE_VER}.tar.gz SSHCure

echo "Launching installation script ..."
./install.sh
