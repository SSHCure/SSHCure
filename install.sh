#!/bin/sh

#########################################################
#
# Installation script for SSHCure.
#
# Author(s):    Rick Hofstede   <r.j.hofstede@utwente.nl>
#               Luuk Hendriks   <luuk.hendriks@utwente.nl>
#
# LICENSE TERMS - 3-clause BSD license
#
# $Id: install.sh 963 2014-07-02 09:13:49Z rickhofstede $
#
#########################################################

GEO_DB=GeoLiteCity.dat.gz
GEOv6_DB=GeoLiteCityv6.dat.gz

err () {
    printf "ERROR: ${*}\n"
    exit 1
}

FRONTEND_ONLY=0             # Install/update frontend only
BACKEND_ONLY=0              # Install/update backend only
NFSEN_CONF_OVERWRITE=""     # Overwrite path to nfsen.conf (i.e., don't determine path automatically)

# http://wiki.bash-hackers.org/howto/getopts_tutorial
while getopts ":fbn:" opt; do
    case $opt in
        f)
            FRONTEND_ONLY=1
            ;;
        b)
            BACKEND_ONLY=1
            ;;
        n)
            NFSEN_CONF_OVERWRITE=$OPTARG
            ;;
        \?)
            err "Invalid option: -$OPTARG"
            exit 1
            ;;
        :)
            err "Option -$OPTARG requires an argument. Exiting..."
            exit 1
            ;;
    esac
done

if [ $FRONTEND_ONLY = 1 -a $BACKEND_ONLY = 1 ]; then
    err "You have specified two excluding options (-f and -b)."
fi

# Determine (based on combination of input parameters) whether frontend has to be installed
if [ $FRONTEND_ONLY = 1 ] || [ $FRONTEND_ONLY = 0 -a $BACKEND_ONLY = 0 ]; then
    INSTALL_FRONTEND=1
else
    INSTALL_FRONTEND=0
fi

# Determine (based on combination of input parameters) whether backend has to be installed
if [ $BACKEND_ONLY = 1 ] || [ $FRONTEND_ONLY = 0 -a $BACKEND_ONLY = 0 ]; then
    INSTALL_BACKEND=1
else
    INSTALL_BACKEND=0
fi

echo "SSHCure installation script"
echo "---------------------------"

# Check for availability of (frontend/backend) source files
if [ ! -d "frontend" -o ! -d "backend" -o ! -f "dependency_check.pm" ]; then
    err "Could not find the required installation files. Please clone the repository at https://github.com/SSHCure/SSHCure.git, and rerun this installer."
fi

# Check PHP dependencies
PHP_JSON=$(php -m | grep 'json' 2> /dev/null)
PHP_MBSTRING=$(php -m 2> /dev/null | grep 'mbstring')
PHP_PDOSQLITE=$(php -m 2> /dev/null | grep 'pdo_sqlite$') # The dollar-sign ($) makes sure that 'pdo_sqlite2' is not accepted
PHP_SOCKETS=$(php -m 2> /dev/null | grep '^sockets$')
PHP_XML=$(php -m 2> /dev/null | grep '^xml$')

if [ "$PHP_JSON" != "json" ]; then
    err "The PHP 'JSON' module is missing.\nDon't forget to restart your Web server after installing the package."
elif [ "$PHP_MBSTRING" != "mbstring" ]; then
    err "The PHP 'mbstring' module is missing.\nDon't forget to restart your Web server after installing the package."
elif [ "$PHP_PDOSQLITE" != "pdo_sqlite" ]; then
    err "The PHP PDO SQLite v3 module is missing.\nDon't forget to restart your Web server after installing the package."
elif [ "$PHP_SOCKETS" != "sockets" ]; then
    err "The PHP 'sockets' module is missing.\nDon't forget to restart your Web server after installing the package."
elif [ "$PHP_XML" != "xml" ]; then
    err "The PHP 'xml' module is missing.\nDon't forget to restart your Web server after installing the package."
fi

# Discover NfSen configuration
NFSEN_VARFILE=/tmp/nfsen-tmp.conf
if [ ! -n "$(ps axo command | grep [n]fsend | grep -v nfsend-comm)" ]; then
    err "NfSen - nfsend not running; cannot detect nfsen.conf location. Exiting..."
fi

NFSEN_LIBEXECDIR=$(cat $(ps axo command= | grep -vE "(nfsend-comm|grep)" | grep -Eo "[^ ]+nfsend") | grep libexec | cut -d'"' -f2 | head -n 1)

if [ -z "${NFSEN_CONF_OVERWRITE}" ]; then
    NFSEN_CONF=$(cat ${NFSEN_LIBEXECDIR}/NfConf.pm | grep \/nfsen.conf | cut -d'"' -f2)
else
    NFSEN_CONF=$NFSEN_CONF_OVERWRITE
fi

# Parse nfsen.conf file
cat ${NFSEN_CONF} | grep -v \# | egrep '\$BASEDIR|\$BINDIR|\$LIBEXECDIR|\$HTMLDIR|\$FRONTEND_PLUGINDIR|\$BACKEND_PLUGINDIR|\$WWWGROUP|\$WWWUSER|\$USER' | tr -d ';' | tr -d ' ' | cut -c2- | sed 's,/",",g' > ${NFSEN_VARFILE}
. ${NFSEN_VARFILE}
rm -rf ${NFSEN_VARFILE}

SSHCURE_CONF=${FRONTEND_PLUGINDIR}/SSHCure/config.php

# Check Perl dependencies
printf "Checking Perl dependencies...\n\n"
./dependency_check.pm 2> /dev/null
PERL_DEP_CHECK_RETURN_CODE=$?
echo ""

if [ $PERL_DEP_CHECK_RETURN_CODE = 0 ]; then
    echo "All Perl dependencies are available on the system. Continuing installation..."
else
    err "Some Perl dependencies are missing or outdated. Aborting installation..."
fi

# Check permissions to install SSHCure - you must be ${USER} or root
if [ "$(id -u)" != "$(id -u ${USER})" ] && [ "$(id -u)" != "0" ]; then
    err "You do not have sufficient permissions to install SSHCure on this machine!"
fi

if [ "$(id -u)" = "$(id -u ${USER})" ]; then
    WWWUSER=${USER}     # we are installing as normal user
fi

# Download files from Web
if [ $(uname) = "FreeBSD" -o $(uname) = "OpenBSD" ]; then
    RETRIEVE_TOOL="fetch"
else
    RETRIEVE_TOOL="wget"
fi

if [ ! -f ${GEO_DB} ]; then
    echo "Downloading MaxMind GeoLite City database - http://geolite.maxmind.com"
    ${RETRIEVE_TOOL} -q http://geolite.maxmind.com/download/geoip/database/${GEO_DB}
    if [ $? != 0 ]; then
        err_line "The MaxMind GeoLite City database has not been downloaded successfully. You may have been graylisted by MaxMind because of subsequent download retries. Please try again later."
    fi
fi

if [ ! -f ${GEOv6_DB} ]; then
    echo "Downloading MaxMind GeoLite City (IPv6) database - http://geolite.maxmind.com"
    ${RETRIEVE_TOOL} -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/${GEOv6_DB}
    if [ $? != 0 ]; then
        err_line "The MaxMind GeoLite City (IPv6) database has not been downloaded successfully. You may have been graylisted by MaxMind because of subsequent download retries. Please try again later."
    fi
fi

# Backup old SSHCure installation
SSHCURE_BACKUPDIR_FRONTEND=${FRONTEND_PLUGINDIR}/SSHCure-$(date +%s)
SSHCURE_BACKUPDIR_BACKEND=${BACKEND_PLUGINDIR}/SSHCure-$(date +%s)
if [ $INSTALL_FRONTEND = 1 -a -d ${FRONTEND_PLUGINDIR}/SSHCure ]; then
    echo "Backing up existing SSHCure (frontend) installation to ${SSHCURE_BACKUPDIR_FRONTEND}"
    mv ${FRONTEND_PLUGINDIR}/SSHCure ${SSHCURE_BACKUPDIR_FRONTEND}
fi
if [ $INSTALL_BACKEND = 1 -a -d ${BACKEND_PLUGINDIR}/SSHCure ]; then
    echo "Backing up existing SSHCure (backend) installation to ${SSHCURE_BACKUPDIR_BACKEND}"
    mv ${BACKEND_PLUGINDIR}/SSHCure ${SSHCURE_BACKUPDIR_BACKEND}
fi

# Install backend and frontend plugin files
echo "Installing SSHCure ${VERSION} to ${FRONTEND_PLUGINDIR}/SSHCure"
if [ $INSTALL_FRONTEND = 1 ]; then
    cp -r ./frontend/* ${FRONTEND_PLUGINDIR}
fi
if [ $INSTALL_BACKEND = 1 ]; then
    cp -r ./backend/* ${BACKEND_PLUGINDIR}
fi

# Unpack geoLocation databases
MAXMIND_PATH=${FRONTEND_PLUGINDIR}/SSHCure/lib/MaxMind
echo "Installing MaxMind GeoLite City database to ${MAXMIND_PATH}"
gunzip -c ${GEO_DB} > ${MAXMIND_PATH}/$(basename ${GEO_DB} .gz)
if [ $? != 0 ]; then
    err "The MaxMind GeoLite City database has not been downloaded successfully. You may have been graylisted by MaxMind because of subsequent download retries. Please try again later."
fi

echo "Installing MaxMind GeoLite City (IPv6) database to ${MAXMIND_PATH}"
gunzip -c ${GEOv6_DB} > ${MAXMIND_PATH}/$(basename ${GEOv6_DB} .gz)
if [ $? != 0 ]; then
    err "The MaxMind GeoLite City (IPv6) database has not been downloaded successfully. You may have been graylisted by MaxMind because of subsequent download retries. Please try again later."
fi

# Check whether an old SSHCure version was found and ask whether backend configuration and data structures should be retained
if [ $INSTALL_BACKEND = 1 -a -d ${SSHCURE_BACKUPDIR_BACKEND} ]; then
    OLD_VER=$(cat ${SSHCURE_BACKUPDIR_BACKEND}/../SSHCure.pm | grep -m 1 SSHCURE_VERSION | cut -d"\"" -f2)
    NEW_VER=$(cat ${BACKEND_PLUGINDIR}/SSHCure.pm | grep -m 1 SSHCURE_VERSION | cut -d"\"" -f2)
    if [ ${OLD_VER} = ${NEW_VER} ]; then
        while true; do
            read -p "Do you wish to keep the backend configuration and data structures from your previous installation [y,n] (default: y)? " input
            case $input in
                [Nn]* ) break;;
                * )     echo "Copying backend configuration and data structures from previous installation..."
                        cp ${SSHCURE_BACKUPDIR_BACKEND}/config.pm ${BACKEND_PLUGINDIR}/SSHCure/;
                        cp ${SSHCURE_BACKUPDIR_BACKEND}/data/* ${BACKEND_PLUGINDIR}/SSHCure/data/;
                        break;;
            esac
        done
    fi
fi

# Set permissions - owner and group
echo "Setting plugin file permissions - user \"${USER}\" and group \"${WWWGROUP}\""
if [ $INSTALL_FRONTEND = 1 ]; then
    chown -R ${USER}:${WWWGROUP} ${FRONTEND_PLUGINDIR}/SSHCure*
fi
if [ $INSTALL_BACKEND = 1 ]; then
    chown -R ${USER}:${WWWGROUP} ${BACKEND_PLUGINDIR}/SSHCure*
fi

# Update plugin configuration file - config.php. We use ',' as sed delimiter instead of escaping all '/' to '\/'.
if [ $INSTALL_FRONTEND = 1 ]; then
    echo "Updating plugin configuration file ${SSHCURE_CONF}"
    
    # Since "$config['backend.path']" is also used in "$config['database.dsn']", we have to search (grep) for "'backend.path'] ="
    LINE=$(grep "'backend.path'] =" ${SSHCURE_CONF} | awk '{ START=index($0,"="); LENGTH=length($0)-START; print substr($0,START,LENGTH) }' | cut -d"'" -f2)
    sed -i.tmp "s,$LINE,${BACKEND_PLUGINDIR}/SSHCure/,g" ${SSHCURE_CONF}
fi

# Enable plugin
OLDENTRY=$(grep \@plugins ${NFSEN_CONF})

if grep "SSHCure" ${NFSEN_CONF} > /dev/null; then
    echo "Found 'SSHCure' in ${NFSEN_CONF}; assuming it is already configured"
else
    echo "Updating NfSen configuration file ${NFSEN_CONF}"
    
    # Check whether we are running Linux of BSD (BSD sed does not support inserting new lines (\n))
    if [ $(uname) = "Linux" ]; then
        sed -i.tmp "/SSHCure/d" ${NFSEN_CONF}
        sed -i.tmp "s/${OLDENTRY}/${OLDENTRY}\n    \[ 'live', 'SSHCure' ],/g" ${NFSEN_CONF}
    else # Something else (we assume *BSD)
        sed -i.tmp "s/${OLDENTRY}/${OLDENTRY}\ \[ 'live', 'SSHCure' ],/g" ${NFSEN_CONF}
    fi
fi

# Check whether an old SSHCure version was found and ask whether the backup of that version should be removed
if [ -d ${SSHCURE_BACKUPDIR_FRONTEND} -o -d ${SSHCURE_BACKUPDIR_BACKEND} ]; then
    while true; do
        read -p "Do you wish to remove the backup of your previous SSHCure installation [y,n] (default: n)? " input
        case $input in
            [Yy]* ) echo "Removing backup of previous installation..."
                    rm -rf ${SSHCURE_BACKUPDIR_FRONTEND} ${SSHCURE_BACKUPDIR_BACKEND}; 
                    break;;
            * )     break;;
        esac
    done
fi

echo "-----"
echo "Please restart/reload NfSen to finish installation (e.g., sudo ${BINDIR}/nfsen reload)"
