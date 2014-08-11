SSHCure: A Flow-Based SSH Intrusion Detection System

Version:    3.0
Author:     Luuk Hendriks, University of Twente <luuk.hendriks@utwente.nl>
            Rick Hofstede, University of Twente <r.j.hofstede@utwente.nl>

--

The purpose of this readme is to provide a quick start guide for installation and 
configuration of SSHCure for NfSen. More details and in-depth motivations of concepts 
etc., can be found in the SSHCure manual.

1) Introduction

SSHCure is a flow-based SSH intrusion detection system and is available as a plugin 
for NfSen. For more details, the following resources are available:
    - [Website] http://sshcure.sf.net
    - [Mailing list] sshcure-discuss@lists.sourceforge.net

2) Installation instructions

SSHCure can be installed in a variety of ways (for notes on a version upgrade, 
check 2.5; for installation verification, check 2.6):

2.1) Requirements & dependencies

- Default system, having the following installed:
    * NfSen
    * PHP 5.2.4 or newer
    * PHP modules:
        - mbstring
        - PDO SQLite v3
    * PHP modules:
        - DBI SQLite (Debian/Ubuntu: libdbd-sqlite3-perl; RHEL/CentOS: perl-DBD-SQLite)
        - JSON (Debian/Ubuntu: libdbd-sqlite3-perl; RHEL/CentOS: perl-DBD-SQLite)
        - LWP::UserAgent (Debian/Ubuntu: libdbd-sqlite3-perl, libjson-perl, libwww-perl; RHEL/CentOS: perl-DBD-SQLite, perl-JSON, perl-libwww-perl)
        - Net::IP (Debian/Ubuntu: libnet-ip-perl; RHEL/CentOS: perl-Net-IP)

- INVEA-TECH's FlowMon Probe (version >= 5.0) (http://www.invea-tech.com/products-and-services/flowmon/flowmon-probes)
- INVEA-TECH's FlowMon Collector (version >= 5.0) (http://www.invea-tech.com/products-and-services/flowmon/flowmon-collectors)

2.2) Automated tar ball installation (latest stable, recommended)

- Download installation script:
    $ wget http://downloads.sourceforge.net/project/sshcure/install.sh
    $ chmod +x install.sh

- Install plugin:
    $ ./install.sh
    $ sudo /data/nfsen/bin/nfsen reload (this path might differ, depending on your setup)

2.3) Manual tar ball installation (latest stable)

- Download tar ball from SourceForge repository:
    $ wget http://downloads.sourceforge.net/project/sshcure/source/SSHCure_v2.2.tar.gz

- Download MaxMind GeoLite City database:
    $ wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
    
- Download MaxMind GeoLite City (IPv6) database:
    $ wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz

- Unpack installation package:
    $ tar zxf SSHCure_v2.2 --directory=.

- Install plugin files:
    $ cp -r SSHCure/frontend/* /var/www/nfsen/plugins/
        (path might differ, depending on your setup)
    $ cp -r SSHCure/backend/* /data/nfsen/plugins/
        (path might differ, depending on your setup)
    $ gunzip -c GeoLiteCity.dat.gz > /var/www/nfsen/plugins/SSHCure/lib/MaxMind/GeoLiteCity.dat
        (path might differ, depending on your setup)
    $ gunzip -c GeoLiteCityv6.dat.gz > /var/www/nfsen/plugins/SSHCure/lib/MaxMind/GeoLiteCityv6.dat
        (path might differ, depending on your setup)

- Configure plugin (config/config.php):
    $ vi /var/www/nfsen/plugins/SSHCure/config/config.php (this path might differ, depending on your setup)
        $config['nfsen.config-file'] = '/data/nfsen/etc/nfsen.conf';
            (path might differ, depending on your setup)

        $config['backend.path'] = '/data/nfsen/plugins/SSHCure/';
            (path might differ, depending on your setup)

- Enable plugin:
    $ vi /data/nfsen/etc/nfsen.conf (path might differ, depending on your setup)
        [ 'live', 'SSHCure' ],

- Check file and directory permissions:
    - The backend directory (e.g. /data/nfsen/plugins/SSHCure) should (recursively) be owned by the user configured as $USER and group $WWWGROUP in nfsen.conf
    - The frontend directory (e.g. /var/www/nfsen/plugins/SSHCure) should (recursively) be owned by the group $WWWGROUP in nfsen.conf

- Start plugin:
    $ sudo /data/nfsen/bin/nfsen reload

2.4) SVN trunk installation (latest development version)
    $ wget http://svn.code.sf.net/p/sshcure/code/trunk/install-svn-trunk.sh
    $ chmod +x install-svn-trunk.sh
    $ ./install-svn-trunk.sh

2.5) Upgrading existing installation

When upgrading your SSHCure installation to a newer version, keep in mind that the 
configuration file (config/config.php) is not always compatible between the 
versions. It's therefore very important to update the settings in the configuration 
file of the version you're upgrading to. Regarding the upgrade, you could use either 
of the installation methods discussed above. In case you're using a method that's based 
on an installation script (i.e. 'automated tar ball installation' (2.2) or 'SVN trunk 
installation' (2.4)) the scripts will automatically archive your existing SSHCure 
installation, including the configuration file. If you're doing a manual 
installation/upgrade, keep in mind to archive your old installation yourself.

Besides backing up the configuration file, you can save the contents of the data folder
of SSHCure's backend (e.g. /data/nfsen/plugins/SSHCure/data/*), in order to save the
previous detections after upgrading.

2.6) Installation verification

In case you installed SSHCure using an installation script, the script will have told
you whether all the required Perl modules are present on your system. When you start/reload
NfSen after the installation of SSHCure, the following line will be logged to syslog if
the backend is working fine:

SSHCure: Init done

To find out whether the frontend is working properly, you can load the frontend by
loading NfSen, navigating to the 'Plugins' tab and clicking 'SSHCure'. If you see some
(potentially) empty tables, communication with the database is working fine. However,
if you still see the processing messages after waiting for a couple of seconds, your
system is missing the PHP PDO SQLite module.

3) Using SSHCure

When it's the first time you run SSHCure after installation/upgrade, please restart 
your Web browser and clear its cache (cookies, recent history, cache files, …).
After that, you can open NfSen, navigate to the 'Plugins' tab and choose 'SSHCure'. 
You should never call SSHCure directly by its URL, since it will not be able to 
communicate properly with NfSen.

4) Support

For any questions or general technical support issues, please feel free to send an 
e-mail to <r.j.hofstede@utwente.nl> or to join the SSHCure mailing list:
sshcure-discuss@lists.sourceforge.net
