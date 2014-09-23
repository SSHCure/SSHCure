######################################################################
#
#  RPC.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::RPC;

use warnings;
use strict;

use SSHCure::Utils;
use SSHCure::Utils::Nfdump;

use Exporter;
our @ISA = 'Exporter';

our @EXPORT = qw (
    get_active_notification_configs
    get_backend_errors
    get_backend_init_time
    get_backend_profile
    get_backend_sources
    get_backend_version
    get_db_max_size
    get_host_on_openbl_blacklist
    get_internal_domains
    get_nfdump_version
    get_nfsen_profiledatadir
    get_override_source
    get_run_lock_mtime
);

sub get_active_notification_configs {
    my ($socket, $opts) = @_;
    my @configs;
    
    while (my ($notification_id, $config) = each(%CFG::NOTIFICATIONS)) {
        push(@configs, $notification_id);
    }
    
    my %args;
    
    if (scalar (@configs) == 0) {
        $args{'active_notification_configs'} = "";
    } else {
        # Sort alphabetically (using lowercase)
        @configs = sort { lc($a) cmp lc($b) } @configs;
        
        $args{'active_notification_configs'} = join(", ", @configs);
    }
    
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_backend_errors {
    my ($socket, $opts) = @_;
    my %args = (
        'error_codes' => backend_checks()
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_backend_init_time {
    my ($socket, $opts) = @_;
    my %args;
    $args{'backend_init_time'} = $SSHCure::init_time;
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_backend_profile {
    my ($socket, $opts) = @_;
    my %args = (
        'backend_profile' => get_profile()
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_backend_sources {
    my ($socket, $opts) = @_;
    my %args;

    if ($CFG::OVERRIDE_SOURCE eq '') {
        my @sources;
        my $profile = get_profile();
        my $profile_dir = "$NfConf::PROFILEDATADIR/$profile/";
        
        opendir(my $dh, $profile_dir) || die;
        while(defined(my $entry = readdir($dh))) {
            if ($entry ne '.' && $entry ne '..' && -d "$NfConf::PROFILEDATADIR/$profile/$entry") {
                push(@sources, $entry);
            }
        }
        closedir($dh);

        @sources = sort(@sources);
        $args{'backend_sources'} = join(':', @sources);
    } else {
        $args{'backend_sources'} = $CFG::OVERRIDE_SOURCE;
    }

    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_backend_version {
    my ($socket, $opts) = @_;
    my %args = (
        'backend_version' => $SSHCure::SSHCURE_VERSION
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_db_max_size {
    my ($socket, $opts) = @_;
    my %args = (
        'db_max_size' => $CFG::CONST{'DB'}{'MAX_SIZE'}
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_host_on_openbl_blacklist {
    my ($socket, $opts) = @_;

    unless (exists $$opts{'host'} ) {
        Nfcomm::socket_send_error($socket, "Missing parameter");
        return;
    }

    my %args = (
        'host'              => $CFG::CONST{'DB'}{'MAX_SIZE'},
        'host_on_blacklist' => host_on_openbl_blacklist($$opts{'host'})
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_internal_domains {
    my ($socket, $opts) = @_;
    my %args = (
        'internal_domains' => $CFG::INTERNAL_DOMAINS
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_nfdump_version {
    my ($socket, $opts) = @_;
    my %args = (
        'nfdump_version' => $SSHCure::nfdump_version
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_nfsen_profiledatadir {
    my ($socket, $opts) = @_;
    my %args = (
        'nfsen_profiledatadir' => $NfConf::PROFILEDATADIR
    );
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_override_source {
    my ($socket, $opts) = @_;
    my %args = (
        'sources' => $CFG::OVERRIDE_SOURCE
    );
    $args{'sources'} = $CFG::OVERRIDE_SOURCE;
    Nfcomm::socket_send_ok($socket, \%args);
}

sub get_run_lock_mtime {
    my ($socket, $opts) = @_;
    my %args;

    my $mtime = (stat($CFG::CONST{'FN_RUN_LOCK'}))[9];
    if (defined $mtime) {
        $args{'timestamp'} = scalar $mtime;
    } else {
        $args{'timestamp'} = 0;
    }

    Nfcomm::socket_send_ok($socket, \%args);
}

1;
