######################################################################
#
#  Utils.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Utils;
use strict;
use warnings;

use SSHCure::Utils::Nfdump;

use DBD::SQLite;
use LWP::Simple;
use Net::IP;
use POSIX qw(strftime);
use Sys::Syslog;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw (
    debug
    log_debug
    log_info
    log_error
    log_warning
    
    parse_nfdump_pipe
    parse_nfdump_list
    
    save_profiling_data
    save_profiling_value
    
    ip2dec
    dec2ip
    ip_addr_in_range
    ip2hostname
    get_ip_version

    SYN_only
    ACK_only
    RST_only
    ASF_only
    APS_only
    AF_only
    APS
    FIN
    RST
    SYN
    SYN_ACK
    no_ACK
    no_PSH
    no_SYN
    no_FIN_RST
    dec2flags
    
    database_maintenance
    backend_checks
    config_sanity_check

    fetch_openbl_blacklist_snapshot
    host_on_openbl_blacklist
);

####################
# Logging routines
####################

# All logging routines return the message they log, so multiple routines can be chained

sub debug {
    printf($SSHCure::debug_log_fh "%s [%7.10s] %s\n", strftime("%H:%M:%S", localtime()), $SSHCure::PHASE, $_[0]) if $CFG::DBG{'ENABLED'};
    return $_[0];
}

sub log_debug {
    syslog('info', "SSHCure: DEBUG - $_[0]");
    debug "SYSLOG (debug): $_[0]";
    return $_[0];
}

sub log_info {
    syslog('info', "SSHCure: $_[0]");
    debug "SYSLOG (info): $_[0]";
    return $_[0];
}

sub log_error {
    syslog('info', "SSHCure: ERROR - $_[0]");
    debug "SYSLOG (error): $_[0]";
    return $_[0];
}

sub log_warning {
    syslog('info', "SSHCure: WARNING - $_[0]");
    debug "SYSLOG (error): $_[0]";
    return $_[0];
}

##############################
#
# Parsers
#
##############################

sub parse_nfdump_pipe {
    my $nfdump_output = shift;
    my @nfdump_parsed_output = ();

    foreach my $line (@$nfdump_output) {
        chomp($line);
        next if $line eq "" || $line eq "No matched flows" || index($line, 'ERROR') != -1;
        my ($af, $first, $first_msec, $last, $last_msec, $protocol,
            $sa_0, $sa_1, $sa_2, $sa_3, $src_port,
            $da_0, $da_1, $da_2, $da_3, $dst_port,
            $src_as, $dst_as, $r_input, $r_output,
            $flags, $tos, $packets, $octets) = split(/\|/, $line);

        push(@nfdump_parsed_output, [
                (scalar $first) + (scalar $first_msec) / 1000,
                (scalar $last) + (scalar $last_msec) / 1000,
                $protocol,
                $sa_0, $sa_1, $sa_2, $sa_3, $src_port,
                $da_0, $da_1, $da_2, $da_3, $dst_port,
                $flags,
                $packets,
                $octets
            ]
        );
    }

    return \@nfdump_parsed_output;
}

sub parse_nfdump_list {
    my ($nfdump_output, $parsed_output) = @_;

    foreach my $line (@$nfdump_output) {
        chomp($line);
        next if $line eq "" || $line eq "No matched flows" || index($line, 'ERROR') != -1;

        my @values = split(/\|\s*/, $line);                                                 # split line into seperate values
        push(@$parsed_output, \@values);                                                    # add array of values to result-array    
    }
}

##############################
#
# Profiling routines
#
##############################

sub save_profiling_data {
    my $timestamp = shift;
    my $run_time = shift;
    my $flow_records = shift;
    my $run_skipped = 0;
    $run_skipped = shift if @_;
    
    my $target_count_query      = 'SELECT SUM(target_count) as sum_target_count FROM attack WHERE certainty > ? AND certainty <= ?';
    my $target_count_scan       = $SSHCure::DBH->selectrow_array($target_count_query, undef, (0, 0.25)) || 0;
    my $target_count_bruteforce = $SSHCure::DBH->selectrow_array($target_count_query, undef, (0.25, 0.50)) || 0;
    my $target_count_compromise = $SSHCure::DBH->selectrow_array($target_count_query, undef, (0.50, 1)) || 0;
    
    my ($db_file) = ($CFG::CONST{'DB'}{'DSN'} =~ /dbname=([^:]+)/);
    my $db_size = int ((-s $db_file) / (1024*1024));
    my $maintenance_failed = 0;
    while (glob("@{[$CFG::CONST{'SSHCURE_DATA_DIR'}]}/retry_maintenance_*")) { $maintenance_failed++ };
    
    my $profile_sql = "INSERT INTO profile (time, db_size, run_time, target_count_scan, target_count_bruteforce, target_count_compromise, maintenance_failed,
            run_skipped, flow_records)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    my $profile_DBH = DBI->connect($CFG::CONST{'DB'}{'DSN_PROFILING'}, "", "", {sqlite_use_immediate_transaction => 1}) or log_error("Could not connect to profiling database");
    my $sth_profile = $profile_DBH->prepare($profile_sql);
    $sth_profile->execute($timestamp, $db_size, $run_time, $target_count_scan, $target_count_bruteforce, $target_count_compromise,
            $maintenance_failed, $run_skipped, $flow_records);
    
    if ($sth_profile->err) {
        log_error("Could not insert data into profiling DB: ".$sth_profile->errstr);
    }
}

sub save_profiling_value {
    my $timestamp = shift;
    my $column = shift;
    my $value = shift;
    
    my $sql = "UPDATE profile SET $column = ? WHERE time = ?";
    my $profile_DBH = DBI->connect($CFG::CONST{'DB'}{'DSN_PROFILING'},"", "", {sqlite_use_immediate_transaction => 1}) or log_error("Could not connect to profiling database");
    my $sth = $profile_DBH->prepare($sql);
    $sth->execute($value, $timestamp);
    
    log_error("Could not insert data into profiling DB: ".$sth->errstr) if ($sth->err);
}

##############################
#
# Operations on flow data fields
#
##############################

sub ip2dec {
    my $address = shift;

    # Determine whether $address is a valid IPv4 address
    if (($address =~ tr/.//) == 3) {
        my $address_dec = $SSHCure::ip2dec_cache->get($address);
        unless ($address_dec) {
            $address_dec = unpack N => pack CCCC => split /\./ => $address;
            $SSHCure::ip2dec_cache->set($address, $address_dec);
        }

        return $address_dec;
    } else {
        # Return input value if not a valid IPv4 address, or IPv6 address
        return $address;
    }
}

sub dec2ip {
    my ($addr0, $addr1, $addr2, $addr3) = @_;
    my $ip_address;

    if (scalar (@_) == 1) { # IPv4
        # This condition exists for compatibility with code that calls dec2ip using a single parameter
        $addr3 = $addr0;
        $addr0 = 0;
        $addr1 = 0;
        $addr2 = 0;
    }

    if ($addr0 == 0 && $addr1 == 0 && $addr2 == 0) { # IPv4
        $ip_address = $SSHCure::dec2ip_cache->get($addr3);
        unless ($ip_address) {
            $ip_address = join '.' => map { ($addr3 >> 8*(3-$_)) % 256 } 0..3;
            $SSHCure::dec2ip_cache->set($addr3, $ip_address);
        }
    } else { # IPv6
        $ip_address = sprintf("%08x", $addr0).sprintf("%08x", $addr1).sprintf("%08x", $addr2).sprintf("%08x", $addr3);
        $ip_address =~ s/....\K(?=.)/:/sg; # Add colons after every 2 bytes
    }

    return $ip_address;
}

# Determines whether an IP address (first parameter) falls within the
# provided IP address prefix (second parameter).
sub ip_addr_in_range {
    log_debug("[ip_addr_in_range] Called");
    my ($address, $prefix) = @_;
    my $cache_elem = $SSHCure::prefix_cache->get($prefix);
    my ($first_address, $last_address);

    if ($cache_elem) {
        $first_address = @{$cache_elem}[0];
        $last_address = @{$cache_elem}[1];
    } else {
        my $prefix_obj = new Net::IP($prefix);
        $first_address = scalar $prefix_obj->intip();
        
        # intip() does not return properly in case a '/0' prefix is used
        unless (defined $first_address) {
            $first_address = 0;
        }
        
        $last_address = scalar $prefix_obj->last_int();
        $SSHCure::prefix_cache->set($prefix, [ scalar $first_address, scalar $last_address ]);
    }

    return ($address >= $first_address && $address <= $last_address);
}

# Returns the hostname for a provided IP address. If the hostname could
# not be determined, the original IP address is returned.
sub ip2hostname {
    my $address = shift;
    my $hostname;
    
    if (qx(which dig)) {
        $hostname = qx(dig +short -x $address);
        $hostname =~ s/^\s+|\.?\s*\n?$//g;
    } elsif (qx(which nslookup)) {
        my $nslookup = qx(nslookup $address | grep -i "name =") =~ /(.*)\tname = (.*)\.$/;
        my ($reverse, $hostname) = ($1, $2);
    } else {
        $hostname = $address;
    }
    
    # In case of an error, use the original IP address
    if ($hostname eq "" || $hostname eq ";; connection timed out; no servers could be reached") {
        $hostname = $address;
    }
    
    return $hostname;
}

# Return the version of the supplied IP address. In case of an invalid IP address, -1 is returned
sub get_ip_version {
    my $address = shift;
    my $version = -1;
    if (($address =~ tr/.//) == 3) {
        $version = 4;
    } elsif (($address =~ tr/://) > 1) {
        $version = 6;
    } else {
        # Do nothing (return -1)
    }

    return $version;
}

# Flags: UAPRSF
sub SYN_only {
    return $_[0] == 0x2;
}

sub ACK_only {
    return $_[0] == 0b010000;
}

sub RST_only {
    return $_[0] == 0b000100;
}

sub ASF_only {
    return $_[0] == 0b010011;
}

sub APS_only {
    return $_[0] == 0b011010;
}

sub AF_only {
    return $_[0] == 0b010001;
}

sub APS {
    return ($_[0] & 0b011010) == 0b011010;
}

sub FIN {
    return ($_[0] & 0x1) == 0x1;
}

sub RST {
    return ($_[0] & 0x4) == 0x4;
}

sub SYN {
    return ($_[0] & 0x2) == 0x2; 
}

sub SYN_ACK {
    return ($_[0] & 0x12) == 0x12;
}

sub no_ACK {
    return ($_[0] & 0b010000) == 0;
}

sub no_PSH {
    return ($_[0] & 0b001000) == 0;
}

sub no_SYN {
    return ($_[0] & 0b000010) == 0;
}

sub no_FIN_RST {
    return ($_[0] & 0b000101) == 0;
}

sub dec2flags {
    my ($dec) = @_;
    my $flags = 'UAPRSF';
    foreach (reverse(0..5)) {
        substr($flags, $_, 1) = '.' unless $dec & 1;
        $dec = $dec >> 1;
    }
    return $flags;
}

##############################
#
# Database maintenance
#
##############################

# Regular cleanup subroutine, called every sunday at 0:00 or as specified in config.pm.
sub database_maintenance {
    my $timestamp = (shift);
    
    my ($db_file) = ($CFG::CONST{'DB'}{'DSN'} =~ /dbname=([^:]+)/);
    my $db_size = int ((-s $db_file) / (1024*1024));
    
    log_info("Starting database maintenance (size: $db_size MB)...");
    
    my $start_time = time;
    my $scan_attack_time_min        = $timestamp - ($CFG::CONST{'DB'}{'MAX_SCAN_ATTACK_AGE'} * 3600 * 24);
    my $scan_target_time_min        = $timestamp - ($CFG::CONST{'DB'}{'MAX_SCAN_TARGET_AGE'} * 3600 * 24);
    my $bruteforce_attack_time_min  = $timestamp - ($CFG::CONST{'DB'}{'MAX_BRUTEFORCE_ATTACK_AGE'} * 3600 * 24);
    my $bruteforce_target_time_min  = $timestamp - ($CFG::CONST{'DB'}{'MAX_BRUTEFORCE_TARGET_AGE'} * 3600 * 24);
    my $compromise_attack_time_min  = $timestamp - ($CFG::CONST{'DB'}{'MAX_COMPROMISE_ATTACK_AGE'} * 3600 * 24);
    my $compromise_target_time_min  = $timestamp - ($CFG::CONST{'DB'}{'MAX_COMPROMISE_TARGET_AGE'} * 3600 * 24);
    
    my $remove_targets_query = "DELETE FROM target WHERE attack_id IN (SELECT id FROM attack WHERE start_time < ? AND certainty <= ?)";
    my $sth_targets = $SSHCure::DBH->prepare($remove_targets_query);
    
    my $remove_attacks_query = "DELETE FROM attack WHERE start_time < ? AND certainty <= ?";
    my $sth_attacks = $SSHCure::DBH->prepare($remove_attacks_query);
    
    my $aff_rows = $sth_targets->execute($scan_target_time_min, $CFG::ALGO{'CERT_SCAN'});
    log_info("Deleted $aff_rows scan targets");
    $aff_rows = $sth_targets->execute($bruteforce_target_time_min, $CFG::ALGO{'CERT_BRUTEFORCE'});
    log_info("Deleted $aff_rows brute-force targets");
    $aff_rows = $sth_targets->execute($compromise_target_time_min, $CFG::ALGO{'CERT_COMPROMISE'});
    log_info("Deleted $aff_rows compromise targets");
    
    $aff_rows = $sth_attacks->execute($scan_attack_time_min, $CFG::ALGO{'CERT_SCAN'});
    log_info("Deleted $aff_rows scan attacks");
    $aff_rows = $sth_attacks->execute($bruteforce_attack_time_min, $CFG::ALGO{'CERT_BRUTEFORCE'});
    log_info("Deleted $aff_rows brute-force attacks");
    $aff_rows = $sth_attacks->execute($compromise_attack_time_min, $CFG::ALGO{'CERT_COMPROMISE'});
    log_info("Deleted $aff_rows compromise attacks");
    
    if ($CFG::MAINTENANCE{'QUICK'}) {
        log_info("Skipping database cleaning (quick mode)");
        log_info("Skipping database reindexing (quick mode)");
    } else {
        log_info("Cleaning database...");
        $SSHCure::DBH->do("VACUUM");
        
        log_info("Reindexing database...");
        $SSHCure::DBH->do("REINDEX");
    }
    
    my $maintenance_time_needed = time - $start_time;
    $db_size = int ((-s $db_file) / (1024*1024));
    log_info("Database maintenance completed (new size: $db_size MB); time needed: ${maintenance_time_needed}s");
}

sub backend_checks {
    my @error_codes = ();
    
    my $profile = get_profile();
    my $datadir_prefix = "$NfConf::PROFILEDATADIR/$profile";

    my @datadirs = ();
    if ($CFG::OVERRIDE_SOURCE eq "") {
        push(@datadirs, "${datadir_prefix}/");
    } else {
        my @overrides = split(':', $CFG::OVERRIDE_SOURCE);
        foreach my $source_dir (@overrides) {
            push(@datadirs, "${datadir_prefix}/$source_dir");
        }
    }

    # Check datadir existence
    foreach my $datadir (@datadirs) {
        if (not -e $datadir) {
            push(@error_codes, $CFG::CONST{'ERROR'}{'DATADIR_NOT_FOUND'});
            log_error("NfSen data directory not found: $datadir");
        }
    }
    
    # Only check for datadir readability if datadir exists
    if (grep { $CFG::CONST{'ERROR'}{'DATADIR_NOT_FOUND'} eq $_ } @error_codes) {
        # Check datadir readability
        foreach my $datadir (@datadirs) {
            if (not -r $datadir) {
                push(@error_codes, $CFG::CONST{'ERROR'}{'DATADIR_NOT_READABLE'});
                log_error("NfSen directory not readable: $datadir");
            }
        }
    }
    
    # Check SSHCURE/data readability
    if (not -r $CFG::CONST{'SSHCURE_DATA_DIR'}) {
        push(@error_codes, $CFG::CONST{'ERROR'}{'SSHCUREDATA_NOT_READABLE'});
        log_error("SSHCure data directory not readable: $CFG::CONST{'SSHCURE_DATA_DIR'}");
    }
    
    # Check SSHCURE/data writability
    if (not -w $CFG::CONST{'SSHCURE_DATA_DIR'}) {
        push(@error_codes, $CFG::CONST{'ERROR'}{'SSHCUREDATA_NOT_WRITABLE'});
        log_error("SSHCure data directory not writable: $CFG::CONST{'SSHCURE_DATA_DIR'}");
    }
    
    # Check database readability
    my ($db_file) = ($CFG::CONST{'DB'}{'DSN'} =~ /dbname=([^:]+)/);
    if (not -r $db_file) {
        push(@error_codes, $CFG::CONST{'ERROR'}{'DATABASE_NOT_READABLE'});
        log_error("SSHCure database not readable: $db_file");
    }
    
    # Check database writability
    if (not -w $db_file) {
        push(@error_codes, $CFG::CONST{'ERROR'}{'DATABASE_NOT_WRITABLE'});
        log_error("SSHCure database not writable: $db_file");
    }
    
    # Check for existing failed_maintenance files
    if (scalar glob("@{[$CFG::CONST{'SSHCURE_DATA_DIR'}]}/failed_maintenance_*")) {
        push(@error_codes, $CFG::CONST{'ERROR'}{'MAINTENANCE_FAILED'});
    }
    
    # Check database not larger than DB_MAX_SIZE 
    if ( -s $db_file > ($CFG::CONST{'DB'}{'MAX_SIZE'} * 1024 * 1024)) {
        push(@error_codes, $CFG::CONST{'ERROR'}{'DATABASE_TOO_BIG'});
    }

    return \@error_codes;
}

# Checks the notification configuration in config.pm
sub config_sanity_check {
    # Notifications
    while (my ($notification_id, $config) = each(%CFG::NOTIFICATIONS)) {
        # Name
        unless ($notification_id ne '') {
            log_error("Found a notification configuration without a name");
            return 0;
        }
        
        # Filter
        unless ($$config{'filter'} ne '') {
            log_error("Notification configuration '".$notification_id."' has an empty filter");
            return 0;
        }
        
        # Filter type
        unless(grep { $_ eq $$config{'filter_type'} } (values %{$CFG::CONST{'NOTIFICATIONS'}{'FILTER_TYPE'}})) {
            log_error("Notification configuration '".$notification_id."' has no valid filter_type");
            return 0;
        }
        
        # Attack phase
        unless(grep { $_ eq $$config{'attack_phase'} } (values %{$CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}})) {
            log_error("Notification configuration '".$notification_id."' has no valid attack_phase");
            return 0;
        }
        
        # When
        unless(grep { $_ eq $$config{'when'} } (values %{$CFG::CONST{'NOTIFICATIONS'}{'WHEN'}})) {
            log_error("Notification configuration '".$notification_id."' has no valid trigger time (when)");
            return 0;
        }
        
        # Notification type
        unless(grep { $_ eq $$config{'notification_type'} } (values %{$CFG::CONST{'NOTIFICATIONS'}{'TYPE'}})) {
            log_error("Notification configuration '".$notification_id."' has no valid notification_type");
            return 0;
        }
        
        # Notification sender + destination (http://www.regular-expressions.info/email.html)
        if ($$config{'notification_type'} eq $CFG::CONST{'NOTIFICATIONS'}{'TYPE'}{'EMAIL'}) {
            # Sender
            unless ($$config{'notification_sender'} ne '' && $$config{'notification_sender'} =~ tr/@// == 1) {
                log_error("Notification configuration '".$notification_id."' should have exactly one e-mail address");
                return 0;
            }
            
            # Destination
            unless ($$config{'notification_destination'} ne '') {
                log_error("Notification configuration '".$notification_id."' should not be empty");
                return 0;
            }
            
            unless ($$config{'notification_destination'} =~ tr/@// == (($$config{'notification_destination'} =~ tr/<// + $$config{'notification_destination'} =~ tr/>//)) / 2) {
                log_error("Every notification_destination in notification configuration '".$notification_id."' should be enclosed with brackets (e.g., '<name1\@domain.com>,<name2\@domain.com>')");
                return 0;
            }
        } elsif ($$config{'notification_type'} eq $CFG::CONST{'NOTIFICATIONS'}{'TYPE'}{'LOG'}) {
            # Sender
            unless ($$config{'notification_sender'} eq '') {
                log_error("Notification configuration '".$notification_id."' should have an empty notification_sender");
                return 0;
            }
            
            # Destination
            unless ($$config{'notification_destination'} ne '') {
                log_error("Notification configuration '".$notification_id."' should not be empty");
                return 0;
            }
        }
    }

    # Override source
    unless (($CFG::OVERRIDE_SOURCE =~ tr/;//) == 0 && ($CFG::OVERRIDE_SOURCE =~ tr/,//) == 0) {
        log_error("Syntax error in OVERRIDE_SOURCE specification");
        return 0;
    }

    # Internal networks
    unless ($CFG::INTERNAL_NETWORKS eq "" || ($CFG::INTERNAL_NETWORKS =~ tr/\///) == ($CFG::INTERNAL_NETWORKS =~ tr/,//) + 1) {
        log_error("Syntax error in INTERNAL_NETWORKS specification");
        return 0;
    }
    
    return 1;
}

sub fetch_openbl_blacklist_snapshot {
    my $resp_code = mirror($CFG::CONST{'OPENBL'}{'SSH_BLACKLIST_URL'}, $CFG::CONST{'OPENBL'}{'SSH_BLACKLIST_LOCAL_PATH'});
    if ($resp_code == 200) {
        log_info("Successfully fetched OpenBL blacklist snapshot (".strftime("%H:%M", localtime(time)).")");
    } else {
        log_error("OpenBL blacklist snapshot could not be fetched; trying again in 24 hours...");
    }

    return $resp_code;
}

sub host_on_openbl_blacklist {
    my ($host) = @_;

    # If $host does not contain valid IPv4 or IPv6 address, it may be a decimal IPv4 address
    if (get_ip_version($host) == -1) {
        $host = dec2ip($host);
    }
    
    open(my $fh, '<:encoding(UTF-8)', $CFG::CONST{'OPENBL'}{'SSH_BLACKLIST_LOCAL_PATH'}) or log_error("Could not open OpenBL blacklist snapshot");
    while (my $row = <$fh>) {
        chomp($row);

        # Skip line if it starts with a comment
        next if (index($row, "#") == 0);

        return 1 if ($host eq $row);
    }

    return 0;
}

sub IO::Async::Loop::run_child_future {
    my $self = shift;
    my $f = $self->new_future;
    $self->run_child( @_,
        on_finish => sub {
        $f->done(($_[2], $_[3])) },
    );
    return $f;
}

1;
