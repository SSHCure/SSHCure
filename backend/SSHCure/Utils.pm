######################################################################
#
#  Utils.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Utils;
use strict;
use warnings;

use DBD::SQLite;
use Net::IP;
use POSIX qw(strftime mktime);
use Sys::Syslog;
use Time::Local;

use IO::Async::Loop;
use IO::Async::Process;
use IO::Async::Function;
use IO::Async::Future;
use Future::Utils qw(fmap_concat);

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
    
    get_profile
    nfdumptime2unix
    nfcapd2date
    nfcapd2unix
    unix2nfcapd
    previous_nfcapd
    get_info_from_nfcapd
    get_corrected_interval_for_timeslot
    nfcapd_is_empty
    ip2or_nfdump_filter
    retrieve_nfdump_version
    nfdump_version_check
    get_sorting_flag
    
    compare_string_version_number
    
    database_maintenance
    backend_checks
    perform_config_sanity_check
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
    # FIXME make this ipv6 compatible
    my $nfdump_output = shift;
    my @nfdump_parsed_output = ();

    foreach my $line (@$nfdump_output) {
        chomp($line);
        my ($af, $first, $first_msec, $last, $last_msec, $prot,
            $sa_0, $sa_1, $sa_2, $sa_3, $src_port,
            $da_0, $da_1, $da_2, $da_3, $dst_port,
            $src_as, $dst_as, $r_input, $r_output,
            $flags, $tos, $no_pkts, $no_octets) = split(/\|/, $line);
        
        push(@nfdump_parsed_output, [
                (scalar $first) + (scalar $first_msec) / 1000,
                (scalar $last) + (scalar $last_msec) / 1000,
                $prot,
                $sa_3, $src_port,
                $da_3, $dst_port,
                $flags,
                $no_pkts,
                $no_octets
            ]
        );
    }

    return \@nfdump_parsed_output;
}

sub parse_nfdump_list {
    my ($nfdump_output, $parsed_output) = @_;

    foreach my $line (@$nfdump_output) {
        $line =~ s/^\s+|\s+$//g;                                                            # trim whitespace
        next if $line eq "" || $line eq "No matched flows" || index($line, 'ERROR') != -1;  # skip
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
    
    if ($sth->err) {
        log_error("Could not insert data into profiling DB: ".$sth->errstr);
    }
}

##############################
#
# Operations on flow data fields
#
##############################

sub ip2dec ($) {
    my $ip = shift;
    return $ip if $ip =~/:/;
    return unpack N => pack CCCC => split /\./ => $ip;
}

# http://netfactory.dk/2007/10/02/ip-address-conversion-with-perl/
sub dec2ip ($) {
    my $dec = shift;
    return $dec if $dec =~ /:/;
    return join '.' => map { ($dec >> 8*(3-$_)) % 256 } 0 .. 3;
}

# Determines whether an IP address (first parameter) falls within the
# provided IP prefix (second parameter).
my %prefix_cache = ();

sub ip_addr_in_range {
    my $address = shift;
    my $prefix = shift;
    
    unless (exists $prefix_cache{$prefix}) {
        my $prefix_obj = new Net::IP($prefix);
        my $first_address = scalar $prefix_obj->intip();
        
        # intip() does not return properly in case a '/0' prefix is used
        unless (defined $first_address) {
            $first_address = 0;
        }
        
        my $last_address = scalar $prefix_obj->last_int();
        $prefix_cache{$prefix} = [scalar $first_address, scalar $last_address];
    }

    return ($address >= $prefix_cache{$prefix}[0] && $address <= $prefix_cache{$prefix}[1]);
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

#####################
# Time routines
#####################

# nfdump syntax -t:
# timewin is YYYY/MM/dd.hh:mm:ss[-YYYY/MM/dd.hh:mm:ss]

sub nfdumptime2unix {
    my $raw = shift;
    my ($year, $mon, $day, $hour, $min, $sec, $msec) = ($raw =~ /(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})/);
    return timelocal($sec,$min,$hour,$day,$mon-1,$year) + $msec/1000;
}

sub nfcapd2date {
    my $nfcapd_timestamp = shift; # format: yyyymmddhhmm
    my @date = ($nfcapd_timestamp =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/g);
    return @date;
}

sub nfcapd2unix {
    my $nfcapd_timestamp = shift; # format: yyyymmddhhmm
    my ($y, $m, $d, $h, $min) = ($nfcapd_timestamp =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/g);
    return timelocal(0,$min,$h,$d,$m-1,$y);
}

sub unix2nfcapd {
    my $unix_timestamp = shift;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($unix_timestamp);
    $year += 1900;
    $mon += 1;
    return sprintf("%d%02d%02d%02d%02d", $year, $mon, $mday, $hour, $min);
}

sub previous_nfcapd {
    my $nfcapd_timestamp = shift;
    my $unix_timestamp = nfcapd2unix($nfcapd_timestamp);
    $unix_timestamp -= 5*60; # - 300sec == - 5min
    return unix2nfcapd($unix_timestamp);
}

##############################
#
# nfdump-related
#
##############################

sub get_profile {    
    my $profile = (grep(@{$_}[1] eq 'SSHCure' , @NfConf::plugins))[0]->[0];
    
    if ($profile eq '*' || $profile eq '!') {
        $profile = 'live';
    }
    
    return $profile;
}

# Returns the sum of all nfcapd file header fields, belonging to the specified timeslot,
# of all specified sources. The list of sources should be provided as a colon-separated
# list of sources (String). The following exceptions apply:
#   - 'Ident' is not returned at all, because it is a String field
#   - 'First' and 'msec_first' are returned based on the source with the lowest respective values
#   - 'Last' and 'msec_last' are returned based on the source with the highest respective values
sub get_info_from_nfcapd {
    my ($sources_path, $sources, $timeslot) = @_;
    my %result = ();

    (fmap_concat {
        my $source = shift;
        my $cmd = "$NfConf::PREFIX/nfdump -M ${sources_path}${source} -r nfcapd.$timeslot -I";
        my @cmd = split(" ", $cmd);

        $SSHCure::loop->run_child_future(
            command => \@cmd,
        )->then( sub {
            my @nfdump_output = split("\n", $_[0]);
            my %result_per_source = ();

            foreach my $line (@nfdump_output) {
                $line =~ s/^\s+|\s+\n?$//g;
                my ($key, $value) = ($line =~ /(.*)\:\s+(.*)/);
                
                if (defined($key) && defined($value)) {
                    $result_per_source{$key} = $value;
                }
            }

            Future->wrap(\%result_per_source);
        });  
    } concurrent => $SSHCure::async_workers, foreach => [ split(':', $sources) ])->then( sub {
        my @results_per_source = @_;

        my $earliest = -1; my $latest = -1;
        my $earliest_msec = -1; my $latest_msec = -1;
        my $store_msec_first = 0; my $store_msec_last = 0;

        foreach my $result (@results_per_source) {
            foreach my $key (keys %$result) {
                my $value = $$result{$key};
                next if $key eq 'Ident';

                if ($key eq 'First') {
                    if ($earliest == -1 || $value lt $earliest) {
                        $earliest = $value;
                        $store_msec_first = 1;
                    }
                } elsif ($key eq 'Last') {
                    if ($latest == -1 || $value gt $latest) {
                        $latest = $value;
                        $store_msec_last = 1;
                    }
                } elsif ($key eq 'msec_first' && ($earliest_msec == -1 || $store_msec_first)) {
                    $earliest_msec = $value;
                } elsif ($key eq 'msec_last' && ($latest_msec == -1 || $store_msec_last)) {
                    $latest_msec = $value;
                } elsif (exists($result{$key})) {
                    $result{$key} += $value;
                } else {
                    $result{$key} = $value;
                }
            }

            # Reset values for next iteration
            my $store_msec_first = 0; my $store_msec_last = 0;
        }

        $result{'First'} = $earliest;
        $result{'Last'} = $latest;
        $result{'msec_first'} = $earliest_msec;
        $result{'msec_last'} = $latest_msec;
        Future->wrap();
    })->get();
    
    return %result;
}

sub get_corrected_interval_for_timeslot {
    my ($sources, $sources_path, $timeslot) = @_;
    my $nfcapd_stamp = nfcapd2unix($timeslot);

    my %nfcapd_info = get_info_from_nfcapd($sources_path, $sources, $timeslot);
    
    my $first_act = $nfcapd_info{'First'}.'.'.$nfcapd_info{'msec_first'};
    my $last_act = $nfcapd_info{'Last'}.'.'.$nfcapd_info{'msec_last'};

    my $DELTA_MAX = 30 * 60;
    if ($first_act - $last_act > $DELTA_MAX) {
        my ($s, $min, $h, $d, $m, $y) = localtime($nfcapd_stamp - 10*60);
        my $nfdump_time_filter = sprintf("%d/%02d/%02d.%02d:%02d:%02d", $y+1900, $m+1, $d, $h, $min, $s);
        ($s, $min, $h, $d, $m, $y) = localtime($nfcapd_stamp + 10*60);
        $nfdump_time_filter .= "-".sprintf("%d/%02d/%02d.%02d:%02d:%02d", $y+1900, $m+1, $d, $h, $min, $s);

        log_info sprintf "Time window correction: turned %i - %i into %i - %i",
                $first_act, $last_act, ($nfcapd_stamp - 10*60), ($nfcapd_stamp + 10*60);
        return $nfdump_time_filter;
    } else {
        my ($s, $min, $h, $d, $m, $y) = localtime($first_act);
        my $parsed_interval_start = sprintf("%d/%02d/%02d.%02d:%02d:%02d", $y+1900, $m+1, $d, $h, $min, $s);

        ($s, $min, $h, $d, $m, $y) = localtime($last_act);
        my $parsed_interval_end = sprintf("%d/%02d/%02d.%02d:%02d:%02d", $y+1900, $m+1, $d, $h, $min, $s);

        return "$parsed_interval_start-$parsed_interval_end";
    }
}

sub nfcapd_is_empty {
    my ($sources_path, $sources, $timeslot) = @_;
    my %info = get_info_from_nfcapd($sources_path, $sources, $timeslot);
    return not int($info{'Flows'}) > 0;
}

# Create nfdump OR filter of all IP addresses in a hash
sub ip2or_nfdump_filter {
    my @targets = @{(shift)};
    my @ips = map { dec2ip($_) } @targets;
    debug "ip2or_nfdump_filter called, number of ips: " . scalar @targets;
    return '(ip ' . (join ' or ip ', @ips) . ')';
}

# Retrieves the nfdump version number.
# If the (first) argument is '1', then the potentially available patch level is returned as well (e.g., 1.6.10p1)
sub retrieve_nfdump_version {
    my $include_patch_level = $_[0];
    my $cmd = "$NfConf::PREFIX/nfdump -V";
    my $full_version = qx($cmd);
    (my $version, my $patch_level) = $full_version =~ /nfdump: Version: ([\.0-9]+)((p[0-9]+)?)/;
    return ($include_patch_level) ? $version.$patch_level : $version;
}

sub nfdump_version_check {
    my $must_be = shift;
    return compare_string_version_number($SSHCure::nfdump_version, $must_be) != 1;
}

sub get_sorting_flag {
    return (nfdump_version_check("1.6.8")) ? "-O tstart" : "-m";
}

##############################
#
# Miscellaneous
#
##############################

# Compares the two specified version number. Only string-based version numbers (e.g., "1.3.6") are supported.
# Also patch-levels indicated in version numbers are supported (e.g., "1.3.6p1").
# The following return values are supported:
#   -1  - The first version number is higher
#   0   - Both version numbers are equal
#   1   - The second version number is higher
sub compare_string_version_number {
    my ($version1, $version2) = @_;
    
    # Remove dots from version numbers
    $version1 =~ s/[.]//g;
    $version2 =~ s/[.]//g;
    
    # Make sure both version numbers have the same structure (i.e., major.minor.patchlevel)
    if ($version1 < 100) {
        $version1 *= 10;
    }
    if ($version2 < 100) {
        $version2 *= 10;
    }
    
    my $result;
    if ($version1 > $version2) {
        $result = -1;
    } elsif ($version1 < $version2) {
        $result = 1;
    } else {
        $result = 0;
    }
    
    return $result;
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
sub perform_config_sanity_check {
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
    
    return 1;
}

use IO::Async::Future;
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
