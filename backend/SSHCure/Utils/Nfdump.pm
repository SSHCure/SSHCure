######################################################################
#
#  nfdump.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Utils::Nfdump;
use strict;
use warnings;

use SSHCure::Utils;

use IO::Async::Future;
use Future::Utils qw(fmap_concat);
use Time::Local;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw (
    compare_nfdump_version_number
    get_corrected_interval_for_timeslot
    get_info_from_nfcapd
    get_profile
    get_sorting_flag
    ip2or_nfdump_filter
    nfcapd_is_empty
    nfdump_version_check
    retrieve_nfdump_version

    nfdumptime2unix
    nfcapd2date
    nfcapd2unix
    unix2nfcapd
    previous_nfcapd
);

# Compares the two specified version number. Only string-based version numbers (e.g., "1.3.6") are supported.
# Also patch-levels indicated in version numbers are supported (e.g., "1.3.6p1").
# The following return values are supported:
#   -1  - The first version number is higher
#   0   - Both version numbers are equal
#   1   - The second version number is higher
sub compare_nfdump_version_number {
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

        log_info("Corrected time window: turned %i - %i into %i - %i", $first_act, $last_act, ($nfcapd_stamp - 10*60), ($nfcapd_stamp + 10*60));
        return $nfdump_time_filter;
    } else {
        my ($s, $min, $h, $d, $m, $y) = localtime($first_act);
        my $parsed_interval_start = sprintf("%d/%02d/%02d.%02d:%02d:%02d", $y+1900, $m+1, $d, $h, $min, $s);

        ($s, $min, $h, $d, $m, $y) = localtime($last_act);
        my $parsed_interval_end = sprintf("%d/%02d/%02d.%02d:%02d:%02d", $y+1900, $m+1, $d, $h, $min, $s);

        return "$parsed_interval_start-$parsed_interval_end";
    }
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

sub get_profile {    
    my $profile = (grep(@{$_}[1] eq 'SSHCure' , @NfConf::plugins))[0]->[0];
    
    if ($profile eq '*' || $profile eq '!') {
        $profile = 'live';
    }
    
    return $profile;
}

sub get_sorting_flag {
    return (nfdump_version_check("1.6.8")) ? "-O tstart" : "-m";
}

# Create nfdump OR filter of all IP addresses in a hash
sub ip2or_nfdump_filter {
    my @targets = @{(shift)};
    my @ips = map { dec2ip($_) } @targets;
    return '(ip ' . (join ' or ip ', @ips) . ')';
}

sub nfcapd_is_empty {
    my ($sources_path, $sources, $timeslot) = @_;
    my %info = get_info_from_nfcapd($sources_path, $sources, $timeslot);
    return not int($info{'Flows'}) > 0;
}

sub nfdump_version_check {
    my $must_be = shift;
    return compare_nfdump_version_number($SSHCure::nfdump_version, $must_be) != 1;
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

#####################
# Time routines
#####################

# nfdump syntax -t:
# timewin is YYYY/MM/dd.hh:mm:ss[-YYYY/MM/dd.hh:mm:ss]

sub nfdumptime2unix {
    my $raw = shift;
    my ($year, $mon, $day, $hour, $min, $sec, $msec) = ($raw =~ /(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})/);
    return timelocal($sec, $min, $hour, $day ,$mon - 1, $year) + $msec/1000;
}

sub nfcapd2date {
    my $nfcapd_timestamp = shift; # format: yyyymmddhhmm
    my @date = ($nfcapd_timestamp =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/g);
    return @date;
}

sub nfcapd2unix {
    my $nfcapd_timestamp = shift; # format: yyyymmddhhmm
    my ($y, $m, $d, $h, $min) = ($nfcapd_timestamp =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/g);
    return timelocal(0, $min, $h, $d, $m - 1, $y);
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
    $unix_timestamp -= 5 * 60; # - 300sec == - 5min
    return unix2nfcapd($unix_timestamp);
}
