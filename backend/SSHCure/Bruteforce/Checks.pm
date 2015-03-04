######################################################################
#
#  Bruteforce::Checks.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Bruteforce::Checks;
use strict;
use warnings;

use SSHCure::Bruteforce::Utils;
use SSHCure::Utils;
use SSHCure::Utils::Nfdump;

use IO::Async::Future;
use Future::Utils;

use List::Util qw(sum);

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw (
    check_network_block
    check_instant_logout_abort_dictionary
    check_instant_logout_continue_dictionary
    check_maintain_connection_abort_dictionary
    check_maintain_connection_continue_dictionary
    check_APS_only_flow
    check_login_grace_time
);

# check_network_block detects possible network-wide L3 blocking (e.g. QuarantaineNet)
sub check_network_block {
    my ($attacker_ip) = @_;
    my $non_blocked_attacks = 0;
    my $blocked_attacks = 0;
    my %block_times = ();
    my $bin_size = 1; # bin size in seconds

    unless (exists $SSHCure::attacks{$attacker_ip} && exists $SSHCure::attacks{$attacker_ip}{'targets'}) {
        return undef;
    }

    for my $target_ip (keys %{$SSHCure::attacks{$attacker_ip}{'targets'}}) {
        my $target_info = $SSHCure::attacks{$attacker_ip}{'targets'}{$target_ip};
        next if $$target_info{'certainty'} < $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}; 

        if (exists $$target_info{'is_host_blocked'} && $$target_info{'is_host_blocked'} > 0) {
            $blocked_attacks++;
            my $block_time = int($$target_info{'block_time'}/$bin_size + 0.5);
            $block_times{$block_time}++ or $block_times{$block_time} = 1;
        } else {
            $non_blocked_attacks++;
        }
    }

    return undef if $blocked_attacks < 10;
    
    my ($top_block_time, $top_count, $percentage, $items_combined) = get_histogram_end(\%block_times, 3);
    debug "[NETBLOCK] top: $top_block_time, $top_count, $percentage";
    
    if ($percentage > 0.5) {
        debug sprintf "[NETBLOCK] %i%% of blocks occured at %i",
                $percentage * 100, $top_block_time * $bin_size;
        return $top_block_time * $bin_size;
    } else {
        debug sprintf "[NETBLOCK] %i%% of blocks (occured at %i) is not enough to mark as a network-level block",
                $percentage * 100, $top_block_time * $bin_size;
    }
    
    return undef;
}

sub check_instant_logout_abort_dictionary {
    # Observe the other targets in an attack to distinguish a successful login attempt

    # | ---------
    # | ---------   <-- attack on other targets continue
    # | ---------
    # | -----x      <-- compromised target (last flow to compromised target)
    # | ---------
    # | ---------
    
    # 'Aggregated flow record' has been produced using 'nfdump -a'
    my ($cmd_base, $sources_path, $source, $aggr_flow_record, $last_flow, $cusum_mean, $packets_histogram) = @_;
    my ($ip_version, $fl_stime, $fl_etime, $protocol,
            $attacker_ip, $attacker_port, $target_ip, $target_port,
            $flags, $packets, $bytes) = @{$aggr_flow_record};
    
    # The check only has to be performed if it's the last flow of the current tuple.
    return Future->wrap(0) unless ($last_flow);

    # The potential compromise flow must have at least shown communication with the SSH daemon
    return Future->wrap(0) unless (APS($flags));

    my @packets_histogram_keys = keys %{$packets_histogram};
    my $highest_packets = (sort {$a <=> $b} @packets_histogram_keys)[-1];

    # Make a guess on whether port number reuse affects the 'highest PPF', i.e., '$highest_ppf == 2 * $cusum_mean'.
    # Since we only want to make a guess here, we do it in a conservative way, i.e., without a buffer range.
    if ($highest_packets == 2 * $cusum_mean) {
        # If port number reuse is suspected but there is only one PPF, we skip further processing
        return Future->wrap(0) if (scalar @packets_histogram_keys < 2);

        $highest_packets = (sort {$a <=> $b} @packets_histogram_keys)[-2];
    }
    
    if ($packets >= $cusum_mean + $CFG::ALGO{'BRUTEFORCE_COMPROMISE_MIN_PPF_DEVIATION'} && $packets == $highest_packets && $$packets_histogram{$packets} <= 2) {
        # Calculate the fraction of PPF that is > cusum_mean, to determine whether outlier is expectional or not.
        my $above_cusum_packets_count = 0;
        my $total_packets_count = 0;
        for my $key (@packets_histogram_keys) {
            $above_cusum_packets_count += $$packets_histogram{$key} if ($key > $cusum_mean);
            $total_packets_count += $$packets_histogram{$key};
        }

        # Given the outer if-condition, we know that above_cusum_ppf_count is always > 0
        my $above_cusum_packets_frac = $above_cusum_packets_count / $total_packets_count;
        my $packets_count_threshold = ($total_packets_count > 25) ? 2 : 1;
        unless ($above_cusum_packets_count <= $packets_count_threshold || $above_cusum_packets_frac < 0.05) {
            return Future->wrap(0);
        }
    } else {
        return Future->wrap(0);
    }

    # Find all other bruteforce targets for this attack
    my @bruteforce_targets = ();
    if (exists $SSHCure::attacks{$attacker_ip}) {
        while ((my $target, my $target_info) = each (%{$SSHCure::attacks{$attacker_ip}{'targets'}})) {
            if (exists $$target_info{'last_act_bf'}) {
                push(@bruteforce_targets, $target);
            }
        }
    }
    
    # Check whether we can use other targets that are close in the IP address space
    my @other_targets_to_consider = ();

    # FIXME Investigate how the code below can be made IPv6 compatible (i.e., comparing IPv6 addresses as numeric values)
    if ($ip_version == 4 && scalar @bruteforce_targets > $CFG::ALGO{'BRUTEFORCE_MIN_TARGET_COMPARISON_COUNT'}) {
        # Try to take up to 3 targets that are just below the considered target in the IP address space.
        my @lower_target_ips = (grep $_ < $target_ip, sort @bruteforce_targets);
        if (scalar @lower_target_ips >= 3) {
            push(@other_targets_to_consider, @lower_target_ips[-3..-1]);
        } elsif (scalar @lower_target_ips > 0) {
            push(@other_targets_to_consider, @lower_target_ips[(-1 * scalar @lower_target_ips)..-1]);
        }
        
        # Try to take up to 3 targets that are just above the considered target in the IP address space.
        my @higher_target_ips = (grep $_ > $target_ip, sort @bruteforce_targets);
        if (scalar @higher_target_ips >= 3) {
            push(@other_targets_to_consider, @higher_target_ips[-3..-1]);
        } elsif (scalar @lower_target_ips > 0) {
            push(@other_targets_to_consider, @higher_target_ips[(-1 * scalar @higher_target_ips)..-1]);
        }
    }
    
    # Convert the IP address of all close targets in the IP address space.
    foreach my $other_target (@other_targets_to_consider) {
        $other_target = dec2ip($other_target);
    }
    
    my $cmd_filter;
    if (scalar @other_targets_to_consider > 0) { # Is always IPv4 (see FIXME above)
        $cmd_filter = sprintf "proto tcp and src ip %s and dst ip in [%s] and dst port in [%s]", dec2ip($attacker_ip), join(",", @other_targets_to_consider), "22";
    } elsif ($ip_version == 6) {
        $cmd_filter = sprintf "proto tcp and src ip %s and not dst ip %s and dst port in [%s]", $attacker_ip, $target_ip, "22";
    } else {
        $cmd_filter = sprintf "proto tcp and src ip %s and not dst ip %s and dst port in [%s]", dec2ip($attacker_ip), dec2ip($target_ip), "22";
    }

    my $cmd = sprintf "-M %s%s -o pipe -Nq -A srcip", $sources_path, $source;
    my @cmd = (@$cmd_base, split(" ", $cmd), $cmd_filter);
    
    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my @flow_records = split("\n", shift);

        # If no flow records are returned (e.g, there are no other targets for this attack), the check can never yield a useful result. Return false.
        return Future->wrap(0) if (scalar @flow_records == 0);

        my $parsed_flows = parse_nfdump_pipe(\@flow_records);

        # We expect just a single flow, due to '-A srcip' and filter on source IP address
        my $flow = (@{$parsed_flows})[0];
        my ($aggr_ip_version, $aggr_fl_stime, $aggr_fl_etime, $aggr_protocol,
                $aggr_attacker_ip, $aggr_attacker_port, $aggr_target_ip, $aggr_target_port,
                $aggr_flags, $aggr_packets, $aggr_octets) = @$flow;

        # Only a potential compromise in case the time between the last flow of the tuple and the last traffic of the attacker is more than 7 seconds
        return Future->wrap(abs($aggr_fl_etime - $fl_etime) > 7);
    });
}

sub check_instant_logout_continue_dictionary {
    # 'Aggregated flow record' has been produced using 'nfdump -a'
    my ($aggr_flow_record, $last_flow, $one_but_last_flow, $non_aggr_flow_records, $cusum_mean, $packets_histogram, $port_number_reuse) = @_;
    my ($ip_version, $fl_stime, $fl_etime, $protocol,
            $attacker_ip, $attacker_port, $target_ip, $target_port,
            $flags, $packets, $bytes) = @{$aggr_flow_record};

    # An attacker can never have continued the dictionary if this is the last flow.
    # Also, we see a spike in the one-but-last flow very often, which could result in a FP.
    return Future->wrap(0) if ($last_flow || $one_but_last_flow);

    my @packets_values = ();
    if ($port_number_reuse) {
        foreach my $flow_record (@$non_aggr_flow_records) {
            ($ip_version, $fl_stime, $fl_etime, $protocol,
                    $attacker_ip, $attacker_port, $target_ip, $target_port,
                    $flags, $packets, $bytes) = @{$flow_record};
            push(@packets_values, $packets);
        }
    } else {
        push(@packets_values, $packets);
    }

    my $result = 0;
    foreach $packets (@packets_values) {
        my @packets_histogram_keys = keys %{$packets_histogram};
        my $highest_packets = (sort {$a <=> $b} @packets_histogram_keys)[-1];
        
        if ($packets >= $cusum_mean + $CFG::ALGO{'BRUTEFORCE_COMPROMISE_MIN_PPF_DEVIATION'} && $packets == $highest_packets && $$packets_histogram{$packets} <= 2) {
            # Calculate the fraction of PPF that is > cusum_mean, to determine whether outlier is expectional or not.
            my $above_cusum_packets_count = 0;
            my $total_packets_count = 0;
            for my $ppf_key (@packets_histogram_keys) {
                if ($ppf_key > $cusum_mean) {
                    $above_cusum_packets_count += $$packets_histogram{$ppf_key};
                }
                $total_packets_count += $$packets_histogram{$ppf_key};
            }
            
            # Given the outer if-condition, we know that above_cusum_packets_count is always > 0
            my $above_cusum_packets_frac = $above_cusum_packets_count / $total_packets_count;
            $result = $above_cusum_packets_count == 1 || $above_cusum_packets_frac < 0.05;
        }
        
        last if $result == 1;
    }

    return Future->wrap($result);
}

# Check for a maintained connection towards a single target, while connections (new attempts) to other targets are made.
# If the maintened connection ends, when all other activity ends, it is likely to be a compromise.
sub check_maintain_connection_abort_dictionary {
    # 'Aggregated flow record' has been produced using 'nfdump -a'
    my ($cmd_base, $sources_path, $source, $aggr_flow_record, $last_flow, $highest_duration, $cusum_mean) = @_;
    my ($ip_version, $fl_stime, $fl_etime, $protocol,
            $attacker_ip, $attacker_port, $target_ip, $target_port,
            $flags, $packets, $bytes) = @{$aggr_flow_record};
    
    # This check only has to be performed if it's the last flow of the current tuple.
    return Future->wrap(0) unless ($last_flow);

    # If the aggregated flow record does not even have a TCP FIN/RST flag set, it's an open connection.
    # A 'connection until attack end' should feature at least a TCP FIN flag (or RST?).
    return Future->wrap(0) if (no_FIN_RST($flags));

    # If the flow record is as long or shorter in duration than the average BF-flow ($top_duration is duration with highest frequency), we don't consider it an open connection.
    # return Future->wrap(0) if ($fl_etime - $fl_stime < $top_duration);

    # The potential compromise flow should have a duration in [$highest_duration - 1, $highest_duration + 1]
    return Future->wrap(0) unless ($fl_etime - $fl_stime >= $highest_duration - 1 && $fl_etime - $fl_stime <= $highest_duration + 1);

    # This check can only be performed if other targets exist in this attack and when they are known.
    return Future->wrap(0) unless (exists $SSHCure::attacks{$attacker_ip});

    # We have seen many attacks that look as follows:
    # 2014-02-01  14:39:12.664  21.700  6  A:2371  ->  T:22  .AP.SF  0  21  3351  1
    # 2014-02-01  14:39:20.164  20.100  6  A:4994  ->  T:22  .AP.SF  0  21  3351  1
    # 2014-02-01  14:39:34.414  23.000  6  A:4987  ->  T:22  .AP.SF  0  22  3397  1
    # 2014-02-01  14:39:40.664  20.350  6  A:2034  ->  T:22  .AP.SF  0  19  3275  1
    # 2014-02-01  14:39:57.564  23.900  6  A:2430  ->  T:22  .APRS.  0  12  2277  1
    # 2014-02-01  14:40:01.164  16.700  6  A:2120  ->  T:22  .AP.SF  0  17  3167  1
    # 2014-02-01  14:40:18.014  23.150  6  A:2263  ->  T:22  .APRS.  0  18  3167  1 <-- Not a compromise
    return Future->wrap(0) if ($packets < $cusum_mean && APS($flags) && RST($flags));
    
    my $last_activity_to_target = $fl_etime;
    
    # Determine all of the other bruteforce targets for this attack
    my @bruteforce_targets = ();
    while ((my $target, my $target_info) = each (%{$SSHCure::attacks{$attacker_ip}{'targets'}})) {
        push(@bruteforce_targets, dec2ip($target)) if (exists $$target_info{'last_act_bf'});
    }

    # Skip processing in case there are not enough other targets in this attack.
    return Future->wrap(0) unless (scalar @bruteforce_targets > $CFG::ALGO{'BRUTEFORCE_MIN_TARGET_COMPARISON_COUNT'});

    my $cmd_filter;
    if ($ip_version == 4) {
        $cmd_filter = sprintf "proto tcp and flags APS and src ip %s and not dst ip %s and dst port in [%s]", dec2ip($attacker_ip), dec2ip($target_ip), "22";
    } else {
        $cmd_filter = sprintf "proto tcp and flags APS and src ip %s and not dst ip %s and dst port in [%s]", $attacker_ip, $target_ip, "22";
    }

    my $cmd = sprintf "-M %s%s -o pipe -Nq -A srcip", $sources_path, $source;
    my @cmd = (@$cmd_base, split(" ", $cmd), $cmd_filter);
    
    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my $result = shift;
        my @flow_records = split("\n", $result);

        # If no flow records are returned, the check can never yield a useful result. Return false.
        return Future->wrap(0) if (scalar @flow_records == 0);

        my $parsed_flows = parse_nfdump_pipe(\@flow_records);

        # We expect just a single flow, due to '-A srcip' and filter on source IP address
        my $flow = (@{$parsed_flows})[0];

        ($ip_version, $fl_stime, $fl_etime, $protocol,
                $attacker_ip, $attacker_port, $target_ip, $target_port,
                $flags, $packets, $bytes) = @{$flow};
        return Future->wrap(abs($last_activity_to_target - $fl_etime) < 1);
    });
}

sub check_maintain_connection_continue_dictionary {
    # 'Aggregated flow record' has been produced using 'nfdump -a'
    # 'Last flow record' has been produced using 'nfdump -a'
    my ($cmd_base, $sources_path, $source, $aggr_flow_record, $first_flow, $last_flow, $one_but_last_flow, $last_flow_record, $highest_duration, $port_number_reuse, $highest_packets) = @_;
    my ($ip_version, $fl_stime, $fl_etime, $protocol,
            $attacker_ip, $attacker_port, $target_ip, $target_port,
            $flags, $packets, $bytes) = @{$aggr_flow_record};
    my ($last_ip_version, $last_fl_stime, $last_fl_etime, $last_protocol,
            $last_attacker_ip, $last_attacker_port, $last_target_ip, $last_target_port,
            $last_flags, $last_packets, $last_bytes) = @{$last_flow_record};

    # Many attacks have a flow with an increased PPF as the first flow after the scan phase. Example:
    # 2014-01-13 06:55:55.122   0.350 6  A:6000  ->  T:22  ...RS.  0   2    92  1
    # 2014-01-13 07:08:49.830  67.150 6  A:1397  ->  T:22  .AP.SF  0  21  3351  1 <-- Not a compromise
    # 2014-01-13 07:09:57.180  17.700 6  A:2584  ->  T:22  .AP.SF  0  16  3121  1
    # 2014-01-13 07:10:14.930  18.150 6  A:3512  ->  T:22  .AP.SF  0  16  3121  1
    # 2014-01-13 07:10:33.030  16.900 6  A:3015  ->  T:22  .AP.SF  0  16  3121  1
    #
    # However, if we have a first flow in a new data chunk which is not the first flow for the tuple, we should continue processing.
    # We therefore check whether the tuple is already present in the attacks hash.
    return Future->wrap(0) if ($first_flow && !(exists $SSHCure::attacks{$attacker_ip} && exists $SSHCure::attacks{$attacker_ip}{'targets'}{$target_ip}));

    # Connection until dictionary end can never be the case for the last flow; in that case it's an 'instant logout'
    # Also, we see that very often a spike in the one-but-last flow, which could result in a FP.
    return Future->wrap(0) if ($last_flow || $one_but_last_flow);

    return Future->wrap(0) if ($packets != $highest_packets);

    return Future->wrap(0) if ($port_number_reuse);

    my $comp_start_time = $fl_stime;
    my $comp_end_time = $fl_etime;
    my $comp_duration = $comp_end_time - $comp_start_time;

    # The potential compromise flow should have a duration in [$highest_duration - 1, $highest_duration + 1]
    return Future->wrap(0) unless ($comp_duration >= $highest_duration - 1 && $comp_duration <= $highest_duration + 1);
    
    # The flow should have a minimal duration for it to be qualified for this type of compromise.
    # If many very short BF-flows are observed closely together, it may look like a 'connection until
    # dictionary end', while they're just typical BF attempts.
    # 2014-01-18 23:59:53.178  1.500 TCP  A:57228 -> T:22  .AP.SF  0  12 1152  1 <-- Not a compromise
    # 2014-01-18 23:59:54.728  0.950 TCP  A:57304 -> T:22  .AP.SF  0  12 1152  1 <-- Last flow
    # ---
    # 2014-01-18 23:59:52.578  2.100 TCP  A:59420 -> T:22  .AP.SF  0  16 1384  1 <-- Not a compromise
    # 2014-01-18 23:59:54.628  1.050 TCP  A:59526 -> T:22  .AP.SF  0  16 1384  1 <-- Last flow
    return Future->wrap(0) if ($comp_duration <= 3);
    
    # Aggregate all traffic between attacker and target, except for the potential compromise flow.
    # Compare the flow end time of the possible compromise flow with the aggregated flow record.
    # In this way, we evaluate whether the possible compromise flow 'stops when all activity between attacker/target stops'.
    my $cmd_filter;
    if ($ip_version == 4) {
        $cmd_filter = sprintf "proto tcp and (flags APSF or flags APSR) and src ip %s and dst ip %s and dst port in [%s] and not src port %i", dec2ip($attacker_ip), dec2ip($target_ip), "22", $attacker_port;
    } else {
        $cmd_filter = sprintf "proto tcp and (flags APSF or flags APSR) and src ip %s and dst ip %s and dst port in [%s] and not src port %i", $attacker_ip, $target_ip, "22", $attacker_port;
    }

    my $cmd = sprintf "-M %s%s -o pipe -Nq -A srcip,dstip", $sources_path, $source;
    my @cmd = (@$cmd_base, split(" ", $cmd), $cmd_filter);

    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my $result = shift;
        my @flow_records = split("\n", $result);

        # If no flow records are returned, the check can never yield a useful result. Return false.
        return Future->wrap(0) if (scalar @flow_records == 0);

        my $parsed_flows = parse_nfdump_pipe(\@flow_records);

        # We expect just a single flow, due to '-A srcip' and filter on source IP address
        my $flow = (@{$parsed_flows})[0];

        ($ip_version, $fl_stime, $fl_etime, $protocol,
                $attacker_ip, $attacker_port, $target_ip, $target_port,
                $flags, $packets, $bytes) = @{$flow};

        # Check whether the last two flow records start with a 1s-deviation (abs($last_fl_stime - $comp_start_time) > 1).
        # 2014-01-10 01:46:47.156  5.500 TCP  A:34654 -> T:22  .AP.SF  0  16 1660  1 <-- Not a compromise
        # 2014-01-10 01:46:48.906  4.500 TCP  A:34688 -> T:22  .AP.SF  0  13 1320  1 <-- Last flow
        # ---
        # 2014-01-11 17:34:37.520  7.750 TCP  A:37251 -> T:22  .AP.SF  0  17 1924  1 <-- Not a compromise
        # 2014-01-11 17:34:38.220  6.550 TCP  A:37208 -> T:22  .AP.SF  0  16 1860  1 <-- Last flow
        # ---
        # 2014-02-04 21:49:44.664  8.050 TCP  A:1870  -> T:22  .AP.SF  0  21 3351  1 <-- Not a compromise
        # 2014-02-04 21:49:48.614  4.900 TCP  A:3048  -> T:22  .AP.SF  0  19 3323  1 <-- Last flow
        return Future->wrap(0) if (abs($last_fl_stime - $comp_start_time) <= 1);

        my $delta_time_threshold = ($comp_duration > 100) ? 5 : 1;
        return Future->wrap(abs($comp_end_time - $fl_etime) <= $delta_time_threshold);
    });
}

sub check_APS_only_flow {
    # 'Aggregated flow record' has been produced using 'nfdump -a'
    my ($aggr_flow_record) = @_;
    my ($ip_version, $fl_stime, $fl_etime, $protocol,
            $attacker_ip, $attacker_port, $target_ip, $target_port,
            $flags, $packets, $bytes) = @{$aggr_flow_record};

    my $APS_only_flow = ($flags == 0b011010);

    # We have to use the aggregated flow record here, since we have to look for connections that remain open (i.e., APS-only) beyond
    # the current data chunk. In case it is closed within the current chunk, it is potentially a type of 'maintain connection'.
    return Future->wrap($APS_only_flow && $packets >= $CFG::ALGO{'MIN_SSH_AUTH_PPF'});
}

# check_login_grace_time is only to be called when an open connection has been observed
# i.e. after check_open_connection has been called, and returned true.
sub check_login_grace_time {
    my ($cmd_base, $sources_path, $source, $aggr_flow_record, $non_aggr_flow_records) = @_;

    # If the non-aggregated attacker->target traffic does not have a single APS-flow, the result can never be true
    my $open_conn_found = 0;
    foreach my $flow_record (@$non_aggr_flow_records) {
        my ($ip_version, $fl_stime, $fl_etime, $protocol,
                $attacker_ip, $attacker_port, $target_ip, $target_port,
                $flags, $packets, $bytes) = @{$flow_record};
        if (SYN_ACK($flags) && no_FIN_RST($flags)) {
            $open_conn_found = 1;
            last;
        }
    }

    return Future->wrap(0) unless ($open_conn_found);

    my ($ip_version, $fl_stime, $fl_etime, $protocol,
            $attacker_ip, $attacker_port, $target_ip, $target_port,
            $flags, $packets, $bytes) = @{$aggr_flow_record};

    # Check RETURN traffic (target->attacker)
    my $cmd_filter;
    if ($ip_version == 4) {
        $cmd_filter = sprintf "proto tcp and src ip %s and src port in [%s] and dst ip %s and dst port %i", dec2ip($target_ip), "22", dec2ip($attacker_ip), $target_port;
    } else {
        $cmd_filter = sprintf "proto tcp and src ip %s and src port in [%s] and dst ip %s and dst port %i", $target_ip, "22", $attacker_ip, $target_port;
    }
    
    my $cmd = sprintf "-M %s%s %s -o pipe -Nq", $sources_path, $source, get_sorting_flag();
    my @cmd = (@$cmd_base, split(" ", $cmd), $cmd_filter);
    
    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my $result = shift;
        my @flow_records = split("\n", $result);
        my $parsed_flows = parse_nfdump_pipe(\@flow_records);
        
        my $login_grace_time_detected = 0;
        foreach my $flow (@$parsed_flows) {
            my ($ip_version, $fl_stime, $fl_etime, $protocol,
                    $attacker_ip, $attacker_port, $target_ip, $target_port,
                    $flags, $packets, $bytes) = @{$flow};
            my $duration = $fl_etime - $fl_stime;
            if (FIN($flags) && $duration >= $CFG::ALGO{'OPENSSH_LOGIN_GRACE_TIME'}) {
                # Flow has terminated and its duration is >= SSH login grace time: idle SSH connection in authentication phase
                $login_grace_time_detected = 1;
                last;
            }
        }

        return Future->wrap($login_grace_time_detected);
    });
}

1;
