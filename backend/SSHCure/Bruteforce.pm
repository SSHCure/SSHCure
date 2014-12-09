######################################################################
#
#  Bruteforce.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Bruteforce;
use strict;
use warnings;

use SSHCure::Bruteforce::Checks;
use SSHCure::Bruteforce::Utils;
use SSHCure::Utils;
use SSHCure::Utils::Nfdump;
use SSHCure::Model;

use IO::Async::Function;
use IO::Async::Future;

use Future::Utils qw(fmap_concat fmap_void);

use List::Util qw(max);

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(bruteforce_detection);

my @potential_compromises_next_interval = ();   # Potential compromises that have to be checked only during the next interval
my @potential_compromises_next_intervals = ();  # Potential compromises that have to be checked for at least one next interval
my @cmd_base;

sub bruteforce_detection {
    my ($sources, $sources_path, $timeslot, $timeslot_interval) = @_;
    @cmd_base = split(" ", "$NfConf::PREFIX/nfdump -6 -r nfcapd.$timeslot -t $timeslot_interval");

    # Reset lists
    my @potential_compromises = ();
    my @new_blocked_attackers = ();
    
    # Process potential compromises from previous run
    if (scalar @potential_compromises_next_interval > 0) {
        @potential_compromises = (fmap_concat {
            my $potential_compromise = shift;
            my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$potential_compromise;
            my ($target_ip, $target_info) = %$target;
        
            if ($compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'INSTANT_LOGOUT_ABORT_DICTIONARY'}
                    || $compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION_ABORT_DICTIONARY'}) {
                # Check whether any traffic has been reported between attacker and target in the current file
                my $cmd = "-o pipe -Nq -c 1";
                my $cmd_filter = sprintf "proto tcp and src ip %s and dst ip %s and dst port %i", dec2ip($attacker_ip), dec2ip($target_ip), "22";
                my @cmd = (@cmd_base, "-M", "${sources_path}${source}", split(" ", $cmd), $cmd_filter);
            
                $SSHCure::loop->run_child_future(
                    command => \@cmd,
                )->then( sub {
                    my @flow_records = split("\n", shift);
                
                    # If no traffic has been found, proceed with adding this tuple as a compromise
                    if (scalar @flow_records == 0) {
                        Future->wrap($potential_compromise);
                    } else {
                        Future->wrap();
                    }
                });
            } else {
                Future->wrap();
            }
        } concurrent => $SSHCure::async_workers, foreach => \@potential_compromises_next_interval)->get();
    } else {
        # Do nothing
    }

    # Process potential compromises from previous run(s)
    if (scalar @potential_compromises_next_intervals > 0) {
        # fmap_concat shifts potential_compromises_next_intervals, so we make a copy to retain the list
        my @next_intervals_results = (fmap_concat {
            my $potential_compromise = shift;
            my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$potential_compromise;
            my ($target_ip, $target_info) = %$target;

            my @conf_potential_compromise = ();
            my @check_next_intervals = ();
        
            if ($compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION'}) {
                my $cmd = "-o pipe -Nq";

                # Check whether an AF-only-flow is found
                my $cmd_filter = sprintf "proto tcp \
                        and src ip %s and src port %i \
                        and dst ip %s and dst port %s \
                        and flags %s and not flags %s",
                        dec2ip($attacker_ip), $compromise_port, dec2ip($target_ip), "22", "AF", "S";

                # Check whether an AF-only flow or AR-only flow is found
                $SSHCure::loop->run_child_future(
                    command => [ @cmd_base, "-M", "${sources_path}${source}", split(" ", $cmd), $cmd_filter ],
                )->then( sub {
                    my @flow_records = split("\n", shift);

                    if (scalar @flow_records == 1) {
                        push(@conf_potential_compromise, $potential_compromise);
                    } elsif (abs(nfcapd2unix($timeslot) - $compromise_time) < $CFG::ALGO{'MAX_OPEN_CONNECTION_DURATION'} && scalar @flow_records == 0) {
                        push(@check_next_intervals, $potential_compromise);
                    } elsif ($CFG::ALGO{'CONSIDER_MULTIPLE_CONNECTION_CLOSINGS_AS_COMP'} && scalar @flow_records > 1) {
                        push(@conf_potential_compromise, $potential_compromise);
                    } else {
                        # Do nothing; current entry will be removed from queue
                    }

                    Future->wrap([ \@conf_potential_compromise, \@check_next_intervals ]);
                });
            } else {
                Future->wrap([ \@conf_potential_compromise, \@check_next_intervals ]);
            }
        } concurrent => $SSHCure::async_workers, foreach => \@potential_compromises_next_intervals)->get();

        # Process results
        foreach my $result (@next_intervals_results) {
            my ($conf_potential_compromise, $check_next_intervals) = @{$result};

            if (scalar @{$conf_potential_compromise} > 0) {
                # There is always just a single element in the array
                push(@potential_compromises, @{$conf_potential_compromise});
            } elsif (scalar @{$check_next_intervals} > 0) {
                # There is always just a single element in the array
                push(@potential_compromises_next_intervals, @{$check_next_intervals});
            } else {
                # Do nothing
            }
        }
    } else {
        # Do nothing
    }

    # Pre-selection
    my $cmd = "-A srcip,dstip -o pipe -Nq";
    my $cmd_filter = sprintf "proto tcp and dst port 22 and packets > %i and packets < %i", ($CFG::ALGO{'BRUTEFORCE_MIN_PPF'} - 1), ($CFG::ALGO{'BRUTEFORCE_MAX_PPF'} + 1);
    my @preselection_parsed_tmp = (fmap_concat {
        my $source = shift;
        my @cmd = (@cmd_base, "-M", "${sources_path}${source}", split(" ", $cmd), $cmd_filter);
        
        $SSHCure::loop->run_child_future(
            command => \@cmd
        )->then( sub {
            my @preselection_raw = split("\n", shift);
            Future->wrap(parse_nfdump_pipe(\@preselection_raw));
        });
    } concurrent => $SSHCure::async_workers, foreach => [ split(":", $sources) ])->get();

    # Create a hash out of preselection_parsed_tmp that uses the (data) sources as keys
    my $preselection_tuples = 0;
    my %preselection_parsed = ();
    my @splitted_sources = split(":", $sources);
    for (my $i = 0; $i < scalar @splitted_sources; $i++) {
        $preselection_parsed{$splitted_sources[$i]} = $preselection_parsed_tmp[$i];
        $preselection_tuples += scalar @{$preselection_parsed_tmp[$i]};
    }
    
    # Detection
    return if $preselection_tuples == 0;

    my @new_attackers = ();
    foreach my $source (@splitted_sources) {
        my @new_attackers_source = (fmap_concat {
            my $preselection_flow = shift;
            my $ip_version = @$preselection_flow[0];

            my ($attacker_ip, $target_ip);
            if ($ip_version == 4) {
                $attacker_ip = dec2ip(@$preselection_flow[4]);
                $target_ip = dec2ip(@$preselection_flow[6]);
            } else {
                $attacker_ip = @$preselection_flow[4];
                $target_ip = @$preselection_flow[6];
            }
            
            my $filter_cmd = sprintf "proto tcp and dst port in [%s] and src ip %s and dst ip %s", "22", $attacker_ip, $target_ip;
            my $cmd = sprintf "%s -o pipe -Nq -a", get_sorting_flag();
            my @cmd = (@cmd_base, "-M", "${sources_path}${sources}", split(" ", $cmd), $filter_cmd);
            $SSHCure::loop->run_child_future(
                command => \@cmd,
            )->then( sub {
                bruteforce_detection_function($sources_path, $source, shift, $preselection_flow);
            });
        } concurrent => $SSHCure::async_workers, foreach => $preselection_parsed{$source})->get();

        # Merge new attackers per source into a single list
        push(@new_attackers, @new_attackers_source);
    }

    foreach my $result_item (@new_attackers) {
        my $add_this_tuple                              = $$result_item{'add_this_tuple'};
        my $attacker_ip                                 = $$result_item{'attacker_ip'};
        my $target_ip                                   = $$result_item{'target_ip'};
        my $target_info                                 = $$result_item{'target_info'};
        my $new_potential_compromises                   = $$result_item{'potential_compromises'};
        my $new_potential_compromises_next_interval     = $$result_item{'potential_compromises_next_interval'};
        my $new_potential_compromises_next_intervals    = $$result_item{'potential_compromises_next_intervals'};
        
        if (defined $new_potential_compromises && scalar @$new_potential_compromises > 0) {
            push(@potential_compromises, @$new_potential_compromises);
        }
        if (defined $new_potential_compromises_next_interval && scalar @$new_potential_compromises_next_interval > 0) {
            push(@potential_compromises_next_interval, @$new_potential_compromises_next_interval) if defined $new_potential_compromises_next_interval;
        }
        if (defined $new_potential_compromises_next_intervals && scalar @$new_potential_compromises_next_intervals > 0) {
            push(@potential_compromises_next_intervals, @$new_potential_compromises_next_intervals) if defined $new_potential_compromises_next_intervals;
        }
        
        if ($add_this_tuple) {
            add_bf_attacker($attacker_ip, $target_info);
            
            if ($$target_info{$target_ip}{'is_host_blocked'}) {
                push(@new_blocked_attackers, $attacker_ip);
            }
        }
    }

    # Determine whether a network-level block occured
    foreach my $attacker_ip (@new_blocked_attackers) {
        my $attacker_blocking_time = check_network_block($attacker_ip);
        if ($attacker_blocking_time) {
            set_attacker_blocking_time($attacker_ip, $attacker_blocking_time);
        }
    }
    
    # Determine whether multiple (different) compromise reasons have been found for the same attacker/target tuple
    my %attacker_compromise_reasons;
    foreach my $new_compromise (@potential_compromises) {
        my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$new_compromise;
        my ($target_ip, $target_info) = %$target;
    
        if (exists $attacker_compromise_reasons{$attacker_ip}{$target_ip}) {
            unless (grep {$_ =~ $compromise_reason} @{$attacker_compromise_reasons{$attacker_ip}{$target_ip}}) {
                push @{$attacker_compromise_reasons{$attacker_ip}{$target_ip}}, $compromise_reason;
            }
        } else {
            push @{$attacker_compromise_reasons{$attacker_ip}{$target_ip}}, $compromise_reason;
        }
    }
    
    for (my $i = 0; $i < scalar @potential_compromises; $i++) {
        my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @{$potential_compromises[$i]};
        my ($target_ip, $target_info) = %$target;
        
        my @sorted_compromise_reasons = sort(@{$attacker_compromise_reasons{$attacker_ip}{$target_ip}});
        my $most_likely_compromise_reason = $sorted_compromise_reasons[-1];
        
        if ($most_likely_compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION'}
                && ($compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION_ABORT_DICTIONARY'}
                        || $compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION_CONTINUE_DICTIONARY'})) {
            # Do nothing
        } elsif ($compromise_reason != $most_likely_compromise_reason) {
            splice(@potential_compromises, $i, 1);
            $i--;
        }
    }
    
    ##### DEBUG #####
    # my $debug_target_ip = 2186907671;
    # foreach my $compromise (@potential_compromises) {
    #     my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$compromise;
    #     my ($target_ip, $target_info) = %$target;
        
    #     if ($target_ip == $debug_target_ip) {
    #         printf "[%s] BF   - %s (%i) -> %s, compromise reason: %i\n", $timeslot, dec2ip($attacker_ip), $compromise_port, dec2ip($target_ip), $compromise_reason;
    #     }
    # }
    # foreach my $compromise (@potential_compromises_next_interval) {
    #     my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$compromise;
    #     my ($target_ip, $target_info) = %$target;
        
    #     if ($target_ip == $debug_target_ip) {
    #         printf "[%s] BF   - %s (%i) -> %s, potential compromise reason (next interval): %i\n", $timeslot, dec2ip($attacker_ip), $compromise_port, dec2ip($target_ip), $compromise_reason;
    #     }
    # }
    # foreach my $compromise (@potential_compromises_next_intervals) {
    #     my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$compromise;
    #     my ($target_ip, $target_info) = %$target;
        
    #     if ($target_ip == $debug_target_ip) {
    #         printf "[%s] BF   - %s (%i) -> %s, potential compromise reason (next intervals): %i\n", $timeslot, dec2ip($attacker_ip), $compromise_port, dec2ip($target_ip), $compromise_reason;
    #     }
    # }
    #################
    
    # Loop over the potential compromises and add them if no network-level block is detected
    foreach my $new_compromise (@potential_compromises) {
        my ($attacker_ip, $target, $source, $compromise_time, $flow_endtime, $compromise_port, $compromise_reason, $detection_time) = @$new_compromise;
        
        my ($target_ip, $target_info) = %$target;
        $$target{$target_ip}{'last_act'} = $flow_endtime;
        $$target{$target_ip}{'compromise_reason'} = $compromise_reason;
        add_compromise_port($$target{$target_ip}, $compromise_port);
        
        if (exists $SSHCure::attacks{$attacker_ip}{'blocking_time'}) {
            if ($compromise_time >= $SSHCure::attacks{$attacker_ip}{'blocking_time'}) {
                debug sprintf "[NETBLOCK] compromise at %f was after the network-level block at %f, not adding as compromise",
                        $compromise_time, $SSHCure::attacks{$attacker_ip}{'blocking_time'};
            } elsif ($flow_endtime > $SSHCure::attacks{$attacker_ip}{'blocking_time'}) {
                # compromise_time < blocking_time by definition of if/elsif
                debug sprintf "[NETBLOCK] compromise at %f was before the network-level block at %f, but ended after: not adding as compromise",
                        $compromise_time, $SSHCure::attacks{$attacker_ip}{'blocking_time'};
            } else {
                add_comp_attacker($attacker_ip, $target);
            }
        } else {
            add_comp_attacker($attacker_ip, $target);
        }
    }

    Future->wrap();
}

sub bruteforce_detection_function {
    my ($sources_path, $source, $raw_nfdump_output, $preselection_flow) = @_;
    my @preselection_flow = @{$preselection_flow};
    my ($presel_ip_version, $presel_fl_stime, $presel_fl_etime, $presel_protocol, $presel_attacker_ip, $presel_attacker_port, $presel_target_ip, $presel_target_port, $presel_flags, $presel_packets, $presel_bytes) = @preselection_flow;

    foreach my $ip_range (split(',', $CFG::WHITELIST{'sources'})) {
        return Future->wrap() if (ip_addr_in_range($presel_attacker_ip, $ip_range));
    }
    foreach my $ip_range (split(',', $CFG::WHITELIST{'destinations'})) {
        return Future->wrap() if (ip_addr_in_range($presel_target_ip, $ip_range));
    }

    my $add_this_tuple = 0;
    my @new_potential_compromises;
    my @new_potential_compromises_next_interval;
    my @new_potential_compromises_next_intervals;
    my %target;

    # Get all the SSH flows between attacker and target, ordered by start time
    my @flow_records = split("\n", $raw_nfdump_output);
    my $parsed_flows = parse_nfdump_pipe(\@flow_records);
    my $flow_count = scalar @$parsed_flows;

    # The 2nd part of the if-condition below is for situations in which a (last) fraction of the attack lies in a new data chunk
    if ($flow_count < $CFG::ALGO{'BRUTEFORCE_CUSUM_STREAK_THRESHOLD'} && !(
            exists $SSHCure::attacks{$presel_attacker_ip} &&
            exists $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip} &&
            exists $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'certainty'} >= $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'})) {
        # Skip further processing as soon as possible
        return Future->wrap();
    }

    # Construct histograms
    my %duration_histogram;
    my %ppf_histogram;
    my %conn_starts;
    foreach my $flow_record (@$parsed_flows) {
        my $duration = int(@$flow_record[2]) - int(@$flow_record[1]);
        $duration_histogram{$duration} += 1 or $duration_histogram{$duration} = 1;
        
        my $ppf = @$flow_record[9];
        $ppf_histogram{$ppf} += 1 or $ppf_histogram{$ppf} = 1;

        # Concurrent connection starts
        $conn_starts{@$flow_record[1]} += 1 or $conn_starts{@$flow_record[1]} = 1;
    }

    my ($top_duration, $top_duration_flowcount, $top_duration_percentage, $highest_duration) = get_histogram_stats(\%duration_histogram);
    my ($top_ppf, $top_ppf_flowcount, $top_ppf_percentage, $highest_ppf) = get_histogram_stats(\%ppf_histogram);
    my ($avg_conc_conn_starts, $max_conc_conn_starts) = get_concurrent_connection_stats(\%conn_starts);

    unless ($top_ppf >= $CFG::ALGO{'BRUTEFORCE_MIN_PPF'} && $top_ppf <= $CFG::ALGO{'BRUTEFORCE_MAX_PPF'}) {
        # The top ppf is not in a 'valid BF range', this tuple can not yield new BF/COMP attackers
        return Future->wrap();
    } else {
        my ($cusum_mean, $cusum_mean_flow_records);

        # Check whether cusum mean was determined more reliably in previous iterations (i.e., more flow records having that 'top PPF')
        if (exists $SSHCure::attacks{$presel_attacker_ip}
                && exists $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}
                && exists $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'bf_cusum'}
                && exists $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'bf_cusum_flow_records'}
                && $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'bf_cusum'} != $top_ppf
                && $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'bf_cusum_flow_records'} > $top_ppf_flowcount) {
            # Use previously determined values, since they were determined more reliably
            $cusum_mean = $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'bf_cusum'};
            $cusum_mean_flow_records = $SSHCure::attacks{$presel_attacker_ip}{'targets'}{$presel_target_ip}{'bf_cusum_flow_records'};
        } else {
            $cusum_mean              = $top_ppf;
            $cusum_mean_flow_records = $top_ppf_flowcount;
            $target{$presel_target_ip} = {
                'bf_cusum'              => $cusum_mean,
                'bf_cusum_flow_records' => $cusum_mean_flow_records,
                'cusum'                 => 0,
                'cusum_count'           => 0
            };
        }

        # Skip further processing if the cusum mean was determined based on < 2 flow records, as we consider it determined unreliably
        return Future->wrap() if ($cusum_mean_flow_records < $CFG::ALGO{'BRUTEFORCE_CUSUM_DETERMINATION_THRESHOLD'});

        my $cusum_streak = 0;
        my $attack_start_time = time;
        my $marked_as_bf = 0;
        my $current_flow_index = 0;
        
        (fmap_void {
            my $flow_record = shift;
            my ($ip_version, $fl_stime, $fl_etime, $proto, $attacker_ip, $atk_port, $target_ip, $target_port, $flags, $ppf, $bytes) = @$flow_record;
            my $duration = $fl_etime - $fl_stime;

            $current_flow_index++;
            
            # $last_flow is a boolean stating whether the current flow record is the last one for this tuple (analogous for one_but_last_flow)
            my $first_flow = ($current_flow_index == 1);
            my $last_flow = ($current_flow_index == $flow_count);
            my $one_but_last_flow = ($flow_count > 1 && $current_flow_index == $flow_count - 1);
             
            if ($ppf == $cusum_mean) {
                # Traffic fits brute-force characteristics
                # Increase the cusum streak count, and mark this attacker as brute-force when the threshold is reached

                # Set the correct start time for the attack
                $attack_start_time = $fl_stime if $cusum_streak == 0;
                $cusum_streak++;

                if ($cusum_streak >= $CFG::ALGO{'BRUTEFORCE_CUSUM_STREAK_THRESHOLD'} && not $marked_as_bf) {
                    $marked_as_bf = 1;
                    $add_this_tuple = 1;
                    $target{$target_ip}{'first_act'} = $attack_start_time;
                    $target{$target_ip}{'last_act'} = $fl_etime;
                }
            
            # Reset cusum_streak if PPF deviates from cusum_mean
            } elsif ($cusum_streak < $CFG::ALGO{'BRUTEFORCE_CUSUM_STREAK_THRESHOLD'}) {
                $cusum_streak = 0;
            }
            
            # Check whether other targets in the same attack have been marked_as_bf
            my $other_targets_marked_as_bf = 0;
            if (!$marked_as_bf && exists $SSHCure::attacks{$attacker_ip}) {
                for my $target (keys %{$SSHCure::attacks{$attacker_ip}{'targets'}}) {
                    my $target_info = $SSHCure::attacks{$attacker_ip}{'targets'}{$target};
                    if (exists $$target_info{'certainty'} && $$target_info{'certainty'} >= $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}) {                        
                        $other_targets_marked_as_bf = 1;
                        last;
                    }
                }
            }
            
            my $non_aggr_flow_records = [];
            if ($marked_as_bf || $other_targets_marked_as_bf) {
                my $control_f;
                my $compromise_reason = $CFG::CONST{'COMPROMISE_REASON'}{'NO_COMPROMISE'};

                if ($ppf >= $CFG::ALGO{'MINIMAL_SSH_AUTH_PPF'} && SYN($flags)) {
                    # fmap_void shifts parsed_flows, so if (scalar @$parsed_flows == 0), this means that $flow_record is the last one in $parsed_flows
                    my $last_flow_record = (scalar @$parsed_flows == 0) ? $flow_record : @$parsed_flows[-1];

                    $control_f = Future->needs_all(
                        # Retrieve non-aggregated flow data and perform subsequent (dependent) checks
                        get_non_aggr_flow_data($source, $sources_path, $attacker_ip, $atk_port, $target_ip, $ppf, $cusum_mean)->then( sub {
                            $non_aggr_flow_records = shift;

                            # Check for port number reuse
                            my $port_number_reuse = port_number_reuse($non_aggr_flow_records);

                            Future->needs_all(
                                check_login_grace_time(\@cmd_base, $sources_path, $source, $flow_record, $non_aggr_flow_records),
                                check_instant_logout_continue_dictionary($flow_record, $last_flow, $one_but_last_flow, $non_aggr_flow_records, $cusum_mean, \%ppf_histogram, $port_number_reuse),
                                check_maintain_connection_continue_dictionary(\@cmd_base, $sources_path, $source, $flow_record, $first_flow, $last_flow, $one_but_last_flow, $last_flow_record, $highest_duration, $port_number_reuse, $highest_ppf),
                            );
                        }),

                        # Perform checks that don't rely on non-aggregated flow data
                        check_APS_only_flow($flow_record),
                        check_instant_logout_abort_dictionary(\@cmd_base, $sources_path, $source, $flow_record, $last_flow, $cusum_mean, \%ppf_histogram),
                        check_maintain_connection_abort_dictionary(\@cmd_base, $sources_path, $source, $flow_record, $last_flow, $highest_duration, $cusum_mean),
                    )->then(sub {
                        my ($login_grace_time, $instant_logout_continue_dictionary, $maintain_connection_continue_dictionary, $APS_only_flow, $instant_logout_abort_dictionary, $maintain_connection_abort_dictionary) = @_;

                        if ($APS_only_flow && !$login_grace_time) {
                            $compromise_reason = $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION'};
                        } elsif ($maintain_connection_continue_dictionary) {
                            $compromise_reason = $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION_CONTINUE_DICTIONARY'};
                        } elsif ($maintain_connection_abort_dictionary) {
                            $compromise_reason = $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION_ABORT_DICTIONARY'};
                        } elsif ($instant_logout_abort_dictionary) {
                            $compromise_reason = $CFG::CONST{'COMPROMISE_REASON'}{'INSTANT_LOGOUT_ABORT_DICTIONARY'};
                        } elsif ($instant_logout_continue_dictionary) {
                            $compromise_reason = $CFG::CONST{'COMPROMISE_REASON'}{'INSTANT_LOGOUT_CONTINUE_DICTIONARY'};
                        } else {
                            # Do nothing (no compromise)
                        }

                        Future->wrap($non_aggr_flow_records);
                    });
                } else {
                    $control_f = get_non_aggr_flow_data($source, $sources_path, $attacker_ip, $atk_port, $target_ip, $ppf, $cusum_mean);
                }

                $control_f->then( sub {
                    $non_aggr_flow_records = shift;
                    
                    unless ($compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'NO_COMPROMISE'}) { 
                        # In case this tuple was not in the brute-force phase yet, make sure it will
                        unless ($marked_as_bf) {
                            $marked_as_bf = 1;
                            $add_this_tuple = 1;
                            $target{$target_ip}{'first_act'} = $attack_start_time;
                            $target{$target_ip}{'last_act'}  = $fl_etime;
                        }
                        
                        # Split up between potential compromises that have to be checked again in upcoming interval(s), and others
                        my $detection_time = time;
                        my $compromise_info = [ $attacker_ip, \%target, $source, $fl_stime, $fl_etime, $atk_port, $compromise_reason, $detection_time ];
                        if ($compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'INSTANT_LOGOUT_ABORT_DICTIONARY'}
                                || $compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION_ABORT_DICTIONARY'}) {
                            push(@new_potential_compromises_next_interval, $compromise_info);
                        } elsif ($compromise_reason == $CFG::CONST{'COMPROMISE_REASON'}{'MAINTAIN_CONNECTION'}) {
                            push(@new_potential_compromises_next_intervals, $compromise_info);
                        } else {
                            push(@new_potential_compromises, $compromise_info);
                        }
                    }

                    # If PPF != cusum_mean (so in case of a potential block), @$non_aggr_flow_records is always set
                    for my $non_aggr_flow_record (@$non_aggr_flow_records) {
                        my ($ip_version, $fl_stime, $fl_etime, $proto, $attacker_ip, $atk_port, $target_ip, $target_port, $flags, $ppf, $bytes) = @$non_aggr_flow_record;

                        # Check for blocks/rate limiting. AF-only is to avoid removing APS + AF constructions
                        # FIXME - Check '-1' in statement below
                        if ($ppf < $CFG::ALGO{'MINIMAL_SSH_AUTH_PPF'} - 1 && !AF_only($flags)) {
                            $target{$target_ip}{'is_host_blocked'} = $CFG::CONST{'BLOCKED'}{'FAIL2BAN'};
                            $target{$target_ip}{'block_time'} = $fl_stime;

                            my @last_detection_times = ();
                            my @pot_comp_lists = ();

                            # Determine from which array we have to pop a (potential) compromise
                            for my $list (\@new_potential_compromises, \@new_potential_compromises_next_interval, \@new_potential_compromises_next_intervals) {
                                if (scalar @$list > 0) {
                                    my ($last_attacker_ip, $last_target, $source, $last_compromise_time, $last_flow_endtime, $last_compromise_port, $last_compromise_reason, $last_detection_time) = @{@{$list}[-1]};

                                    # Only consider last compromise if it is close (in duration) to the considered (non-aggregated) flow record.
                                    # FIXME Consider: In addition, in case the current record is not the last one, the next flow record should not have $ppf >= $CFG::ALGO{'MINIMAL_SSH_AUTH_PPF'}
                                    if ($fl_stime - $last_compromise_time < 40) {
                                        push(@last_detection_times, $last_detection_time);
                                        push(@pot_comp_lists, $list);
                                    }
                                }
                            }

                            my $max_last_detection_time = max(@last_detection_times);

                            # Remove last added potential compromise from the correct list
                            if ($max_last_detection_time) {
                                foreach my $list (@pot_comp_lists) {
                                    my ($last_attacker_ip, $last_target, $source, $last_compromise_time, $last_flow_endtime, $last_compromise_port, $last_compromise_reason, $last_detection_time) = @{@{$list}[-1]};
                                    if ($last_detection_time == $max_last_detection_time) {
                                        pop(@{$list});
                                        last;
                                    }
                                }
                            }

                            last;
                        } else {
                            # Do nothing
                        }
                    }

                    Future->wrap();
                });
            } else {
                Future->wrap();
            }
        } concurrent => 1, foreach => $parsed_flows)->then( sub {
            # Make a copy of the target hash to avoid problems later...
            my %target_info = %target;
            
            Future->wrap({
                    'attacker_ip'                           => $presel_attacker_ip,
                    'target_ip'                             => $presel_target_ip,
                    'target_info'                           => \%target_info,
                    'add_this_tuple'                        => $add_this_tuple,
                    'potential_compromises'                 => \@new_potential_compromises,
                    'potential_compromises_next_interval'   => \@new_potential_compromises_next_interval,
                    'potential_compromises_next_intervals'  => \@new_potential_compromises_next_intervals,
            });
        });
    } 
} # end of bruteforce_detection_function

sub port_number_reuse {
    my ($non_aggr_flow_records) = @_;

    # If there's only a single flow record available, the port number can never be reused in this set
    return 0 if scalar @$non_aggr_flow_records == 1;

    # Check for port number reuse by checking for the number of flow records having the APS-flags set
    my $records_with_APS = 0;
    for my $non_aggr_flow_record (@$non_aggr_flow_records) {
        my ($ip_version, $t_start, $t_end, $protocol, $s_ip, $s_port, $d_ip, $d_port, $flags, $packets, $bytes) = @$non_aggr_flow_record;
        if (APS($flags)) {
            $records_with_APS++;
        }
    }

    return ($records_with_APS > 1);
}

sub get_non_aggr_flow_data {
    my ($source, $sources_path, $attacker_ip, $attacker_port, $target_ip, $ppf, $cusum_mean) = @_;

    return Future->wrap([]) if ($ppf == $cusum_mean);

    my $cmd = sprintf "-M %s%s -o pipe -Nq ", $sources_path, $source;
    my $cmd_filter = sprintf "proto tcp and src ip %s and src port %i and dst ip %s and dst port in [%s]", dec2ip($attacker_ip), $attacker_port, dec2ip($target_ip), "22";
    my @cmd = (@cmd_base, split(" ", $cmd), $cmd_filter);

    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my @non_aggr_flow_records = split("\n", shift);
        return Future->wrap(parse_nfdump_pipe(\@non_aggr_flow_records));
    });
}

sub add_compromise_port {
    my ($target, $compromise_port) = @_;
    $$target{'compromise_ports'} .= ',' if defined $$target{'compromise_ports'};
    $$target{'compromise_ports'} .= $compromise_port;
}

1;
