######################################################################
#
#  Model.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Model;
use strict;
use warnings;

use SSHCure::Notifications;
use SSHCure::Utils;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    add_scan_attacker
    add_bf_attacker
    add_comp_attacker
    remove_timeouts
    merge_found_compromised_attackers
    update_db
    set_attacker_blocking_time
    untargetize_attack
);

####################
# Adding attackers
####################

sub add_scan_attacker {
    my $attacker_ip = shift;
    my $targets = shift;

    if (exists $SSHCure::attacks{$attacker_ip}) {
        # attacker exists
        my $existing_attack = $SSHCure::attacks{$attacker_ip};
        merge_targets($existing_attack, $targets, $CFG::ALGO{'CERT_SCAN'});

        # If the existing attack is not scan, but it was detected without a scan phase earlier on (i.e., certainty is 0.4 or 0.65), add the difference (i.e. 0.10)
        if ($$existing_attack{'certainty'} > $CFG::ALGO{'CERT_SCAN'} && ($$existing_attack{'certainty'} != $CFG::ALGO{'CERT_BRUTEFORCE'} && $$existing_attack{'certainty'} != $CFG::ALGO{'CERT_COMPROMISE'})) {
            $$existing_attack{'certainty'} += ($CFG::ALGO{'CERT_BRUTEFORCE'} - $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'});
        }

        update_attack_details($existing_attack);
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'scan');
        update_db($attacker_ip, $existing_attack, $targets);
    } else {
        # new attacker
        while ((my $target, my $target_info) = each (%$targets)) {
            $target_info->{'certainty'} = $CFG::ALGO{'CERT_SCAN'};
        }

        $SSHCure::attacks{$attacker_ip} = {'targets' => $targets, 'certainty' => $CFG::ALGO{'CERT_SCAN'}};
        update_attack_details($SSHCure::attacks{$attacker_ip});
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'scan');
        my $new_db_id = update_db($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
        $SSHCure::attacks{$attacker_ip}{'db_id'} = $new_db_id;
    }
    
    notify($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
}

sub add_bf_attacker {
    my $attacker_ip = shift;
    my $targets = shift;
    
    if (exists $SSHCure::attacks{$attacker_ip}) {
        # Attacker exists
        my $existing_attack = $SSHCure::attacks{$attacker_ip};
        if ($$existing_attack{'certainty'} == $CFG::ALGO{'CERT_SCAN'}) {
            # attack is in scan phase, transition to bf phase
            $$existing_attack{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE'};
            $SSHCure::attacks{$attacker_ip}{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE'};
            merge_targets($existing_attack, $targets, $CFG::ALGO{'CERT_BRUTEFORCE'});
        } else {
            if ($$existing_attack{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE'}
                    || $$existing_attack{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}) {
                # Attack in bf, use existing certainty (might be with or without scan)
                merge_targets($existing_attack, $targets, $$existing_attack{'certainty'});
            } elsif ($$existing_attack{'certainty'} == $CFG::ALGO{'CERT_COMPROMISE'}
                    || $$existing_attack{'certainty'} == $CFG::ALGO{'CERT_COMPROMISE_NO_SCAN'}) {
                # Existing attacker, not in scan nor BF phase. Merge targets (merge routine will preserve the certainty, which is in the compromise ranges)
                merge_targets($existing_attack, $targets, $$existing_attack{'certainty'} - $CFG::ALGO{'CERT_COMPROMISE_ADDITION'});
            }
        }
        
        update_attack_details($existing_attack);
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'bf');
        update_db($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
    } else {    
        # New attacker: no scan phase detected, so add with lower certainty
        $SSHCure::attacks{$attacker_ip} = {'targets' => $targets, 'certainty' => $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}};
        while ((my $target, my $target_info) = each (%$targets)) {
            $SSHCure::attacks{$attacker_ip}{'targets'}{$target}{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'};
        }
        
        update_attack_details($SSHCure::attacks{$attacker_ip});
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'bf');
        my $new_db_id = update_db($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
        $SSHCure::attacks{$attacker_ip}{'db_id'} = $new_db_id;
    }
    
    notify($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
}

sub add_comp_attacker {
    my ($attacker_ip, $targets, $attack_tool) = @_;
    
    if (exists $SSHCure::attacks{$attacker_ip}) {
        # Attacker exists, like it must
        my $existing_attack = $SSHCure::attacks{$attacker_ip};
        if (not exists $$existing_attack{'attack_tool_name'}) {
            debug sprintf "[FINGERPRINT] setting attack_tool_name to %s (attacker: %s)", $attack_tool, dec2ip($attacker_ip);
        } elsif ($$existing_attack{'attack_tool_name'} eq $attack_tool) {
            debug sprintf "[FINGERPRINT] setting attack_tool_name to %s (attacker: %s)", $attack_tool, dec2ip($attacker_ip);
        } else {
            debug sprintf "[FINGERPRINT] different attack_tool_name for existing attack: old: %s vs new: %s (attacker: %s)",
                    $$existing_attack{'attack_tool_name'}, $attack_tool, dec2ip($attacker_ip);
        }
        $$existing_attack{'attack_tool_name'} = $attack_tool if defined $attack_tool;

        unless ($$existing_attack{'certainty'} > $CFG::ALGO{'CERT_BRUTEFORCE'}) {
            # attack was already in COMP state, no need to increase the certainty
            $$existing_attack{'certainty'} += $CFG::ALGO{'CERT_COMPROMISE_ADDITION'};
        }
        
        update_attack_details($existing_attack);
        merge_targets($existing_attack, $targets, $$existing_attack{'certainty'});

        update_last_activities($existing_attack, $targets, 'comp');
        update_db($attacker_ip, $existing_attack, $targets);
        notify($attacker_ip, $existing_attack, $targets);
    } else {
        # error, the bruteforce phase must have been detected
        log_error "Something went wrong, a compromise has been detected without a brute-force phase";
    }
}

####################
# Generic routines
####################

sub get_target_count_for_attack {
    my $attack = $_[0];
    return scalar (keys %{$$attack{'targets'}});
}

sub update_attack_details {
    my $attack = $_[0];
    $$attack{'target_count'} = get_target_count_for_attack($attack);
}

sub merge_found_compromised_attackers {
    my %h1 = %{$_[0]};
    my %h2 = %{$_[1]};
    my %merged = ();

    while ((my $k,my $v) = each(%h1) ) {
        $merged{$k} = $v;
    }

    while ((my $k,my $v) = each(%h2) ) {
        if(exists $merged{$k}) {
            $merged{$k} = {merge_ips($merged{$k}, $v)};
        } else {
            $merged{$k} = $v;
        }

    }
    return %merged;
}

####################
# Model mutations
####################

sub merge_targets {
    # %{$_[0]} is existing hash
    # %{$_[1]} is new, to merge
    my $new_certainty = $_[2];

    # It seems that 'merging' a single target with itself (i.e., updating it) can result in bogus attack start times.
    # This happens when there is only a single target for the attack, the attack time was set to time T, the target is again detected
    # and the target last_act is updated BUT the attack's start time is not.

    while ((my $target_ip, my $target_info) = each(%{$_[1]})) {
        if (exists $_[0]{'targets'}{$target_ip}) {
            my $existing_target_info = $_[0]{'targets'}{$target_ip};
            while ((my $k, my $v) = each (%{$target_info})) {
                if (exists ($$existing_target_info{$k})) {
                    if ($k =~ /last_act_.*/) {
                        $existing_target_info->{$k} = $v if $v > $existing_target_info->{$k};
                    } elsif (not $k eq "certainty") {
                        if ($k eq "compromise_ports") {
                            $$existing_target_info{$k} = merge_compromise_ports($$existing_target_info{$k}, $v);
                        } else {
                            $$existing_target_info{$k} = $v;
                        }
                    }
                } else {
                    $existing_target_info->{$k} = $v;
                }
            }
            if (!exists $_[0]{'targets'}{$target_ip}{'certainty'} || $new_certainty > $_[0]{'targets'}{$target_ip}{'certainty'}) {
                $_[0]{'targets'}{$target_ip}{'certainty'} = $new_certainty;
            }
        } else {
            $_[0]{'targets'}{$target_ip} = $target_info; 
            $_[0]{'targets'}{$target_ip}{'certainty'} = $new_certainty;
        }
    }
}

sub merge_compromise_ports {
    my ($existing, $new) = @_;
    return $existing unless defined $new;
    return $new unless defined $existing;
    my $combined = $existing . "," . $new;
    
    # Remove duplicate ports
    my %unique = map { $_, 1} split(/,/ , $combined);
    return join(',' , keys %unique);
}

sub remove_timeouts {
    # $_[0] is \%SSHCure::attacks
    # $_[1] might be $time_now_hack
    my $current_time = time;
    $current_time = $_[1] if $_[1];

    while ((my $attacker_ip, my $attack_info) = each (%{$_[0]})) {
        my $first_activity = $$attack_info{'start_time'};
        my $last_activity = $$attack_info{'end_time'};
        if (($current_time - $last_activity > $CFG::ALGO{'ATTACK_IDLE_TIMEOUT'})
                || ($current_time - $first_activity > $CFG::ALGO{'ATTACK_ACTIVE_TIMEOUT'})) {
            notify($attacker_ip, $attack_info, $$attack_info{'targets'}, 1); # last param 1 -> $done
            delete $_[0]{$attacker_ip};

            mark_attack_done_in_db($$attack_info{'db_id'}, $last_activity);
        } 
    }
}

sub update_last_activities {
    my $attack = $_[0];
    my $targets = $_[1];
    my $phase = $_[2];

    $$attack{'start_time'} = time unless exists $$attack{'start_time'};
    $$attack{'end_time'} = 0 unless exists $$attack{'end_time'};
    while ((my $target, my $target_info) = each (%$targets)) {
        if (!exists $$attack{'targets'}{$target}{'last_act_' . $phase}) {
            $$attack{'targets'}{$target}{'last_act_' . $phase} = $$target_info{'last_act'};
        } else {
            $$attack{'targets'}{$target}{'last_act_' . $phase} = $$target_info{'last_act'} if $$target_info{'last_act'} > $$attack{'targets'}{$target}{'last_act_' . $phase};
        }
        $$attack{'end_time'} = $$target_info{'last_act'} if $$target_info{'last_act'} > $$attack{'end_time'};
        
        if (exists $$target_info{'first_act'}) {
            $$attack{'start_time'} = $$target_info{'first_act'} if $$target_info{'first_act'} < $$attack{'start_time'};
        } else {
            $$attack{'start_time'} = $$target_info{'last_act'} if $$target_info{'last_act'} < $$attack{'start_time'};
        }
    }
}

####################
# Database routines
####################

sub update_db {
    my $attacker_ip = $_[0];
    my %attack_info = %{$_[1]};
    my %targets = %{$_[2]};

    my $db_id;
    my $sql_attack;

    if (exists $attack_info{'db_id'}) {
        # Attack already in DB, use UPDATE for attack table
        $db_id = $attack_info{'db_id'};
        $sql_attack = " UPDATE attack
                        SET start_time      = ?,
                            certainty       = ?,
                            attacker_ip     = ?,
                            target_count    = ?,
                            attack_tool_name= ?
                        WHERE id = '$db_id'";
    } else {
        # Attack is new in DB.
        $sql_attack = " INSERT INTO attack
                            (start_time, certainty, attacker_ip, target_count, attack_tool_name)
                        VALUES (?, ?, ?, ?, ?)";
    }
    
    my $attack_tool_name = '';
    $attack_tool_name = $attack_info{'attack_tool_name'} if exists $attack_info{'attack_tool_name'};
    
    my $sth_attack = $SSHCure::DBH->prepare($sql_attack);
    $sth_attack->execute($attack_info{'start_time'}, $attack_info{'certainty'}, $attacker_ip, $attack_info{'target_count'}, $attack_tool_name) or debug "[MODEL] Oops! $SSHCure::DBI::errstr\nQuery was $sql_attack";
    
    # get last_inserted_id and overwrite if needed
    $db_id ||= $SSHCure::DBH->last_insert_id("", "", "attack", "");

    # Only store scan phase targets if enabled in config
    unless ($attack_info{'certainty'} <= $CFG::ALGO{'CERT_SCAN'} && $CFG::STORE_SCAN_TARGETS == 0) {
        # update victims table
        my $sql_target = "  INSERT OR REPLACE INTO target
                                (attack_id, target_ip, certainty, last_scan_activity, last_bruteforce_activity,
                                last_compromise_activity, is_host_blocked, compromise_ports)
                            VALUES ('$db_id', ?, ?, ?, ?, ?, ?, ?)";

        my $sth_target = $SSHCure::DBH->prepare($sql_target);

        $SSHCure::DBH->begin_work;
        while ((my $target_ip, my $target_info) = each (%targets)) {
            $target_info = $attack_info{'targets'}{$target_ip};
            my $is_host_blocked = 0;
            $is_host_blocked = $$target_info{'is_host_blocked'} if exists $$target_info{'is_host_blocked'};
            $sth_target->execute($target_ip, $$target_info{'certainty'},
                                    $$target_info{'last_act_scan'},
                                    $$target_info{'last_act_bf'},
                                    $$target_info{'last_act_comp'},
                                    $is_host_blocked,
                                    $$target_info{'compromise_ports'}) or debug "[MODEL] tried to REPLACE target, certainty: $$target_info{'certainty'} , while attack's certainty: $attack_info{'certainty'}";
        }
        $SSHCure::DBH->commit;
    }
    return $db_id;
}

sub mark_attack_done_in_db {
    my $atk_id = (shift);
    my $timestamp = (shift);
    my $sql = "UPDATE attack SET end_time = ?  WHERE id = ?";
    my $sth = $SSHCure::DBH->prepare($sql) or debug("[MODEL] [SQL] [mark_attack_done] prepare failed: $sql");
    $sth->execute($timestamp, $atk_id);
}

sub set_attacker_blocking_time {
    my ($attacker_ip, $blocking_time) = @_;
    my $atk_id = $SSHCure::attacks{$attacker_ip}{'db_id'};
    $SSHCure::attacks{$attacker_ip}{'blocking_time'} = $blocking_time;
    my $sql = "UPDATE attack SET blocking_time = ? WHERE id = ?";
    my $sth = $SSHCure::DBH->prepare($sql) or debug("[MODEL] [SQL] [set_attacker_blocking_time] prepare failed: $sql");
    $sth->execute($blocking_time, $atk_id);
}

#######################
# Development routines
#######################

sub untargetize_attack {
    my %attack = %{$_[0]};
    $attack{'targets'} = undef;

    return \%attack;
}

sub format_attacks {
    my $attacks = $_[0];
    my @output = ("Attacks:");

    while ((my $attacker_ip, my $attack_info) = each (%$attacks)) {
        my $cert = $$attack_info{'certainty'};
        my $target_count = $$attack_info{'target_count'};
        my $starttime = $$attack_info{'start_time'};
        my $endtime = $$attack_info{'end_time'};
        push(@output, sprintf("%-20s %-10.2f %-10d %-10.3f %-10.3f", $attacker_ip, $cert, $target_count, $starttime, $endtime));
    }
    return join("\n", @output) . "\n";
}

sub check_last_act_from_targets {
    my $attack = (shift);
    my %targets = %{$$attack{'targets'}};
    my @act_times = ();
    while ((my $target, my $target_info) = each (%targets)) {
        push(@act_times, scalar $$target_info{'last_act_scan'}) if exists $$target_info{'last_act_scan'};
        push(@act_times, scalar $$target_info{'last_act_bf'}) if exists $$target_info{'last_act_bf'};
        push(@act_times, scalar $$target_info{'last_act_comp'}) if exists $$target_info{'last_act_comp'};
    }
    return if scalar @act_times == 0;
    
    @act_times = sort @act_times;
    my $last_act = $act_times[-1];
    debug "[ST] Attack end time vs targets' activities: $$attack{'end_time'} - $last_act = " . ($$attack{'end_time'} - $last_act);
}

1;
