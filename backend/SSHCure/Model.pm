######################################################################
#
#  Model.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
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
    set_attacker_blocking_time
);

####################
# Adding attackers
####################

sub add_scan_attacker {
    my ($attacker_ip, $targets) = @_;

    if (exists $SSHCure::attacks{$attacker_ip}) { # Attacker exists
        my $attack = $SSHCure::attacks{$attacker_ip};
        merge_targets($attack, $targets, $CFG::ALGO{'CERT_SCAN'});

        # If the existing attack is not scan, but it was detected without a scan phase earlier on (i.e., certainty is 0.4 or 0.65), add the difference (i.e. 0.10)
        if ($$attack{'certainty'} > $CFG::ALGO{'CERT_SCAN'} && ($$attack{'certainty'} != $CFG::ALGO{'CERT_BRUTEFORCE'} && $$attack{'certainty'} != $CFG::ALGO{'CERT_COMPROMISE'})) {
            $$attack{'certainty'} += ($CFG::ALGO{'CERT_BRUTEFORCE'} - $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'});
        }

        update_attack_target_count($attack);
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'scan');
        update_db($attacker_ip, $attack, $targets);
    } else { # New attacker
        # Check whether attack is inbound or outbound
        my $attack_direction = $CFG::CONST{'ATTACK_DIRECTION'}{'INBOUND'};
        foreach my $network (split(/,/, $CFG::INTERNAL_NETWORKS)) {
            if (ip_addr_in_range($attacker_ip, $network)) {
                $attack_direction = $CFG::CONST{'ATTACK_DIRECTION'}{'OUTBOUND'};
                last;
            }
        }

        # Check whether attacker has been blacklisted by OpenBL
        my $host_blacklisted = host_on_openbl_blacklist($attacker_ip);

        while ((my $target, my $target_info) = each (%$targets)) {
            $target_info->{'certainty'} = $CFG::ALGO{'CERT_SCAN'};
        }

        $SSHCure::attacks{$attacker_ip} = {
            'targets' => $targets,
            'certainty' => $CFG::ALGO{'CERT_SCAN'}
        };

        update_attack_target_count($SSHCure::attacks{$attacker_ip});
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'scan');

        my $new_db_id = update_db($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets, $attack_direction, $host_blacklisted);
        $SSHCure::attacks{$attacker_ip}{'db_id'} = $new_db_id;
    }
    
    notify($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
}

sub add_bf_attacker {
    my ($attacker_ip, $targets) = @_;
    
    if (exists $SSHCure::attacks{$attacker_ip}) { # Attacker exists
        my $attack = $SSHCure::attacks{$attacker_ip};
        if ($$attack{'certainty'} == $CFG::ALGO{'CERT_SCAN'}) {
            # attack is in scan phase, transition to bf phase
            $$attack{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE'};
            $SSHCure::attacks{$attacker_ip}{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE'};
            merge_targets($attack, $targets, $CFG::ALGO{'CERT_BRUTEFORCE'});
        } else {
            if ($$attack{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE'}
                    || $$attack{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}) {
                # Attack in bf, use existing certainty (might be with or without scan)
                merge_targets($attack, $targets, $$attack{'certainty'});
            } elsif ($$attack{'certainty'} == $CFG::ALGO{'CERT_COMPROMISE'}
                    || $$attack{'certainty'} == $CFG::ALGO{'CERT_COMPROMISE_NO_SCAN'}) {
                # Existing attacker, not in scan nor BF phase. Merge targets (merge routine will preserve the certainty, which is in the compromise ranges)
                merge_targets($attack, $targets, $$attack{'certainty'} - $CFG::ALGO{'CERT_COMPROMISE_ADDITION'});
            }
        }
        
        update_attack_target_count($attack);
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'bf');
        update_db($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
    } else { # New attacker: no scan phase detected, so add with lower certainty
        # Check whether attack is inbound or outbound
        my $attack_direction = $CFG::CONST{'ATTACK_DIRECTION'}{'INBOUND'};
        foreach my $network (split(/,/, $CFG::INTERNAL_NETWORKS)) {
            if (ip_addr_in_range($attacker_ip, $network)) {
                $attack_direction = $CFG::CONST{'ATTACK_DIRECTION'}{'OUTBOUND'};
                last;
            }
        }

        # Check whether attacker has been blacklisted by OpenBL
        my $host_blacklisted = host_on_openbl_blacklist($attacker_ip);

        $SSHCure::attacks{$attacker_ip} = {'targets' => $targets, 'certainty' => $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}};
        while ((my $target, my $target_info) = each (%$targets)) {
            $SSHCure::attacks{$attacker_ip}{'targets'}{$target}{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'};
        }
        
        update_attack_target_count($SSHCure::attacks{$attacker_ip});
        update_last_activities($SSHCure::attacks{$attacker_ip}, $targets, 'bf');

        my $new_db_id = update_db($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets, $attack_direction, $host_blacklisted);
        $SSHCure::attacks{$attacker_ip}{'db_id'} = $new_db_id;
    }
    
    notify($attacker_ip, $SSHCure::attacks{$attacker_ip}, $targets);
}

sub add_comp_attacker {
    my ($attacker_ip, $targets) = @_;
    
    if (exists $SSHCure::attacks{$attacker_ip}) {
        my $attack = $SSHCure::attacks{$attacker_ip};

        unless ($$attack{'certainty'} > $CFG::ALGO{'CERT_BRUTEFORCE'}) {
            # attack was already in COMP state, no need to increase the certainty
            $$attack{'certainty'} += $CFG::ALGO{'CERT_COMPROMISE_ADDITION'};
        }
        
        merge_targets($attack, $targets, $$attack{'certainty'});

        update_attack_target_count($attack);
        update_last_activities($attack, $targets, 'comp');
        update_db($attacker_ip, $attack, $targets);
        notify($attacker_ip, $attack, $targets);
    } else {
        log_error("A compromise has been detected without a brute-force phase");
    }
}

####################
# Generic routines
####################

sub get_target_count_for_attack {
    my ($attack) = @_;
    return scalar(keys %{$$attack{'targets'}});
}

sub merge_found_compromised_attackers {
    my %h1 = %{$_[0]};
    my %h2 = %{$_[1]};
    my %merged = ();

    while ((my $k, my $v) = each(%h1)) {
        $merged{$k} = $v;
    }

    while ((my $k ,my $v) = each(%h2)) {
        if(exists $merged{$k}) {
            $merged{$k} = {merge_ips($merged{$k}, $v)};
        } else {
            $merged{$k} = $v;
        }
    }

    return %merged;
}

sub update_attack_target_count {
    my ($attack) = @_;
    $$attack{'target_count'} = get_target_count_for_attack($attack);
}

####################
# Model mutations
####################

sub merge_targets {
    # %{$_[0]} is existing hash
    # %{$_[1]} is hash to merge
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

            # Only adapt target certainty if attack certainty is higher than target certainty
            if ($new_certainty > $_[0]{'targets'}{$target_ip}{'certainty'}) {
                if ($_[0]{'targets'}{$target_ip}{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}) {
                    # Adapt target certainty if attack certainty implies presence of scan (while scan is not present)
                    if ($new_certainty == $CFG::ALGO{'CERT_COMPROMISE'} || $new_certainty == $CFG::ALGO{'CERT_COMPROMISE_NO_SCAN'}) {
                        $_[0]{'targets'}{$target_ip}{'certainty'} = $CFG::ALGO{'CERT_COMPROMISE_NO_SCAN'};
                    } else {
                        # Do nothing
                    }
                } elsif ($_[0]{'targets'}{$target_ip}{'certainty'} == $CFG::ALGO{'CERT_COMPROMISE_NO_SCAN'} && $new_certainty == $CFG::ALGO{'CERT_COMPROMISE'}) {
                    # Do nothing
                } else {
                    $_[0]{'targets'}{$target_ip}{'certainty'} = $new_certainty;
                }
            }
        } else {
            $_[0]{'targets'}{$target_ip} = $target_info;

            # If a target is added with a certainty > 0.4 while it is not present in this hash (else-branch),
            # it means that it was not scanned before. We therefore have to adapt the certainty.
            if ($new_certainty == $CFG::ALGO{'CERT_BRUTEFORCE'}) {
                $_[0]{'targets'}{$target_ip}{'certainty'} = $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'};
            } elsif ($new_certainty == $CFG::ALGO{'CERT_COMPROMISE'}) {
                $_[0]{'targets'}{$target_ip}{'certainty'} = $CFG::ALGO{'CERT_COMPROMISE_NO_SCAN'};
            } else {
                $_[0]{'targets'}{$target_ip}{'certainty'} = $new_certainty;
            }
        }
    }
}

sub merge_compromise_ports {
    my ($existing, $new) = @_;

    return $existing unless defined $new;
    return $new unless defined $existing;

    my $combined = $existing . "," . $new;
    
    # Remove port duplicates
    my %unique = map {$_, 1} split(/,/, $combined);
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
    my ($attack, $targets, $phase) = @_;

    $$attack{'start_time'} = time unless exists $$attack{'start_time'};
    $$attack{'end_time'} = 0 unless exists $$attack{'end_time'};

    while ((my $target, my $target_info) = each (%$targets)) {
        if (exists $$attack{'targets'}{$target}{'last_act_' . $phase}) {
            $$attack{'targets'}{$target}{'last_act_'.$phase} = $$target_info{'last_act'} if $$target_info{'last_act'} > $$attack{'targets'}{$target}{'last_act_'.$phase};
        } else {
            $$attack{'targets'}{$target}{'last_act_'.$phase} = $$target_info{'last_act'};
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

sub update_db ($$$;$$) {
    my ($attacker_ip, $attack_info, $targets, $attack_direction, $attacker_blacklisted) = @_;
    my ($db_id, $query);

    if (exists $$attack_info{'db_id'}) {
        # Attack already in DB, use UPDATE for attack table
        $db_id = $$attack_info{'db_id'};
        $query = "  UPDATE attack
                    SET start_time      = ?,
                        certainty       = ?,
                        attacker_ip     = ?,
                        target_count    = ?
                    WHERE id = '$db_id'";

        my $sth_attack = $SSHCure::DBH->prepare($query);
        $sth_attack->execute($$attack_info{'start_time'}, $$attack_info{'certainty'}, $attacker_ip, $$attack_info{'target_count'});
    } else {
        # Attack is new in DB
        $query = "  INSERT INTO attack
                        (start_time, certainty, direction, attacker_ip, target_count, attacker_blacklisted)
                    VALUES (?, ?, ?, ?, ?, ?)";

        # 'attack_direction' and 'attacker_blacklisted' are optional function arguments that only need to be set for new attacks. 
        if (! defined $attack_direction) {
            log_error("New attack to be inserted in DB without 'attack_direction' being set");
            $attack_direction = $CFG::CONST{'ATTACK_DIRECTION'}{'INBOUND'};
        }
        if (! defined $attacker_blacklisted) {
            log_error("New attack to be inserted in DB without 'attacker_blacklisted' being set");
            $attacker_blacklisted = 0;
        }

        my $sth_attack = $SSHCure::DBH->prepare($query);
        $sth_attack->execute($$attack_info{'start_time'}, $$attack_info{'certainty'}, $attack_direction, $attacker_ip, $$attack_info{'target_count'}, $attacker_blacklisted);
    }
    
    # get last_inserted_id and overwrite if needed
    $db_id ||= $SSHCure::DBH->last_insert_id("", "", "attack", "");

    # Only store scan phase targets if enabled in config
    unless ($$attack_info{'certainty'} <= $CFG::ALGO{'CERT_SCAN'} && $CFG::STORE_SCAN_TARGETS == 0) {
        # Update table 'target'
        my $sql_target = "  INSERT OR REPLACE INTO target
                                (attack_id, target_ip, certainty, last_scan_activity, last_bruteforce_activity,
                                last_compromise_activity, is_host_blocked, compromise_ports, compromise_reason)
                            VALUES ('$db_id', ?, ?, ?, ?, ?, ?, ?, ?)";

        my $sth_target = $SSHCure::DBH->prepare($sql_target);

        $SSHCure::DBH->begin_work;
        while ((my $target_ip, my $target_info) = each (%$targets)) {
            $target_info = $$attack_info{'targets'}{$target_ip};

            my $is_host_blocked;
            if (exists $$target_info{'is_host_blocked'}) {
                $is_host_blocked = $$target_info{'is_host_blocked'};
            } else {
                $is_host_blocked = 0;
            }

            my $compromise_reason;
            if (exists $$target_info{'compromise_reason'}) {
                $compromise_reason = $$target_info{'compromise_reason'};
            } else {
                $compromise_reason = 0;
            }

            $sth_target->execute($target_ip, 
                    $$target_info{'certainty'},
                    $$target_info{'last_act_scan'},
                    $$target_info{'last_act_bf'},
                    $$target_info{'last_act_comp'},
                    $is_host_blocked,
                    $$target_info{'compromise_ports'},
                    $compromise_reason
            );
        }
        $SSHCure::DBH->commit;
    }
    return $db_id;
}

sub mark_attack_done_in_db {
    my ($attack_id, $timestamp) = @_;

    my $sql = "UPDATE attack SET end_time = ?  WHERE id = ?";
    my $sth = $SSHCure::DBH->prepare($sql);
    $sth->execute($timestamp, $attack_id);
}

sub set_attacker_blocking_time {
    my ($attacker_ip, $blocking_time) = @_;
    my $attack_id = $SSHCure::attacks{$attacker_ip}{'db_id'};

    $SSHCure::attacks{$attacker_ip}{'blocking_time'} = $blocking_time;

    my $sql = "UPDATE attack SET blocking_time = ? WHERE id = ?";
    my $sth = $SSHCure::DBH->prepare($sql);
    $sth->execute($blocking_time, $attack_id);
}

1;
