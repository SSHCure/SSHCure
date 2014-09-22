######################################################################
#
#  Compromise.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Compromise;
use strict;
use warnings;

use SSHCure::Utils;
use SSHCure::Utils::Nfdump;
use SSHCure::Model;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(compromise_detection); 

# NB this subroutine depends on the format of the nfdump (parsed) output!
sub check_parsed_for_compromised_phase_attackers {
    my $parsed = shift;
    my $bare_cmd = shift;
    my %result = ();

    #check every entry for some characteristics
    my %cache = ();
    foreach my $entry (@$parsed) {
        # 'compromised' traffic can occur in both directions
        #my ($flows, $packets, $ip_a, $ip_b, $bytes, $time) = @{$entry};
        #my $bpf = ($flows > 0) ? $bytes/$flows : 0;
        #my $ppf = ($flows > 0) ? $packets/$flows : 0;

        my ($flows, $packets, $ip_a, $ip_t, $bytes, $time) = @{$entry};
        $ip_a = ip2dec($ip_a);
        $ip_t = ip2dec($ip_t);

        my $fail2ban_cmd = $bare_cmd  . " -o long -Nq 'proto tcp and dst port 22 and flags S and not flags A and ip %s and ip %s and packets < 4'";

        my %targets_for_bf_attacker;
        if (!exists $cache{$ip_a}) {
            debug "no cached bf targets for $ip_a, constructing...";
            while ( my ($target_ip, $target_info) = (each %{$SSHCure::attacks{$ip_a}->{'targets'}}) ) {
                if ($$target_info{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE'} || $$target_info{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}) {
                    $targets_for_bf_attacker{$target_ip} = $target_info;
                    #print "adding target $target_ip for bf attacker $ip_a, target cert: $$target_info{'certainty'}\n";
                }
            }
            $cache{$ip_a} = \%targets_for_bf_attacker;
            #debug "construction done, total cache: " . Dumper(\%cache);
        } else {
            %targets_for_bf_attacker = %{$cache{$ip_a}};
            #debug "cache: " . Dumper(\%cache);
            #debug "got bf targets for $ip_a from cache: " . Dumper(\%targets_for_bf_attacker);
        }
        #print "in check for comp, targets_for_bf_attacker{ip_t}: " . Dumper($targets_for_bf_attacker{$ip_t});
        if (!exists $targets_for_bf_attacker{$ip_t}{'cusum'}) {
            debug "[CUSUM] no cusum field for target $ip_t !";
        }
        #print debug "post construction of bf target hash, targets: " . (keys %targets_for_bf_attacker);
        #if($packets > $CFG::ALGO{'BRUTEFORCE_PHASE_MAX_PPF'} || $packets < $CFG::ALGO{'BRUTEFORCE_PHASE_MIN_PPF'}) {
        if (abs($packets - $targets_for_bf_attacker{$ip_t}{'bf_cusum'}) > 2 ) {
            #debug "COMP: \$packets drop/peak ($ip_a -> $ip_t)";
            #my $delta = 0;
            my $delta = abs($packets - $targets_for_bf_attacker{$ip_t}{'bf_cusum'});
            debug "delta from bf_cusum: $delta";
            #if($packets < $CFG::ALGO{'BRUTEFORCE_PHASE_MIN_PPF'}) {
            #    # drop
            #    #$delta = $CFG::ALGO{'BRUTEFORCE_PHASE_MIN_PPF'} - $packets;
            #    #debug "COMP: \$packets drop, \$delta = $delta";
            #}else{
            #    # peak
            #    #$delta = $packets - $CFG::ALGO{'BRUTEFORCE_PHASE_MAX_PPF'};
            #    #debug "COMP: \$packets peak, \$delta = $delta";
            #}
            #$SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum'} += $delta;
            #$SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum_count'} += 1;
                                    
            $targets_for_bf_attacker{$ip_t}{'cusum'} += $delta;
            $targets_for_bf_attacker{$ip_t}{'cusum_count'} += 1;

            # CHeck cusum > treshold?
            #if ($SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum'} > $CFG::ALGO{'COMPROMISE_CUSUM_TRESHOLD'} 
            #    && $SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum_count'} > $CFG::ALGO{'COMPROMISE_CUSUM_COUNT_TRESHOLD'} ) {
            if ($targets_for_bf_attacker{$ip_t}->{'cusum'} > $CFG::ALGO{'COMPROMISE_CUSUM_TRESHOLD'} 
                && $targets_for_bf_attacker{$ip_t}->{'cusum_count'} > $CFG::ALGO{'COMPROMISE_CUSUM_COUNT_TRESHOLD'}) {
                 # check for fail2ban characteristics
                 $fail2ban_cmd = sprintf($fail2ban_cmd, dec2ip($ip_a), dec2ip($ip_t));
                 my @result = qx($fail2ban_cmd);
               
                 if(scalar (@result) > 0) {
                    # there were flows with only SYN-flags
                    debug "fail2ban like traffic detected, not adding atttacker $ip_a, target $ip_t";
                    #$bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_b}->{'fail2ban'} = 1;
                    $SSHCure::attacks{$ip_a}{'targets'}{$ip_t}{'fail2ban'} = 1;
                    update_db($ip_a, $SSHCure::attacks{$ip_a}, { $ip_t => $SSHCure::attacks{$ip_a}{'targets'}{$ip_t} });
                 } else {
                    # Compromise detected, add to results
                    #debug "COMP: cusum > treshold (".$SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum'}."), adding compromise ($ip_a -> $ip_t)";
                    debug sprintf "compromise detected: attacker %s, target %s", dec2ip($ip_a), dec2ip($ip_t);
                    $result{$ip_a} = {} if (!exists $result{$ip_a});
                    $result{$ip_a}->{$ip_t}->{'last_act'} = nfdumptime2unix($time);
                }
            }

        #}elsif($SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum'} > 0) {
        }elsif($targets_for_bf_attacker{$ip_t}{'cusum'} > 0) {
            # cusum resetten?
            #debug "COMP: \$packets ($packets) within margin, resetting cusum ($ip_a -> $ip_t)";
            #$SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum'} = 0;
            #$SSHCure::bruteforce_phase_attackers{$ip_a}{'targets'}->{$ip_t}->{'cusum_count'} = 0;
            $targets_for_bf_attacker{$ip_t}->{'cusum'} = 0;
            $targets_for_bf_attacker{$ip_t}->{'cusum_count'} = 0;
        }


    }
    return %result;
}

# NB this subroutine depends on the format of the nfdump (parsed) output!
sub check_parsed_for_active_compromised_phase_attackers {
    my $parsed = shift;
    my %result = ();
    #check every entry for some characteristics
    foreach my $entry (@$parsed) {
        my ($flows, $packets, $ip_a, $ip_b, $bytes, $time) = @{$entry};
        my $bpf = ($flows > 0) ? $bytes/$flows : 0;
        my $ppf = ($flows > 0) ? $packets/$flows : 0;

        $ip_a = ip2dec($ip_a);
        $ip_b = ip2dec($ip_b);

        if (exists $SSHCure::compromised_phase_attackers{$ip_a}) {
            # ip_a is the attacker
            $result{$ip_a} = {} if (!exists $result{$ip_a});
            $result{$ip_a}->{$ip_b}->{'last_act'} = nfdumptime2unix($time);
        } elsif (exists $SSHCure::compromised_phase_attackers{$ip_b}) {
            # ip_b is the attacker
            $result{$ip_b} = {} if (!exists $result{$ip_b});
            $result{$ip_b}->{$ip_a}->{'last_act'} = nfdumptime2unix($time);
        }
    }
    return %result;
}


sub compromise_detection {
    my ($netflow_sources, $timeslot, $timeslot_interval, $timeslot_intervals) = @_;
    my $fmt = "'fmt:%fl|%pkt|%sa|%da|%byt|%ts'";

    #foreach iterate over bf_phase_attackers as $bf_phase_attacker and bf_phase_targets
    my %compromised_attackers = ();

    while (my ($attacker_ip, $attack_info) = each (%SSHCure::attacks)) {
        next unless $$attack_info{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE'} || $$attack_info{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'};
        debug "in while checking for comps, attack certainty $$attack_info{'certainty'}";
        my @bf_phase_target_ips;
        while ( my ($target_ip, $target_info) = (each %{$$attack_info{'targets'}}) ) {
            push @bf_phase_target_ips, $target_ip if $$target_info{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE'} || $$target_info{'certainty'} == $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'};
        }
        my $query_ips = targets2or_query(\@bf_phase_target_ips);
        my $nfdump_filter = "proto tcp and port 22 and src ip " . dec2ip($attacker_ip) . " and $query_ips and (packets > 2) and not (packets 1 and flags F)";
        my $bare_cmd = "$NfConf::PREFIX/nfdump -6 -M $netflow_sources -r nfcapd.$timeslot -t $timeslot_interval ";
        my $cmd = $bare_cmd . " -o $fmt -Nq '$nfdump_filter'";
        my @nfdump_output = qx($cmd); # or debug "[COMP] what did go wrong?";i # when nfdump returns no flow records, the qx will evaluate to false triggering the 'or' clause to be evaluated and thus the debug routine to be called. However, an empty result from nfdump is perfectly valid. TODO make something nicer, i.e. only log when the nfdump query was really erroneous. 

        my @result = parse_nfdump_list(\@nfdump_output);
        $bare_cmd = "$NfConf::PREFIX/nfdump -6 -M $netflow_sources -r nfcapd.$timeslot ";
        my %new_compromised_attackers = check_parsed_for_compromised_phase_attackers(\@result, $bare_cmd);
        if (keys %new_compromised_attackers > 0) {
          %compromised_attackers = merge_found_compromised_attackers(\%compromised_attackers, \%new_compromised_attackers);
        }
    }

    $SSHCure::PHASE = "A-COMP";

    $fmt = "'fmt:%fl|%pkt|%sa|%da|%byt|%te'";
    # check existing compromised attackers/targets: is there still traffic between them?
    my %active_compromised_attackers = ();

    while (my ($attacker, $targets) = each(%compromised_attackers)) {
        add_comp_attacker($attacker, $targets);
    }

    while (my ($attacker, $targets) = each(%active_compromised_attackers)) {
        add_comp_attacker($attacker, $targets);
    }


}

1;
