######################################################################
#
#  Notifications.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::Notifications;

use warnings;
use strict;

use SSHCure::Notifications::Email;
use SSHCure::Notifications::Log;
use SSHCure::Notifications::Qmanage;
use SSHCure::Utils;

use Exporter;
our @ISA = 'Exporter';

our @EXPORT = qw (
    notify
);

my $notifications_this_run = 0;
my %notifications_per_config = ();
sub notify {
    # $done is 1 when notify is called from SSHCure::Model::remove_timeouts
    my ($attacker_ip, $attack, $new_targets, $done) = @_;
    if ($notifications_this_run >= $CFG::CONST{'NOTIFICATIONS'}{'LIMITS'}{'MAX_OVERALL'}
            && $CFG::CONST{'NOTIFICATIONS'}{'LIMITS'}{'MAX_OVERALL'} > 0) {
        log_warning("Overall notification limit ($CFG::CONST{'NOTIFICATIONS'}{'LIMITS'}{'MAX_OVERALL'}) reached; skipping any further notification triggers...");
        return;
    }

    while (my ($notification_id, $config) = each(%CFG::NOTIFICATIONS)) {
        #debug "[NOTIFICATIONS] using config $config_name";
        $notifications_per_config{$notification_id} or $notifications_per_config{$notification_id} = 0;
        
        next if ((not defined $done) && $$config{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_END'});
        next if ((defined $done) && $$config{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_START'});
        
        if ($notifications_per_config{$notification_id} >= $CFG::CONST{'NOTIFICATIONS'}{'LIMITS'}{'MAX_PER_CONFIG'}
                && $CFG::CONST{'NOTIFICATIONS'}{'LIMITS'}{'MAX_OVERALL'} > 0) {
            log_warning("Notification limit ($CFG::CONST{'NOTIFICATIONS'}{'LIMITS'}{'MAX_PER_CONFIG'}) reached for config '$notification_id'; skipping any further notification triggers...");
            next;
        }
        if ($$config{'filter_type'} eq $CFG::CONST{'NOTIFICATIONS'}{'FILTER_TYPE'}{'ATTACKER'}) {
            # Filter on Attacker
            if ($$attack{'certainty'} >= $$config{'attack_phase'}) {
                # Phase minimum matched
                # Now, check if there is a matching IP/prefix
                foreach my $ip_range (split(/,/ ,$$config{'filter'})) {
                    if (ip_addr_in_range($attacker_ip, $ip_range)) {
                        # Don't send a notification for ATTACK_START if it has been sent before
                        unless ($$config{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_START'}
                                    && exists $$attack{"notification_sent_$notification_id"}
                                    && $$attack{"notification_sent_$notification_id"} == 1) {
                            my $notification_type = $$config{'notification_type'};
                            "SSHCure::Notifications::$notification_type"->handle_notification($attacker_ip, \%{$attack}, $new_targets, $notification_id); 
                            $notifications_this_run++;
                            $notifications_per_config{$notification_id}++;
                            
                            # Store the name of the config, so other notifcation configs can still be triggered
                            $$attack{"notification_sent_$notification_id"} = 1;
                        }
                        last;
                    } else {
                        #debug "[NOTIFICATIONS] $ip_range does not contain $attacker_ip";
                    }
                }
            }
        } elsif ($$config{'filter_type'} eq $CFG::CONST{'NOTIFICATIONS'}{'FILTER_TYPE'}{'TARGET'}) {
             if ($$attack{'certainty'} >= $$config{'attack_phase'}) {
                 # Phase minimum matched. A target can not have a higher certainty
                 # than the attack, so this check functions as a filter
                TARGETWHILE: while (my ($target_ip, $target_info) = each(%$new_targets)) {
                    # Check whether the phase matches, else next
                    next if ($$attack{'targets'}{$target_ip}{'certainty'} < $$config{'attack_phase'});
                    
                    # Check the actual IP/prefix filter
                    foreach my $ip_range (split(/,/ ,$$config{'filter'})) {
                        #debug "[NOTIFICATIONS] in foreach, checking for $ip_range";
                        if (ip_addr_in_range($target_ip, $ip_range)) {
                            #debug sprintf "[NOTIFICATIONS] matching ip (TARGET) found, %s is in %s", dec2ip($target_ip), $ip_range;
                            my $persistent_target_info = $$attack{'targets'}{$target_ip};
                            
                            # Don't send a notification for ATTACK_START if it has been sent before
                            unless ($$config{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_START'}
                                    && exists $$persistent_target_info{"notification_sent_$notification_id"}
                                    && $$persistent_target_info{"notification_sent_$notification_id"} == 1) {

                                my $notification_type = $$config{'notification_type'};
                                "SSHCure::Notifications::$notification_type"->handle_notification(
                                        $attacker_ip, $attack, $new_targets, $notification_id);
                                $notifications_this_run++;
                                $notifications_per_config{$notification_id}++;
                                
                                # Store the name of the config, so other notifcation configs can still be triggered
                                $$persistent_target_info{"notification_sent_$notification_id"} = 1;
                                last TARGETWHILE;
                            }
                        }
                    }
                }
            }
        } else {
            log_error("Unknown filter_type specified for notification config '$notification_id'");
        }
    }
}

1;
