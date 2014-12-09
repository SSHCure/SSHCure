######################################################################
#
#  Notifications::Email.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::Notifications::Email;
use strict;
use warnings;

use MIME::Lite;
use POSIX qw(strftime);
use SSHCure::Utils;

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;
    
    # Convert IP number to address
    $attacker_ip = dec2ip($attacker_ip);
    
    # Get name of host running SSHCure
    my $sshcure_host = qx(hostname -f);
    $sshcure_host =~ s/^\s+|\s+\n?$//g;
    
    # Resolve attacker hostname
    my $attacker_hostname = ip2hostname($attacker_ip);
    $attacker_hostname = ($attacker_hostname eq $attacker_ip) ? "" : "($attacker_hostname)"; # Either show the reverse in parentheses, or don't show anything at all
    
    # Get attack phase name (certainty -> name), based on notification config (as the attack may move to a next phase before the notification was sent)
    my $attack_type;
    my @target_list;
    if ($CFG::NOTIFICATIONS{$notification_id}{'filter_type'} eq $CFG::CONST{'NOTIFICATIONS'}{'FILTER_TYPE'}{'ATTACKER'}){
        if ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'COMPROMISE'}){
            $attack_type = "compromise";
        } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'BRUTEFORCE'}){
            $attack_type = "brute-force attack";
        } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'SCAN'}){
            $attack_type = "scan attack";
        } else {
            # Do nothing
        }

        @target_list = keys(%$new_targets);
    } else {
        # FILTER_TYPE == TARGET
        # Select only those targets to be shown in the notification message that match the notification filter
        my $max_certainty = 0;
        foreach my $target (keys(%$new_targets)) {
            my $target_info = $$attack{'targets'}{$target};
            foreach my $ip_range (split(/,/ ,$CFG::NOTIFICATIONS{$notification_id}{'filter'})) {
                if (ip_addr_in_range($target, $ip_range)) {
                    push(@target_list, $target);
                    $max_certainty = $$target_info{'certainty'} if $$target_info{'certainty'} > $max_certainty;
                    last; # Break only inner loop
                }
            }
        }
        # transform $max_certainty into a string
        if ($max_certainty >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'COMPROMISE'}){
            $attack_type = "compromise";
        } elsif ($max_certainty >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'BRUTEFORCE'}){
            $attack_type = "brute-force attack";
        } elsif ($max_certainty >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'SCAN'}){
            $attack_type = "scan attack";
        } else {
            # Do nothing
        }
    }
 
    # Sort target list
    @target_list = sort { $a <=> $b } @target_list;
    
    # Convert IP numbers to addresses
    foreach (@target_list) {
        my $target_dec_ip = $_;
        $_ = dec2ip($_);
        $_ .= ' (compromised)' if (exists $$new_targets{$target_dec_ip} && exists $$new_targets{$target_dec_ip}{'compromise_ports'} && $$new_targets{$target_dec_ip}{'compromise_ports'} ne '');
    }
    
    # Join all IP addresses into a string
    my $formatted_target_list = join("\n", @target_list);

    my $start_time = strftime("%A, %B %d, %Y %H:%M", localtime($$attack{'start_time'}));
    my $end_time;

    # Since the attack's end time is updated after every interval (in case the attack is active),
    # we have to check whether the attack has really ended. This is done by the first condition.
    if ($CFG::NOTIFICATIONS{$notification_id}{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_END'} && $$attack{'end_time'} > 0) {
        $end_time = strftime("%A, %B %d, %Y %H:%M", localtime($$attack{'end_time'}));
    } else {
        $end_time = '(ongoing)';
    }
    
    my $mail_body =<<END;
A $attack_type has been detected by SSHCure on $sshcure_host, matching notification trigger '$notification_id'.
---

Start time: $start_time
End time: $end_time
Attacker: $attacker_ip $attacker_hostname

Targets:

$formatted_target_list

---
This message has been generated automatically by SSHCure $SSHCure::SSHCURE_VERSION.

END

    # Generate e-mail message for transporting IODEF attack report (using MIME)
    my $msg = MIME::Lite->new(
        From        => $CFG::NOTIFICATIONS{$notification_id}{'notification_sender'},
        To          => $CFG::NOTIFICATIONS{$notification_id}{'notification_destination'},
        Subject     => '[SSHCure] '.ucfirst($attack_type).' detected ('.$notification_id.')',
        Type        => 'text/plain',
        Data        => $mail_body
    );

    if ($msg->send('smtp', $NfConf::SMTP_SERVER)) {
        log_info("E-mail notification has been sent to '".$CFG::NOTIFICATIONS{$notification_id}{'notification_destination'}."' (attack ID: ".$$attack{'db_id'}.")");
    } else {
        log_info("Could not send e-mail notification to '".$CFG::NOTIFICATIONS{$notification_id}{'notification_destination'}."' (attack ID: ".$$attack{'db_id'}.")");
    }
}

1;
