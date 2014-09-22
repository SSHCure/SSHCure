######################################################################
#
#  Notifications::Log.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::Notifications::Log;
use strict;
use warnings;

use Cwd 'abs_path';
use SSHCure::Utils;

use Exporter;
our @ISA = 'Exporter';

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;
    
    my $file_name = $CFG::NOTIFICATIONS{$notification_id}{'notification_destination'};
    
    # Check whether the file exists
    my $file_exists = (-e $file_name);
    
    # Try to open file or create it if it doesn't exist yet
    my $file;
    if (!open ($file, '>>', $file_name)) {
        log_error("Notification log file '".abs_path($file_name)."' could neither be opened, nor created");
        return;
    }
    
    # Add header line to log in case the log has just been created
    if (!$file_exists) {
        print $file ("# attack_id,attack_level,attack_start,attack_end,attacker_ip,target_count,compromised_target_list\n");
    }
    
    my $attack_id = $$attack{'db_id'};
    my $attack_start = $$attack{'start_time'};
    my $attack_end = $$attack{'end_time'};
    my $target_count = $$attack{'target_count'};
    
    # Get attack phase name (certainty -> name)
    my $attack_level = "";
    if ($$attack{'certainty'} <= $CFG::ALGO{'CERT_SCAN'}) { 
        $attack_level = "scan";
    } elsif ($$attack{'certainty'} <= $CFG::ALGO{'CERT_BRUTEFORCE'}) {
        $attack_level = "brute-force";
    } elsif ($$attack{'certainty'} <= $CFG::ALGO{'CERT_COMPROMISE'}) {
        $attack_level = "compromise";
    }
    
    # Find compromised targets
    my @compromised_target_list;
    foreach (keys(%$new_targets)) {
        if (exists $$new_targets{$_} && exists $$new_targets{$_}{'compromise_ports'} && $$new_targets{$_}{'compromise_ports'} ne '') {
            push(@compromised_target_list, $_);
        }
    }
    
    # Sort target list and join all IP addresses of compromised targets into a string
    @compromised_target_list = sort { $a <=> $b } @compromised_target_list;
    my $formatted_compromised_target_list = join(";", @compromised_target_list);
    
    # Add line to log
    print $file ("$attack_id,$attack_level,$attack_start,$attack_end,$attacker_ip,$target_count,$formatted_compromised_target_list\n");
    
    # Close file handle
    if (!close ($file)) {
        log_error("Notification log file '".abs_path($file_name)."' could not be closed");
        return;
    }
    
    log_info("Notification has been written to '".abs_path($file_name)."' (attack ID: ".$attack_id.")");
}    
