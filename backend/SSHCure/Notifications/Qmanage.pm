######################################################################
#
#  Notifications::Qmanage.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::Notifications::Qmanage;
use strict;
use warnings;

use RPC::XML::Client;
use POSIX qw(strftime);
use SSHCure::Utils;

use Exporter;
our @ISA = 'Exporter';

# Provide your Qmanage configuration here
my $username = "";
my $password = "";
my $server_url = "https://<host>/admin/rpc";
# -----

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;

    # Qmanage does not have IPv6 support yet, so skip further processing in case of IPv6 attack
    return if (get_ip_version($attacker_ip) == 6);

    # Resolve name of host running SSHCure
    my $sshcure_host = qx(hostname -f);
    $sshcure_host =~ s/^\s+|\s+\n?$//g;

    # Check whether attacker is part of internal network
    my $internal_attacker = 0;
    for my $internal_network (split(/,/, $CFG::INTERNAL_NETWORKS)) {
        if (ip_addr_in_range($attacker_ip, $internal_network)) {
            $internal_attacker = 1;
            last;
        }
    }

    # Compromised machines should be placed in category 'Network Risk'
    my $qmanage_category = "";
    if ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'COMPROMISE'}) {
        $qmanage_category = "Network Risk";
    } elsif ($internal_attacker || $$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'BRUTEFORCE'}) {
        $qmanage_category = "Brute-Force Attack";
    } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'SCAN'}) {
        $qmanage_category = "Portscan";
    } else {
        # Do nothing
        log_error("Qmanage notification: Could not identify Qmanage category");

        # Stop further processing since 'category' is a required field
        return;
    }

    # Username and password are added to the URL, since ->credentials seems to not be supported by Qmanage
    my $server_url_auth = $server_url;
    if (index(lc($server_url), "https:") == -1) { # HTTP
        $server_url_auth =~ s/^http:\/\//http:\/\/${username}:${password}\@/;
    } else { # HTTPS
        $server_url_auth =~ s/^https:\/\//https:\/\/${username}:${password}\@/;
    }

    my $client = RPC::XML::Client->new($server_url_auth,
        error_handler => sub {
            if (index($_[0], "Authorization Required") != -1) {
                log_error("Could not communicate with Qmanage ($server_url): credentials missing or incorrect");
            } else {
                log_error("Could not communicate with Qmanage ($server_url): $_[0]");
            }
        },
        fault_handler => sub {
            my $fault = $_;
            log_error("A server-side error occurred with communicating with Qmanage ($server_url); code: $$fault{'faultCode'}, message: $$fault{'faultString'}");
        }
    );

    my $time_zone = strftime("%z", localtime($$attack{'start_time'}));
    $time_zone =~ s/(\d{2})(\d{2})/$1:$2/;
    my $timestamp_iso8601 = strftime("%Y-%m-%dT%H:%M:%S".$time_zone, localtime($$attack{'start_time'}));

    log_error("No start time set for attack (attack ID: ".$$attack{'db_id'}.")") unless ($$attack{'start_time'});

    my $response = $client->simple_request('create_reports' => {
            reports => RPC::XML::array->new({
                suspect => RPC::XML::array->new(RPC::XML::array->new('ipv4', dec2ip($attacker_ip))), # Should be a list of lists
                source => RPC::XML::string->new('SSHCure@'.$sshcure_host),
                timestamp => RPC::XML::datetime_iso8601->new($timestamp_iso8601),
                category => RPC::XML::string->new($qmanage_category),
                subcategory => RPC::XML::string->new('SSHCure'),
                confidence => RPC::XML::double->new($$attack{'certainty'}),
            })
    });

    if ($response) {
        my $report_id = $$response{'report_id'}[0];
        log_info("Notification was successfully sent to Qmanage (attack ID: ".$$attack{'db_id'}.", report ID: $report_id)");
    } else {
        log_error("No XML-RPC response received from Qmanage ($server_url)");
    }
}

1;
