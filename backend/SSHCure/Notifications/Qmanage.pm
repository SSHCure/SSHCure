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

use List::Util qw(min);
use POSIX qw(strftime);
use RPC::XML::Client;
use SSHCure::Utils;

# Provide your Qmanage configuration here
my $username = "";
my $password = "";
my $server_url = "https://<host>/admin/rpc";
# -----

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;

    # Qmanage does not have IPv6 support yet, so skip further processing in case of IPv6 attack
    return if (get_ip_version($attacker_ip) == 6);

    # Check whether attacker is part of internal network
    my $internal_attacker = 0;
    for my $internal_network (split(/,/, $CFG::INTERNAL_NETWORKS)) {
        if (ip_addr_in_range($attacker_ip, $internal_network)) {
            $internal_attacker = 1;
            last;
        }
    }

    # Username and password have to be added to the URL, since ->credentials seems to not be supported by Qmanage
    my $server_url_auth = $server_url;
    if (index(lc($server_url), "https:") == -1) { # HTTP
        $server_url_auth =~ s/^http:\/\//http:\/\/${username}:${password}\@/;
    } else { # HTTPS
        $server_url_auth =~ s/^https:\/\//https:\/\/${username}:${password}\@/;
    }

    # Initialize XML-RPC client
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

    # Determine timestamp
    my $time_zone = strftime("%z", localtime($$attack{'start_time'}));
    $time_zone =~ s/(\d{2})(\d{2})/$1:$2/;
    my $timestamp_iso8601 = strftime("%Y-%m-%dT%H:%M:%S".$time_zone, localtime($$attack{'start_time'}));

    log_error("No start time set for attack (attack ID: ".$$attack{'db_id'}.")") unless ($$attack{'start_time'});

    # Other report parameters (static)
    my $qmanage_subcategory = "SSHCure";

    # Compromised machines should be placed in category 'Network Risk'
    my $qmanage_category;
    my $host_blacklisted = host_on_openbl_blacklist($attacker_ip);
    if ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'COMPROMISE'}) {
        # Report attacker
        $qmanage_category = "Brute-Force Attack";
        $host_blacklisted = host_on_openbl_blacklist($attacker_ip);
        send_report(
                $client,
                $attack,
                RPC::XML::array->new(
                    RPC::XML::array->new('ipv4', dec2ip($attacker_ip))
                ),
                $timestamp_iso8601,
                $qmanage_category,
                $qmanage_subcategory,
                $host_blacklisted ? $$attack{'certainty'} + 0.2 : $$attack{'certainty'},
                "Host blacklisted by OpenBL: $host_blacklisted\r\nSSHCure attack certainty: ".$$attack{'certainty'},
        );

        # Report targets
        $qmanage_category = "Network Risk";

        # Determine compromised hosts (i.e., targets)
        foreach (keys(%$new_targets)) {
            if (exists $$new_targets{$_}{'certainty'} && $$new_targets{$_}{'certainty'} > 0.65) {
                $host_blacklisted = host_on_openbl_blacklist($_);
                send_report(
                        $client,
                        $attack,
                        RPC::XML::array->new(
                            RPC::XML::array->new('ipv4', dec2ip($_))
                        ),
                        $timestamp_iso8601,
                        $qmanage_category,
                        $qmanage_subcategory,

                        # Maximum Qmanage confidence is '0.9'
                        $host_blacklisted ? min($$new_targets{$_}{'certainty'} + 0.2, 0.9) : $$new_targets{$_}{'certainty'},
                        "Host blacklisted by OpenBL: $host_blacklisted\r\nSSHCure target certainty: ".$$new_targets{$_}{'certainty'},
                );
            }
        }
    } elsif ($internal_attacker || $$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'BRUTEFORCE'}) {
        $qmanage_category = "Brute-Force Attack";
        send_report(
                $client,
                $attack,
                RPC::XML::array->new(
                    RPC::XML::array->new('ipv4', dec2ip($attacker_ip))
                ),
                $timestamp_iso8601,
                $qmanage_category,
                $qmanage_subcategory,
                $host_blacklisted ? $$attack{'certainty'} + 0.3 : $$attack{'certainty'},
                "Host blacklisted by OpenBL: $host_blacklisted\r\nSSHCure attack certainty: ".$$attack{'certainty'},
        );
    } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'SCAN'}) {
        $qmanage_category = "Portscan";
        send_report(
                $client,
                $attack,
                RPC::XML::array->new(
                    RPC::XML::array->new('ipv4', dec2ip($attacker_ip))
                ),
                $timestamp_iso8601,
                $qmanage_category,
                $qmanage_subcategory,
                $host_blacklisted ? $$attack{'certainty'} + 0.5 : $$attack{'certainty'},
                "Host blacklisted by OpenBL: $host_blacklisted\r\nSSHCure attack certainty: ".$$attack{'certainty'},
        );
    } else {
        # Do nothing
        log_error("Qmanage notification: Could not identify Qmanage category");

        # Stop further processing since 'category' is a required field
        return;
    }
}

sub send_report {
    my ($rpc_client, $attack, $suspects, $timestamp, $category, $subcategory, $confidence, $details) = @_;

    # Resolve name of host running SSHCure
    my $sshcure_host = qx(hostname -f);
    $sshcure_host =~ s/^\s+|\s+\n?$//g;

    # Send report
    my $response = $rpc_client->simple_request('create_reports' => {
            reports => RPC::XML::array->new({
                suspect => $suspects,
                source => RPC::XML::string->new('SSHCure@'.$sshcure_host),
                timestamp => RPC::XML::datetime_iso8601->new($timestamp),
                category => RPC::XML::string->new($category),
                subcategory => RPC::XML::string->new($subcategory),
                confidence => RPC::XML::double->new($confidence),
                details => RPC::XML::string->new("Reported by SSHCure on $sshcure_host\r\n\r\n".$details),
            })
    });

    if ($response) {
        my $report_id = $$response{'report_id'}[0];
        log_info("Notification was successfully sent to Qmanage (attack ID: ".$$attack{'db_id'}.", report ID: $report_id)");
    } else {
        log_error("No XML-RPC response received from Qmanage ($server_url)");
    }

    return $response;
}

1;
