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
use SSHCure::Utils;

use Exporter;
our @ISA = 'Exporter';

my $server_url = "https://<host>/admin/rpc";
my $realm = "";
my $username = "";
my $password = "";

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;

    # Qmanage does not have IPv6 support yet, so skip further processing in case of IPv6 attack
    return if (get_ip_version($attacker_ip) == 6);

    # Resolve name of host running SSHCure
    my $sshcure_host = qx(hostname -f);
    $sshcure_host =~ s/^\s+|\s+\n?$//g;

    my $qmanage_subcategory = "";
    if ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'COMPROMISE'}){
        $qmanage_subcategory = "Compromise";
    } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'BRUTEFORCE'}){
        $qmanage_subcategory = "Brute-force";
    } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'SCAN'}){
        $qmanage_subcategory = "Scan";
    }
    
    my $client = RPC::XML::Client->new($server_url,
        error_handler => sub {
            log_error("Could not communicate with Qmanage ($server_url): $_[0]");
        },
        fault_handler => sub {
            my $fault = $_;
            log_error("A server-side error occurred with communicating with Qmanage ($server_url); code: $$fault{'faultCode'}, message: $$fault{'faultString'}");
        }
    );
    $client->credentials($realm, $username, $password);

    # my $response = $client->send_request('reports_api_version');
    my $response = $client->send_request('create_reports' => {
            Reports => {
                suspect => (('ipv4', dec2ip($attacker_ip))),
                source => 'SSHCure@$sshcure_host',
                timestamp => strftime("%Y-%m-%dT%H:%M:%S", localtime($$attack{'start_time'})),
                category => 'Brute-Force Attack',
                subcategory => $qmanage_subcategory,
                confidence => $$attack{'certainty'},
            }
    });
}

1;
