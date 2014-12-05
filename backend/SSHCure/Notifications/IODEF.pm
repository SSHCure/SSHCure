######################################################################
#
#  Notifications::IODEF.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::Notifications::IODEF;
use strict;
use warnings;

use SSHCure::Utils;
use XML::Writer;


sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;

    
}

sub send_report {
    my ($rpc_client, $attack, $suspects, $timestamp, $category, $subcategory, $confidence, $details) = @_;

    
}

1;
