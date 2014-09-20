######################################################################
#
#  Notifications::Email.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

package SSHCure::Notifications::Qmanage;
use strict;
use warnings;

use RPC::XML;

use Exporter;
our @ISA = 'Exporter';

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;
    
    # FIXME Implement notification handling
}

1;
