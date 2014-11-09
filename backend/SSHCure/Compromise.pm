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

use SSHCure::Model;
use SSHCure::Utils;

use IO::Async::Future;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(compromise_detection); 

sub compromise_detection {
    my ($sources, $sources_path, $timeslot, $timeslot_interval) = @_;
    
    Future->wrap();
}

1;
