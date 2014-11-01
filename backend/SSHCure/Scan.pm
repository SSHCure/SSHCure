######################################################################
#
#  Scan.pm
#  Authors: Rick Hofstede <r.j.hofstede@utwente.nl>
#           Luuk Hendriks <luuk.hendriks@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################
# vim: expandtab:tw=4:sw=4

package SSHCure::Scan;
use strict;
use warnings;

use SSHCure::Model;
use SSHCure::Utils;

use IO::Async::Future;
use Future::Utils qw(fmap_concat);

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(scan_detection);

my @cmd_base = ("$NfConf::PREFIX/nfdump", split(" ", "-6Nq"));

sub scan_detection {
    my ($sources, $sources_path, $timeslot, $timeslot_interval) = @_;

    my $start_time = time;
    
    # Find all sources of SSH traffic
    my @cmd = (@cmd_base, "-M", "${sources_path}${sources}",
            split(" ", "-r nfcapd.$timeslot -t $timeslot_interval -A srcip,dstip -o pipe"),
            ("proto tcp and dst port 22 and packets < ".($CFG::ALGO{'SCAN_MAX_PPF'} + 1)));
    
    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my @flow_records = split("\n", shift);
        my $parsed_flow_records = parse_nfdump_pipe(\@flow_records);

        # Find all attackers by counting the number of targets per attacker
        my %attackers = ();
        foreach my $flow_record (@$parsed_flow_records) {
            if (exists $attackers{@$flow_record[4]}) {
                $attackers{@$flow_record[4]}->{'target_count'} += 1;
            } else {
                $attackers{@$flow_record[4]}->{'target_count'} = 1;
            }
        }

        # Find all attacker's targets
        foreach my $flow_record (@$parsed_flow_records) {
            # Check whether current attacker (src IP in current flow record; $flow_record[4]) contacted enough targets
            if ($attackers{@$flow_record[4]}->{'target_count'} > $CFG::ALGO{'SCAN_MIN_TARGETS'}) {
                $attackers{@$flow_record[4]}->{'targets'}->{@$flow_record[6]}->{'last_act'} = @$flow_record[2];
            }
        }

        foreach my $attacker (keys %attackers) {
            # If the 'targets' key exists we know it's a valid attacker with at least one target
            if (exists $attackers{$attacker}->{'targets'}) {
                # Check for behaviour that might occur in a network wide (L3) block (e.g. QuarantaineNet) and results in invalid scan targets
                if (exists $SSHCure::attacks{$attacker}) {
                    for my $target (keys $attackers{$attacker}->{'targets'}) {
                        if (exists $SSHCure::attacks{$attacker}{'targets'}{$target}
                                && $SSHCure::attacks{$attacker}{'targets'}{$target}{'certainty'} >= $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'}) {
                            # Remove those targets that are not real scan targets due to network-wide (L3) block
                            delete $attackers{$attacker}->{'targets'}->{$target};
                        }
                    }
                }
                
                add_scan_attacker($attacker, $attackers{$attacker}->{'targets'});
            }
        }
        
        Future->wrap();
    });
}

1;
