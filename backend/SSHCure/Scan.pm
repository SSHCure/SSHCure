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

use SSHCure::Utils;
use SSHCure::Utils::Nfdump;
use SSHCure::Model;

use IO::Async::Function;
use IO::Async::Future;

use Future::Utils qw(fmap_concat);

use Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(scan_detection);

my @cmd_base;

# FIXME IPv6 compatibility (check for _3 in addresses)

# check_parsed_for_scan_phase_attackers
# parameters:
#   $parsed: parsed nfdump output (output from SSHCure::Utils::parse_nfdump_list/pipe)
#
# NB. this subroutine depends on the format of the nfdump (parsed) output!
sub check_parsed_for_scan_phase_attackers {
    my $parsed = shift;
    my %result = ();
    
    #check every entry for scan phase characteristics
    foreach my $entry (@$parsed) {
        my ($time, $atk_ip, $packets, $flows) = @{$entry};
        my $ppf = $packets/$flows;
        if ($flows >= $CFG::ALGO{'SCAN_MIN_FLOWS'} && $ppf <= $CFG::ALGO{'SCAN_MAX_PPF'}) {
            $result{$atk_ip} = $time;
        }
    }
    return %result;
}

sub scan_detection_function {
    my ($sources, $sources_path, $attacker_ip, $timeslot, $timeslot_interval, $raw_nfdump_output, $std_err) = @_;
    my $attacker_ip_dec = ip2dec($attacker_ip);
    my $control_f = $SSHCure::loop->new_future;
   
    my @piped_nfdump_output = split("\n", $raw_nfdump_output); 
    if (defined $std_err && $std_err =~ /error/) {
        # Most likely, the previous nfcapd file does not exist. This might occur on fresh NfSen installations, new profiles, or validation runs.
        # Solution: Redo the nfdump query with only the current nfcapd file as input.
        log_error("Nfdump query in scan phase failed (not fatal): $std_err");

        my @piped_cmd = (@cmd_base, "-M", "${sources_path}${sources}", split(" ", "-r nfcapd.$timeslot -t $timeslot_interval -A dstip -o pipe"), ("proto tcp and dst port 22 and src ip $attacker_ip"));

        $SSHCure::loop->run_child_future(
            command => \@piped_cmd,
        )->on_done( sub {
            @piped_nfdump_output = split("\n", $_[0]);
            $control_f->done();
        });
    } else {
        $control_f->done();
    }
    
    $control_f->then( sub {
        my $parsed_flows = parse_nfdump_pipe(\@piped_nfdump_output);
        my %targets = ();
        if (scalar(@$parsed_flows) >= $CFG::ALGO{'SCAN_MIN_FLOWS'}) {
            foreach my $flow_record (@$parsed_flows) {
                my ($flow_start, $flow_end, $protocol, 
                    $sa_0, $sa_1, $sa_2, $sa_3, $src_port,
                    $da_0, $da_1, $da_2, $da_3, $dst_port,
                    $flags, $packets, $octets) = @$flow_record;

                # Check whether the traffic to this possible target matches scan characteristics
                next if $packets > $CFG::ALGO{'SCAN_MAX_PPF'};

                # Check for behaviour that might occur in a network wide (L3) block (e.g. QNet) and results in invalid scan-targets
                if (exists $SSHCure::attacks{$attacker_ip_dec} && exists $SSHCure::attacks{$attacker_ip_dec}{'targets'}{$da_3}) {
                    next if ($SSHCure::attacks{$attacker_ip_dec}{'targets'}{$da_3}{'certainty'} >= $CFG::ALGO{'CERT_BRUTEFORCE_NO_SCAN'});
                }
                $targets{$da_3}->{'last_act'} = $flow_start;
                $targets{$da_3}->{'prev_ppf'} = 2;
            }
        }

        my @new_scan_tuples;
        if (scalar (keys %targets) > 0) {
            push(@new_scan_tuples, [ $attacker_ip_dec, \%targets ]);
        }
        
        return Future->wrap(@new_scan_tuples);
    });
}

sub scan_detection {
    my ($sources, $sources_path, $timeslot, $timeslot_interval) = @_;
    @cmd_base = ("$NfConf::PREFIX/nfdump", split(" ", "-6 -Nq"));
    
    # Find all sources of SSH traffic
    my $fmt = "fmt:%ts|%sa|%pkt|%fl";
    my @cmd = (@cmd_base, "-M", "${sources_path}${sources}", split(" ", "-r nfcapd.$timeslot -t $timeslot_interval -A srcip -o $fmt"), ("proto tcp and dst port 22"));
    my @queue;
    
    $SSHCure::loop->run_child_future(
        command => \@cmd,
    )->then( sub {
        my @nfdump_output = split("\n", $_[0]);
        my @nfdump_parsed_result = ();
        parse_nfdump_list(\@nfdump_output, \@nfdump_parsed_result);
    
        # Get all sources of SSH traffic that show characteristics the characteristics of a scan -> attackers
        my %attackers = check_parsed_for_scan_phase_attackers(\@nfdump_parsed_result, $timeslot_interval);
        @queue = keys(%attackers);

        Future->wrap(fmap_concat {
            my $attacker_ip = shift;
            my @piped_cmd = (@cmd_base, "-M", $sources_path.$sources, split(" ", "-R nfcapd." . (previous_nfcapd($timeslot)) . ":nfcapd.$timeslot -t $timeslot_interval -A dstip -o pipe -Nq"), ("proto tcp and dst port 22 and src ip $attacker_ip"));
            
            $SSHCure::loop->run_child_future (
                command => \@piped_cmd,
            )->then( sub {
                scan_detection_function($sources, $sources_path, $attacker_ip, $timeslot, $timeslot_interval, $_[0], $_[1]);
            });
        } concurrent => $SSHCure::async_workers, foreach => \@queue);
    })->then( sub {
        my @new_scan_tuples = @_;

        foreach my $new_scan_tuple (@new_scan_tuples) {
            my ($attacker_ip, $targets) = @$new_scan_tuple;
            add_scan_attacker($attacker_ip, $targets);
        }

        Future->wrap();
    });
}

1;
