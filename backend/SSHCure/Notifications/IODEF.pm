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

use POSIX qw(strftime);
use SSHCure::Utils;
use XML::Writer;
use XML::Writer::String; # FIXME Remove

# Example: https://c3isecurity.wordpress.com/2012/06/27/iodef-sci-example/
# Specification: http://www.ietf.org/rfc/rfc5070.txt

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;

    # Determine attack IP address version
    my $ip_version = get_ip_version($attacker_ip);

    # Determine timestamp
    my $time_zone = strftime("%z", localtime($$attack{'start_time'}));
    $time_zone =~ s/(\d{2})(\d{2})/$1:$2/;
    my $timestamp_iso8601 = strftime("%Y-%m-%dT%H:%M:%S".$time_zone, localtime($$attack{'start_time'}));

    # Generate XML file
    my $output_string = XML::Writer::String->new(); # FIXME Remove
    my $doc = new XML::Writer(OUTPUT => $output_string); # FIXME Remove argument
    $doc->startTag('xml', 'version' => '1.0', encoding => 'UTF-8');
        $doc->startTag('IODEF-Document', 'version' => '1.00', 'lang' => 'en',
                'xmlns' => 'urn:ietf:params:xml:ns:iodef-1.0',
                'xmlns:iodef' => 'urn:ietf:params:xml:ns:iodef-1.0',
                'xmlns:iodef-sci' => 'urn:ietf:params:xml:ns:iodef-sci-1.0',
                'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance');
            $doc->startTag('Incident', 'purpose' => 'reporting');
                $doc->startTag('IndicentID', 'name' => ""); # FIXME
                    $doc->characters(''); # FIXME
                $doc->endTag();
                $doc->startTag('ReportTime');
                    $doc->characters($timestamp_iso8601);
                $doc->endTag();
                $doc->startTag('EventData');
                    $doc->startTag('Flow');
                        $doc->startTag('System', 'category' => 'source');
                            $doc->startTag('Node');
                                $doc->startTag('Address', 'category' => 'ipv'.${ip_version}.'-addr');
                                    $doc->characters(dec2ip($attacker_ip));
                                $doc->endTag();
                            $doc->endTag();
                        $doc->endTag();
                        $doc->startTag('System', 'category' => 'target');
                            foreach (keys(%$new_targets)) {
                                $doc->startTag('Node');
                                    $doc->startTag('Address', 'category' => 'ipv'.${ip_version}.'-addr');
                                        $doc->characters(dec2ip($_));
                                    $doc->endTag();
                                $doc->endTag();
                            }
                            $doc->startTag('Service', 'ip_protocol' => '6'); # TCP
                                $doc->startTag('Port');
                                    $doc->characters('22'); # SSH port number
                                $doc->endTag();
                            $doc->endTag();
                        $doc->endTag();
                    $doc->endTag();
                $doc->endTag();
            $doc->endTag();
        $doc->endTag();
    $doc->endTag();

    # Perform final checks
    $doc->end();

    # log_debug("XML file: ".$output_string->value());
}

1;
