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

use IO::File;
use MIME::Lite;
use POSIX qw(strftime);
use SSHCure::Utils;
use XML::Writer;

# Specification: http://www.ietf.org/rfc/rfc5070.txt

sub handle_notification {
    my (undef, $attacker_ip, $attack, $new_targets, $notification_id) = @_;

    my $tmp_xml_file_path = $CFG::CONST{'SSHCURE_DATA_DIR'}.'/iodef_'.$$attack{'db_id'}.'.xml';

    # Convert IP number to address
    $attacker_ip = dec2ip($attacker_ip);

    # Get name of host running SSHCure
    my $sshcure_host = qx(hostname -f);
    $sshcure_host =~ s/^\s+|\s+\n?$//g;

    # Resolve attacker hostname
    my $attacker_hostname = ip2hostname($attacker_ip);
    $attacker_hostname = ($attacker_hostname eq $attacker_ip) ? "" : "($attacker_hostname)"; # Either show the reverse in parentheses, or don't show anything at all

    # Determine attack IP address version
    my $ip_version = get_ip_version($attacker_ip);

    # Convert attack start time to ISO 8601 timestamp
    my $time_zone = strftime("%z", localtime($$attack{'start_time'}));
    $time_zone =~ s/(\d{2})(\d{2})/$1:$2/;
    my $start_time_iso8601 = strftime("%Y-%m-%dT%H:%M:%S".$time_zone, localtime($$attack{'start_time'}));

    # Convert current time to ISO 8601 timestamp
    my $current_time_iso8601 = strftime("%Y-%m-%dT%H:%M:%S".$time_zone, localtime(time));

    # Determine attack type and severity
    my $attack_type; my $severity;
    if ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'COMPROMISE'}) {
        $attack_type = 'compromise';
        $severity = 'high';
    } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'BRUTEFORCE'}) {
        $attack_type = 'brute-force attack';
        $severity = 'medium';
    } elsif ($$attack{'certainty'} >= $CFG::CONST{'NOTIFICATIONS'}{'ATTACK_PHASE'}{'SCAN'}) {
        $attack_type = 'network scan';
        $severity = 'low';
    } else {
        # Do nothing
        return;
    }

    my $confidence = $severity;

    # Generate XML file
    my $output_file = IO::File->new($tmp_xml_file_path, 'w') or log_error("Could not create output file for IODEF XML document (path: $tmp_xml_file_path)");
    my $doc = new XML::Writer(OUTPUT => $output_file);
    $doc->startTag('xml', 'version' => '1.0', encoding => 'UTF-8');
        $doc->startTag('IODEF-Document', 'version' => '1.00', 'lang' => 'en',
                'xmlns' => 'urn:ietf:params:xml:ns:iodef-1.0',
                'xmlns:iodef' => 'urn:ietf:params:xml:ns:iodef-1.0',
                'xmlns:iodef-sci' => 'urn:ietf:params:xml:ns:iodef-sci-1.0',
                'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance');
            $doc->startTag('Incident', 'purpose' => 'reporting');
                $doc->startTag('IndicentID', 'name' => $$attack{'db_id'});
                    $doc->characters('');
                $doc->endTag();
                $doc->startTag('ReportTime');
                    $doc->characters($current_time_iso8601);
                $doc->endTag();
                $doc->startTag('StartTime');
                    $doc->characters($start_time_iso8601);
                $doc->endTag();

                # Since the attack's end time is updated after every interval (in case the attack is active),
                # we have to check whether the attack has really ended. This is done by the first condition.
                if ($CFG::NOTIFICATIONS{$notification_id}{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_END'} && $$attack{'end_time'} > 0) {
                    my $end_time_iso8601 = strftime("%Y-%m-%dT%H:%M:%S".$time_zone, localtime($$attack{'end_time'}));
                    $doc->startTag('EndTime');
                        $doc->characters($end_time_iso8601);
                    $doc->endTag();
                }

                $doc->startTag('Assessment', 'occurrence' => 'actual');
                    $doc->startTag('Impact', 'severity' => $severity, 'type' => 'ext-value', 'ext-type' => $attack_type);
                    $doc->endTag();
                    $doc->startTag('Confidence', 'rating' => $confidence);
                    $doc->endTag();
                $doc->endTag();

                $doc->startTag('Contact', 'role' => 'creator', 'type' => 'ext-value', 'ext-type' => 'application');
                    $doc->startTag('ContactName');
                        $doc->characters('SSHCure');
                    $doc->endTag();
                    $doc->startTag('Email');
                        $doc->characters($CFG::NOTIFICATIONS{$notification_id}{'notification_sender'});
                    $doc->endTag();
                    $doc->startTag('Description');
                        $doc->characters('This report has been generated by SSHCure on $sshcure_host');
                    $doc->endTag();
                $doc->endTag();

                $doc->startTag('EventData');
                    $doc->startTag('Flow');
                        $doc->startTag('System', 'category' => 'source');
                            $doc->startTag('Node');
                                $doc->startTag('Address', 'category' => 'ipv'.${ip_version}.'-addr');
                                    $doc->characters($attacker_ip);
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

    # Perform final checks and write to file
    $doc->end();
    $output_file->close();

    if (! -e $tmp_xml_file_path) {
        log_error("Could not find XML file generated for IODEF notification (attack ID: ".$$attack{'db_id'}.")");
        return;
    }

    # Generate e-mail message body
    my $start_time = strftime("%A, %B %d, %Y %H:%M", localtime($$attack{'start_time'}));
    my $end_time;

    # Since the attack's end time is updated after every interval (in case the attack is active),
    # we have to check whether the attack has really ended. This is done by the first condition.
    if ($CFG::NOTIFICATIONS{$notification_id}{'when'} eq $CFG::CONST{'NOTIFICATIONS'}{'WHEN'}{'ATTACK_END'} && $$attack{'end_time'} > 0) {
        $end_time = strftime("%A, %B %d, %Y %H:%M", localtime($$attack{'end_time'}));
    } else {
        $end_time = '(ongoing)';
    }
    my $mail_body = <<END;
A $attack_type has been detected by SSHCure on $sshcure_host, matching notification trigger '$notification_id'.
---

Start time: $start_time
End time: $end_time
Attacker: $attacker_ip $attacker_hostname

An attack report in IODEF format (XML) is attached to this message.

---
This message has been generated automatically by SSHCure.

END

    # Generate e-mail message for transporting IODEF attack report (using MIME)
    my $msg = MIME::Lite->new(
        From        => $CFG::NOTIFICATIONS{$notification_id}{'notification_sender'},
        To          => $CFG::NOTIFICATIONS{$notification_id}{'notification_destination'},
        Subject     => '[SSHCure] '.ucfirst($attack_type).' detected ('.$notification_id.')',
        Type        => 'multipart/mixed'
    );

    # Add text to e-mail message
    $msg->attach(
        Type        => 'text/plain',
        Data        => $mail_body
    );

    $msg->attach(
        Type        => 'application/xml',
        Path        => $tmp_xml_file_path,
        Filename    => 'SSHCure_'.$$attack{'db_id'}.'.xml',
        Disposition => 'attachment'
    );

    if ($msg->send('smtp', $NfConf::SMTP_SERVER)) {
        log_info("IODEF notification has been sent to '".$CFG::NOTIFICATIONS{$notification_id}{'notification_destination'}."' (attack ID: ".$$attack{'db_id'}.")");
    } else {
        log_info("Could not send IODEF notification to '".$CFG::NOTIFICATIONS{$notification_id}{'notification_destination'}."' (attack ID: ".$$attack{'db_id'}.")");
    }

    # Remove (temporary) XML file
    unlink($tmp_xml_file_path);
}

1;
