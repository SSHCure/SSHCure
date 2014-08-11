#!/usr/bin/perl

######################################################################
#
#  SSHCure_dependency_test.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################

use strict;
use warnings;

my $SHOW_HELP = 1;

my %CONST = (
    'DEPENDENCY_OK'             => 0,
    'MODULE_VERSION_PROBLEM'    => 1,
    'MODULE_MISSING'            => 2,
);

my %perl_dependencies = (
    'Future::Utils' => {
        'packages'      => {
            'CentOS'    => 'perl-Future',
            'Debian'    => '',
            'FreeBSD'   => '',
            'OpenBSD'   => '',
        }
    },
    'IO::Async' => {
        'min_version'   => 0.61,
        'packages'      => {
            'CentOS'    => 'perl-IO-Async',
            'Debian'    => 'libio-async-perl',
            'FreeBSD'   => '',
            'OpenBSD'   => '',
        }
    },
    'JSON' => {
        'packages'      => {
            'CentOS'    => 'perl-JSON',
            'Debian'    => 'libjson-perl',
            'FreeBSD'   => 'p5-JSON',
            'OpenBSD'   => 'p5-JSON',
        }
    },
    'List::Util' => {
        'packages'      => {
            'CentOS'    => '',
            'Debian'    => '',
            'FreeBSD'   => '',
            'OpenBSD'   => '',
        }
    },
    'LWP::UserAgent' => {
        'packages'      => {
            'CentOS'    => 'perl-libwww-perl',
            'Debian'    => 'libwww-perl',
            'FreeBSD'   => 'p5-libwww',
            'OpenBSD'   => 'p5-libwww',
        }
    },
    'Mail::Header' => {
        'packages'      => {
            'CentOS'    => 'perl-MailTools',
            'Debian'    => 'libmailtools-perl',
            'FreeBSD'   => 'p5-Mail-Tools',
            'OpenBSD'   => 'p5-Mail-Tools',
        }
    },
    'Mail::Internet' => {
        'packages'      => {
            'CentOS'    => 'perl-MailTools',
            'Debian'    => 'libmailtools-perl',
            'FreeBSD'   => 'p5-Mail-Tools',
            'OpenBSD'   => 'p5-Mail-Tools',
        }
    },
    'Net::IP' => {
        'packages'      => {
            'CentOS'    => 'perl-Net-IP',
            'Debian'    => 'libnet-ip-perl',
            'FreeBSD'   => 'p5-Net-IP',
            'OpenBSD'   => 'p5-Net-IP',
        }
    },
    'Try::Tiny' => {
        'packages'      => {
            'CentOS'    => 'perl-Try-Tiny',
            'Debian'    => 'libtry-tiny-perl',
            'FreeBSD'   => 'p5-Try-Tiny',
            'OpenBSD'   => 'p5-Try-Tiny',
        }
    },
);

# Check whether modules are installed and whether version requirements are met
while ((my $module_name, my $module_info) = each %perl_dependencies) {
    # Check for presence of the module (no version dependency)
    my $check_command = sprintf("perl -e \"use %s; print 'OK'\"", $module_name);
    my $module_installed = qx($check_command 2> /dev/null) eq "OK";

    # Check for presence of the module, including version dependency, if needed
    if ($module_installed) {
        if (exists $$module_info{'min_version'}) {
            my $check_version_command = sprintf "perl -e \"use %s %f; print 'OK'\"", $module_name, $$module_info{'min_version'};
            my $module_version_OK = qx($check_version_command) eq "OK";

            if ($module_version_OK) {
                $$module_info{'result'} = $CONST{'DEPENDENCY_OK'};
            } else {
                $$module_info{'result'} = $CONST{'MODULE_VERSION_PROBLEM'};
            }
        } else {
            $$module_info{'result'} = $CONST{'DEPENDENCY_OK'};
        }
    } else {
        $$module_info{'result'} = $CONST{'MODULE_MISSING'};
    }
}

# First pass over results: determine maximum column lengths
my $max_module_name_length = 0;
my $max_status_length = 0;
while ((my $module_name, my $module_info) = each %perl_dependencies) {
    if (length($module_name) > $max_module_name_length) {
        $max_module_name_length = length($module_name);
    }

    if ($$module_info{'result'} == $CONST{'DEPENDENCY_OK'}) {
        $max_status_length = 8 if ($max_status_length <= 8);
    } elsif ($$module_info{'result'} == $CONST{'MODULE_MISSING'}) {
        $max_status_length = 13 if $max_status_length <= 13;
    } else {
       $max_status_length = 33;
    }
}

# Second pass over results: output
my $output_format = "%-${max_module_name_length}s | %${max_status_length}s\n";
printf $output_format, "Module", "Status";

for (my $i = 0; $i < $max_module_name_length + $max_status_length + 3; $i++) {
    printf "-";
}
printf "\n";

my $result = 0;

while ((my $module_name, my $module_info) = each %perl_dependencies) {
    if ($$module_info{'result'} == $CONST{'DEPENDENCY_OK'}) {
        printf $output_format, $module_name, "OK";
    } elsif ($$module_info{'result'} == $CONST{'MODULE_VERSION_PROBLEM'}) {
        printf $output_format, $module_name, "Update to at least v".$$module_info{'min_version'}." required";
        $result = 1;
    } else {
        printf $output_format, $module_name, "Not installed";
        $result = 1;
    }
}

for (my $i = 0; $i < $max_module_name_length + $max_status_length + 3; $i++) {
    printf "-";
}
printf "\n";

# Only show help in case not every module's status is 'OK'
if ($SHOW_HELP) {
    while ((my $module_name, my $module_info) = each %perl_dependencies) {
        if ($$module_info{'result'} != $CONST{'DEPENDENCY_OK'}) {
            printf "We refer to http://perl.about.com/od/packagesmodules/qt/perlcpan.htm for a guide on how to install Perl modules using CPAN.\n";
            last;
        }
    }
}

exit $result;

sub log_error {
    my ($msg) = @_;
    printf "ERROR - %s\n", $msg;
    exit 1
}
