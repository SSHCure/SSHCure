######################################################################
#
#  SSHCure.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
#
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html)
#
######################################################################

package SSHCure;
use strict;
use warnings;

our $VERSION = 136;
our $SSHCURE_VERSION = "3.0";

use SSHCure::Model;
use SSHCure::Utils;
use SSHCure::Utils::Nfdump;
use SSHCure::RPC;

use SSHCure::Scan;
use SSHCure::Bruteforce;
use SSHCure::Compromise;

use IO::Async::Loop;
use IO::Async::Future;

use File::Basename;
use File::Find;
use JSON;
use LWP::Simple;
use LWP::UserAgent;
use Storable;
use Try::Tiny;
use POSIX qw(strftime);

# Enable validation mode. NB the $VALIDATION_NFCAPD_DIR needs to be defined either way!
use constant VALIDATION_MODE => 0;
our $VALIDATION_NFCAPD_DIR = "";

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
    attacks
    DBH
    debug_log_fh
    ignored_records_close_outlier_count
    ignored_records_far_outlier_count
    loop
    PHASE
    async_workers
);

our %cmd_lookup = (
    'get_active_notification_configs'   =>  \&get_active_notification_configs,
    'get_backend_errors'                =>  \&get_backend_errors,
    'get_backend_init_time'             =>  \&get_backend_init_time,
    'get_backend_profile'               =>  \&get_backend_profile,
    'get_backend_sources'               =>  \&get_backend_sources,
    'get_backend_version'               =>  \&get_backend_version,
    'get_db_max_size'                   =>  \&get_db_max_size,
    'get_nfdump_version'                =>  \&get_nfdump_version,
    'get_nfsen_profiledatadir'          =>  \&get_nfsen_profiledatadir,
    'get_override_source'               =>  \&get_override_source,
    'get_run_lock_mtime'                =>  \&get_run_lock_mtime
);

our ($ignored_records_far_outlier_count, $ignored_records_close_outlier_count);

our %attacks;
our $DBH;
our $debug_log_fh;
our $init_time;
our $loop = IO::Async::Loop->new;
our $nfdump_version;        # Without potential patch number
our $nfdump_version_full;   # Includes potential patch number
our $PHASE = "PRE-INIT";
our $async_workers;

# The Init function is called when the plugin is loaded. It's purpose is to give the plugin
# the possibility to initialize itself. The plugin should return 1 for success or 0 for
# failure. If the plugin fails to initialize, it's disabled and not used. Therefore, if
# you want to temporarily disable your plugin return 0 when Init is called.
sub Init {
    $PHASE = "INIT";

    # Parse config files
    use Safe;
    my $cpt = new Safe 'CFG';
    $cpt->share_from('main', ['$NfConf::BACKEND_PLUGINDIR']);
    for my $cfgfile ("$NfConf::BACKEND_PLUGINDIR/SSHCure/constants.pm", "$NfConf::BACKEND_PLUGINDIR/SSHCure/config.pm") {
        unless ($cpt->rdo($cfgfile)) {
            log_error("Failed to parse config file '$cfgfile'");
            return;
        }
    }

    # Open logfile if debug is enabled
    open ($debug_log_fh, ">>".$CFG::CONST{'FN_DEBUG_LOG'}) if $CFG::DBG{'ENABLED'};

    # Perform config file sanity check
    log_info("Performing configuration file sanity check...");
    return unless perform_config_sanity_check();

    # Check latest version number
    log_info("Checking for latest version of SSHCure...");
    my $operating_system = qx(uname);
    chomp $operating_system;
    if ($operating_system eq "Linux") {
        if (qx(which lsb_release)) { # Debian-based OS
            ($operating_system) = qx(lsb_release -d 2> /dev/null) =~ /Description:\s+(.*)/;
        } elsif (glob("/etc/*-release")) {
            if (qx(cat /etc/*-release | grep -i 'pretty')) { # Example: PRETTY_NAME="Debian GNU/Linux 7 (wheezy)"
                $operating_system = qx(cat /etc/*-release | grep -i \'pretty\') =~ "(.+)";
                $operating_system =~ s/\"//g;
            } else { # RedHat-based OS
                $operating_system = qx(cat /etc/*-release | head -n 1);
            }
        } else {
            # Do nothing, i.e., use 'Linux'
        }
    } elsif ($operating_system eq "Darwin") {
        $operating_system = 'Mac OS X '.qx(sw_vers -productVersion);
    } elsif ($operating_system eq "FreeBSD" || $operating_system eq "OpenBSD") {
        my $version = qx(uname -r);
        $operating_system .= " ".$version;
    } else {
        $operating_system = "(Unknown)";
    }

    # Determine ulimit and IO::Async workers
    my $ulimit = qx(echo `ulimit -n`);
    if ($ulimit =~ /^[+-]?\d+$/) {
        chomp($ulimit);

        # 7 checks (5 regular, login grace time, non-aggregated)
        #   + 1 buffer
        # 3 file handles per check (command itself, input, output)
        $async_workers = int($ulimit / (8 * 3));

        # Floor to nearest multiple of 100
        if ($async_workers > 100) {
            $async_workers -= $async_workers % 100;
        } elsif ($async_workers > 50) {
            $async_workers -= $async_workers % 50;
        } elsif ($async_workers > 10) {
            $async_workers -= $async_workers % 10;
        }

        $async_workers = $CFG::CONST{'MAX_ASYNC_WORKERS'} if ($async_workers > $CFG::CONST{'MAX_ASYNC_WORKERS'});

        log_info("Using ".$async_workers." IO::ASYNC workers (ulimit: ".$ulimit.")");
    } else {
        $async_workers = 10;
        log_info("Could not determine system ulimit; using ".$async_workers." IO::ASYNC workers");
    }

    my $post_data = [
            'current_version'   => ${SSHCURE_VERSION},
            'operating_system'  => ${operating_system}
    ];
    my $user_agent = LWP::UserAgent->new(timeout => 5);
    $user_agent->env_proxy; # Configure proxy-related settings based on environment variables
    my $response = $user_agent->post("http://sshcure.sourceforge.net/get_version_number.php", $post_data);
    if ($response->is_success) {
        my $result = decode_json($response->decoded_content);
        my $latest_version = $result->{'version'}; 
        my $version_comparison_result = compare_nfdump_version_number($SSHCURE_VERSION, $latest_version);
        if ($version_comparison_result == 1) {
            log_info("A newer version of SSHCure is available: v$result->{'version'} (installed: v${SSHCURE_VERSION})");
        } elsif ($version_comparison_result == 0) {
            log_info("You have installed the latest version of SSHCure: v$result->{'version'}");
        } else {
            log_info("You are running a development version of SSHCure: v${SSHCURE_VERSION} (latest stable: v$result->{'version'})");
        }
    } else {
        log_error("Could not check for latest version of SSHCure (code: ".$response->code.", message: ".$response->message.")!");
    }

    # Setup the database connection
    log_info("Connecting to database...");
    $DBH = DBI->connect($CFG::CONST{'DB'}{'DSN'}, "", "", {
            sqlite_use_immediate_transaction => 1
    }) or log_error("Could not connect to database ($CFG::CONST{'DB'}{'DSN'}). Error: $DBI::errstr");

    # Set SQLite PRAGMA settings (http://stackoverflow.com/questions/1711631/how-do-i-improve-the-performance-of-sqlite)
    log_info("Configuring database driver...");
    $DBH->do("PRAGMA synchronous = OFF");
    $DBH->do("PRAGMA journal_mode = MEMORY");

    # Check database writability. An SQLite database is writable if both the file itself and the parent directory are writable.
    my $db_file = substr($CFG::CONST{'DB'}{'DSN'}, index($CFG::CONST{'DB'}{'DSN'}, "/"));
    my $profiling_db_file = substr($CFG::CONST{'DB'}{'DSN_PROFILING'}, index($CFG::CONST{'DB'}{'DSN_PROFILING'}, "/"));
    if (! -w $db_file) {
        log_error("Database ($db_file) is not writable");
        return;
    }
    if (! -w $profiling_db_file) {
        log_error("Database ($profiling_db_file) is not writable");
        return;
    }
    if (! -w $CFG::CONST{'SSHCURE_DATA_DIR'}) {
        log_error("Parent directory of database ($CFG::CONST{'SSHCURE_DATA_DIR'}) is not writable");
        return;
    }

    $ignored_records_close_outlier_count = 0;
    $ignored_records_far_outlier_count = 0;
    
    $nfdump_version = retrieve_nfdump_version(0);
    $nfdump_version_full = retrieve_nfdump_version(1);
    log_info("Detected nfdump v$nfdump_version_full");

    $init_time = time;
    log_info("Initialized");
    return 1;
}

# Periodic data processing function
#       input:  hash reference including the items:
#               'profile'       profile name
#               'profilegroup'  profile group
#               'timeslot'      time of slot to process: Format yyyymmddHHMM e.g. 200503031200
sub run {
    my $argref       = shift;
    my $profile      = $$argref{'profile'};
    my $profilegroup = $$argref{'profilegroup'};
    my $timeslot     = $$argref{'timeslot'};

    $PHASE = "RUN";

    if (-e $CFG::CONST{'FN_RUN_LOCK'}) {
        log_warning("Previous run has not finished yet (or a stale lock file exists); skipping data processing...");
        my $skip = 1;
        my $mtime = scalar ((stat($CFG::CONST{'FN_RUN_LOCK'}))[9]);
        if ((time() - $mtime) >= $CFG::CONST{'RUN_LOCK_TIMEOUT'}) {
            log_warning("Lock file exists for more than $CFG::CONST{'RUN_LOCK_TIMEOUT'} second(s); assuming stale lock file");
            unlink($CFG::CONST{'FN_RUN_LOCK'});
            log_warning("Stale lock file removed");
            $skip = 0;
        }

        # Insert profiling value with runtime=0, flow_records_sec=0, run_skipped=1
        if ($skip) {
            save_profiling_data($timeslot, 0, 0, 1);
            return;
        }
    }

    if (-e $CFG::CONST{'FN_VALIDATION_LOCK'}) {
        log_info("In validation mode; skipping (regular) data processing...");
        return;
    }

    my %profileinfo     = NfProfile::ReadProfile($profile, $profilegroup);
    my $profilepath     = NfProfile::ProfilePath($profile, $profilegroup);
    my $all_sources     = join(':', keys(%{$profileinfo{'channel'}}));
    $all_sources        = $CFG::OVERRIDE_SOURCE if ($CFG::OVERRIDE_SOURCE ne "");
    my $sources         = "$all_sources";
    my $sources_path    = "$NfConf::PROFILEDATADIR/$profilepath/";

    log_info("Creating lock file ($CFG::CONST{'FN_RUN_LOCK'})");
    unless (open(RUN_LOCK_FH, '>'.$CFG::CONST{'FN_RUN_LOCK'})) {
        log_error("Failed to create lock file ($CFG::CONST{'FN_RUN_LOCK'}): $!. Skipping data processing...");
        return;
    }
    close(RUN_LOCK_FH);

    my @VALIDATION_TIMESTAMPS = ();
    my $validation_time_start = time;
    if (VALIDATION_MODE == 1) {
        # in case of multiple sources, determine the main dir
        my ($validation_main_dir, $with_slash, $multiple_sources) = $VALIDATION_NFCAPD_DIR =~ /([^:]+)(\/(.*))?$/;
        log_info("Validation directory: $validation_main_dir");
        if ($multiple_sources) {
            log_info("Multiple sources for validation: $multiple_sources") if $multiple_sources;
        }
        if (not -e $validation_main_dir) {
            die "Validation directory does not exist: $VALIDATION_NFCAPD_DIR. Exiting...";
        }

        $sources_path = dirname($VALIDATION_NFCAPD_DIR)."/";
        $sources = basename($VALIDATION_NFCAPD_DIR);

        # Create lock file so we know we are validating: this file prevents 'normal' execution of the run sub by nfsen
        open(TEMP_FH,'>'.$CFG::CONST{'FN_VALIDATION_LOCK'}) or log_error("Failed to create lock file ($CFG::CONST{'FN_RUN_LOCK'}): $!");
        close(TEMP_FH);
        
        my %validation_timestamps_hash = ();
        find( sub {
            $validation_timestamps_hash{$1} = 1 if $_ =~ /^nfcapd\.(\d+)$/;
        }, $validation_main_dir);
        @VALIDATION_TIMESTAMPS = keys %validation_timestamps_hash;
            
        # reverse sort the timestamps so we can use pop(@VAL_TIMESTAMPS) to times in a chronological order
        @VALIDATION_TIMESTAMPS = reverse sort @VALIDATION_TIMESTAMPS;

        if (scalar(@VALIDATION_TIMESTAMPS) == 0) {
            die "No nfcapd files found in $VALIDATION_NFCAPD_DIR. Exiting...";
            run_cleanup();
        }
    }

    if (-e $CFG::CONST{'FN_ATTACKS_HASH'}) {
        try {
            my $fh = retrieve($CFG::CONST{'FN_ATTACKS_HASH'});
            %attacks = %{$fh};
        } catch {
            rename($CFG::CONST{'FN_ATTACKS_HASH'}, $CFG::CONST{'FN_ATTACKS_HASH'}."_old");
            %attacks = ();
            log_error("Failed to load attacks hash; renamed corrupted attacks hash to $CFG::CONST{'FN_ATTACKS_HASH'}_old and created new hash");
        };
    }

    # This label is for validation purposes. it processes all of the nfcapd from the specified dir are ran through the algorithm.
    VALIDATION_MODE_START:

    my $run_begin_time = time;

    $ignored_records_close_outlier_count = 0;
    $ignored_records_far_outlier_count = 0;

    if (VALIDATION_MODE == 1) {
        # Set $timeslot to the next nfcapd-file to be validated
        $timeslot = pop(@VALIDATION_TIMESTAMPS);
    }

    log_info("Starting data processing; profile: $profile, profilegroup: $profilegroup, source(s): $sources, timeslot: $timeslot");

    # If there are no flows in the nfcapd, end the run
    if (nfcapd_is_empty($sources_path, $sources, $timeslot)) {
        log_warning("Skipped data processing (no flow data)");
        
        if (VALIDATION_MODE && @VALIDATION_TIMESTAMPS) {
            goto VALIDATION_MODE_START;
        } else {
            run_cleanup();
            return;
        }
    }
    
    my $corrected_interval = get_corrected_interval_for_timeslot($sources, $sources_path, $timeslot);
    if ($corrected_interval eq "") {
        log_error "No flows left to process, stopping this run. If this message occurs often, check the system time.";
        return;
    }
    debug "Corrected time-interval: $corrected_interval";

    $SSHCure::PHASE = "SCAN";
    scan_detection($sources, $sources_path, $timeslot, $corrected_interval)->then( sub {
        $SSHCure::PHASE = "BF";
        bruteforce_detection($sources, $sources_path, $timeslot, $corrected_interval);
    })->then( sub {
        $SSHCure::PHASE = "COMP";

        # Turn off the 'compromise' detection for now; the BF detector does this currently (most sanely)
        # compromise_detection($sources, $timeslot, $corrected_interval, \@timeslot_intervals);
        Future->wrap();
    })->get();

    $PHASE = "";
    if (VALIDATION_MODE) {
        my $time_now_hack = nfcapd2unix($timeslot) + (5 * 60);
        remove_timeouts(\%attacks, $time_now_hack);
    } else {
        remove_timeouts(\%attacks);
    }

    # Determine number of processed flow records
    my %nfcapd_info = get_info_from_nfcapd($sources_path, $sources, $timeslot);
    my $run_time_spent = time - $run_begin_time;
    my $ongoing_attack_count = scalar keys(%attacks);
    log_info("Finished data processing; time needed: ".$run_time_spent." second(s), flow records processed: ".$nfcapd_info{'Flows'}.", ongoing attacks: ".$ongoing_attack_count);

    ################################
    #
    # INSERT PROFILING DATA
    #
    ################################

    save_profiling_data($timeslot, $run_time_spent, $nfcapd_info{'Flows'});

    ################################
    #
    # DATABASE MAINTENANCE
    #
    ################################

    # Check whether maintenance file with counter < 10 exists. Should be within 10 * maintenance_retry_interval from current timestamp.
    # If it exists, try to perform maintenance
    my $retry_previous_maintenance = 0;
    my $filename = '';
    my $file_timestamp;
    my $retry_count;
    my @retry_files = glob("@{[$CFG::CONST{'SSHCURE_DATA_DIR'}]}/retry_maintenance_*.*");
    if (scalar @retry_files) {
        $filename = basename($retry_files[0]);
        $filename =~ /retry_maintenance_([0-9]+)\.([0-9]+)$/;
        $file_timestamp = $1;
        $retry_count = $2;
        $retry_previous_maintenance = $retry_count < 10;
    }
    
    if (VALIDATION_MODE == 0) {
        if (-e $CFG::CONST{'FN_FORCE_DB_MAINTENANCE'}) {
            # Database maintenance should be started forceably
            log_info("Detected force database maintenance trigger file; removing file (".$CFG::CONST{'FN_FORCE_DB_MAINTENANCE'}.")");
            unlink($CFG::CONST{'FN_FORCE_DB_MAINTENANCE'});
            database_maintenance(nfcapd2unix($timeslot) + (5 * 60));
        } elsif (grep($_ eq strftime("%u:%H:%M", localtime(nfcapd2unix($timeslot))), map($_.":00", @{$CFG::MAINTENANCE{'TRIGGERS'}})) or $retry_previous_maintenance) {
            # Regular (scheduled) database maintenance should be performed
            if (300 - $run_time_spent > $CFG::MAINTENANCE{'TIME_NEEDED'} * 1.2) { # 20% leeway
                database_maintenance(nfcapd2unix($timeslot) + (5 * 60));
                unlink("@{[$CFG::CONST{'SSHCURE_DATA_DIR'}]}/$filename");
            } else {
                log_warning("Not enough time for database maintenance; skipping database maintenance...");
                # Check for existing retry file and create one if non-existent
                if ($retry_previous_maintenance) {
                    # Retry file already exists, increase counter
                    $retry_count++;
                    if ($retry_count < 10) {
                        rename("$CFG::CONST{'SSHCURE_DATA_DIR'}/$filename", "$CFG::CONST{'SSHCURE_DATA_DIR'}/retry_maintenance_$file_timestamp.$retry_count");
                    } else {
                        # Tried 10 times; database mainteance has definitely failed
                        rename("$CFG::CONST{'SSHCURE_DATA_DIR'}/$filename", "$CFG::CONST{'SSHCURE_DATA_DIR'}/failed_maintenance_$file_timestamp");
                        log_error("Database maintenance for $file_timestamp failed $retry_count time(s)");
                    }
                } else {
                    # Retry file does not exist yet; create one with count '1'
                    open(TMPRETRYFILE, ">@{[$CFG::CONST{'SSHCURE_DATA_DIR'}]}/retry_maintenance_$timeslot.1");
                    close(TMPRETRYFILE);
                }
            }
        }

        # Check whether local OpenBL blacklist copy needs to be updated
        my $nfcapd_time = strftime("%H:%M", localtime(nfcapd2unix($timeslot) + 5 * 60)); # nfcapd files are always 5 minutes behind in time
        my $fetch_openbl_snapshot = 0;
        unless (-e $CFG::CONST{'OPENBL'}{'SSH_BLACKLIST_LOCAL_PATH'}) {
            log_info("Could not find OpenBL snapshot; fetching snapshot...");
            $fetch_openbl_snapshot = 1;
        } elsif (index($nfcapd_time, $CFG::CONST{'OPENBL'}{'UPDATE_TIME'}) != -1) {
            log_info("Local OpenBL blacklist snapshot has expired; fetching new snapshot...");
            $fetch_openbl_snapshot = 1;
        }

        if ($fetch_openbl_snapshot) {
            my $resp_code = mirror($CFG::CONST{'OPENBL'}{'SSH_BLACKLIST_URL'}, $CFG::CONST{'OPENBL'}{'SSH_BLACKLIST_LOCAL_PATH'});
            if ($resp_code == 200) {
                log_info("Successfully fetched OpenBL blacklist snapshot ($nfcapd_time)");
            } else {
                log_error("OpenBL blacklist snapshot could not be fetched; trying again in 24 hours...");
            }
        }
    }

    if (VALIDATION_MODE == 1 && @VALIDATION_TIMESTAMPS) {
        goto VALIDATION_MODE_START;
    }
    
    store(\%attacks, $CFG::CONST{'FN_ATTACKS_HASH'});

    if (VALIDATION_MODE) {
        log_info("Validation runs completed; alter the constants in SSHCure.pm, empty the db/hashes, remove /tmp/sshcure_validation.lock");
        debug "Total time needed for this (validation) run: " . (time - $validation_time_start) . " second(s)";
        log_info("Total time needed for this (validation) run: " . (time - $validation_time_start) . " second(s)");
    }

    run_cleanup();
} # End of run

# Performs tasks necessary before finishing any processing run, e.g., removes the run lock from the file system
sub run_cleanup {
    # Remove the run lock on the filesystem
    log_info("Removing lock file ($CFG::CONST{'FN_RUN_LOCK'})");
    unlink $CFG::CONST{'FN_RUN_LOCK'} or log_error("Removal of lock file failed ($CFG::CONST{'FN_RUN_LOCK'}); make sure to delete it manually...");
}

sub Cleanup {
    log_info("Cleanup completed");
}

1;
