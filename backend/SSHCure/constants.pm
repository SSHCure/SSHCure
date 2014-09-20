######################################################################
#
#  constants.pm
#  Authors: Luuk Hendriks
#           Rick Hofstede <r.j.hofstede@utwente.nl>
#  University of Twente, The Netherlands
# 
#  LICENSE TERMS: 3-clause BSD license (outlined in license.html) 
#
######################################################################

# ALGO: algorithm constants, used in the detection algorithms
%ALGO = (
    # ATTACK_IDLE_TIMEOUT: mark an attack as 'ended' after this period of inactivity
    'ATTACK_IDLE_TIMEOUT'                           => (60 * 60), # 1 hour, in seconds
    
    # ATTACK_ACTIVE_TIMEOUT: mark an attack as 'ended' after this period, even if activity has been observed
    'ATTACK_ACTIVE_TIMEOUT'                         => (60 * 60 * 24 * 7), # 1 day, in seconds
   
    # CERT_*: numeric values used to distinguish states of an attack
    'CERT_SCAN'                                     => 0.25,
    'CERT_BRUTEFORCE'                               => 0.50,
    'CERT_BRUTEFORCE_NO_SCAN'                       => 0.40,
    'CERT_COMPROMISE'                               => 0.75,
    'CERT_COMPROMISE_NO_SCAN'                       => 0.65,
    'CERT_COMPROMISE_ADDITION'                      => 0.25,

    # Other algorithm values used in the detection
    'SCAN_MAX_PPF'                                  => 2,
    'SCAN_MIN_FLOWS'                                => 10,
    'BRUTEFORCE_MIN_PPF'                            => 11,
    'BRUTEFORCE_MAX_PPF'                            => 51,
    'BRUTEFORCE_CUSUM_DETERMINATION_THRESHOLD'      => 2,
    'BRUTEFORCE_CUSUM_STREAK_THRESHOLD'             => 5,
    'BRUTEFORCE_MIN_TARGET_COMPARISON_COUNT'        => 3,
    'BRUTEFORCE_COMPROMISE_MIN_PPF_DEVIATION'       => 5,
    'CONSIDER_MULTIPLE_CONNECTION_CLOSINGS_AS_COMP' => 0,
    'MAX_OPEN_CONNECTION_DURATION'                  => 60 * 60, # in seconds

    'MINIMAL_SSH_AUTH_PPF'                          => 11,
    
    # Default values used by OpenSSH SSH daemon
    'OPENSSH_LOGIN_GRACE_TIME'                      => 120, # in seconds
    'PAM_TIMEOUT'                                   => 3, # in seconds
);

# SSHCURE_DATA_DIR: directory containing file-based runtime information such as serialized attack hashes and lock files
my $SSHCURE_DATA_DIR = "$NfConf::BACKEND_PLUGINDIR/SSHCure/data";

%CONST = (
    'SSHCURE_DATA_DIR'          => $SSHCURE_DATA_DIR,
    'FN_ATTACKS_HASH'           => $SSHCURE_DATA_DIR."/attacks_hash",
    'FN_RUN_LOCK'               => $SSHCURE_DATA_DIR."/run.lock",
    'FN_FORCE_DB_MAINTENANCE'   => $SSHCURE_DATA_DIR."/force_db_maintenance",
    'FN_VALIDATION_LOCK'        => "/tmp/sshcure_validation.lock",
    'FN_DEBUG_LOG'              => "$NfConf::BACKEND_PLUGINDIR/SSHCure/data/debug.log",
    'RUN_LOCK_TIMEOUT'          => 2 * 60 * 60, # 2 hours, in seconds
    'MAX_ASYNC_WORKERS'         => 100,

    # ERRORs: constants used to communicate errors towards the front-end's dashboard
    'ERROR' => {
        'DATADIR_NOT_FOUND'         => 1,
        'DATADIR_NOT_READABLE'      => 2,
        'SSHCUREDATA_NOT_READABLE'  => 3,
        'SSHCUREDATA_NOT_WRITABLE'  => 4,
        'DATABASE_NOT_READABLE'     => 5,
        'DATABASE_NOT_WRITABLE'     => 6,
        'MAINTENANCE_FAILED'        => 7,
        'DATABASE_TOO_BIG'          => 8,
    },

    # DB: database (clean-up) settings
    'DB' => {
        'DSN'           => "dbi:SQLite:dbname=$NfConf::BACKEND_PLUGINDIR/SSHCure/data/SSHCure.sqlite3",         # DB name/location
        'DSN_PROFILING' => "dbi:SQLite:dbname=$NfConf::BACKEND_PLUGINDIR/SSHCure/data/SSHCure_profile.sqlite3", # Profiling DB name/location
        
        # MAX_*_AGE: maximum values used in maintenance routine, in days
        'MAX_SCAN_ATTACK_AGE'       => 30,  # 1 month
        'MAX_SCAN_TARGET_AGE'       => 2,   # 2 days
        'MAX_BRUTEFORCE_ATTACK_AGE' => 60,  # 2 months
        'MAX_BRUTEFORCE_TARGET_AGE' => 30,  # 1 month
        'MAX_COMPROMISE_ATTACK_AGE' => 365, # 1 year
        'MAX_COMPROMISE_TARGET_AGE' => 365, # 1 year
        
        # MAX_SIZE: only used to show a Dashboard warning about database maintenance
        'MAX_SIZE'      => 3000,   # in MBytes
    },
    
    'NOTIFICATIONS' => {
        'ATTACK_PHASE' => {
            'SCAN'              => $ALGO{'CERT_SCAN'},
            'BRUTEFORCE'        => $ALGO{'CERT_BRUTEFORCE_NO_SCAN'},
            'COMPROMISE'        => $ALGO{'CERT_COMPROMISE_NO_SCAN'},
        },
        'FILTER_TYPE' => {
            'ATTACKER'          => 0,
            'TARGET'            => 1,
        },
        'TYPE' => {
            'EMAIL'             => "Email",
            'LOG'               => "Log",
            'QMANAGE'           => "Qmanage",
        },
        'WHEN' => {
            'ATTACK_START'      => 0,
            'ATTACK_UPDATE'     => 1,
            'ATTACK_END'        => 2,
        },
        'LIMITS' => {
            'MAX_OVERALL'       => 0,
            'MAX_PER_CONFIG'    => 10,
        },
    },
    
    # Reasons for an attack to be blocked
    'BLOCKED' => {
        'NOT_BLOCKED'   => 0,
        'FAIL2BAN'      => 1,
        'QNET'          => 2,
        'TCPWRAPPER'    => 3,
    },
    
    'COMPROMISE_REASON' => {
        'NO_COMPROMISE'                             => -1,
        'INSTANT_LOGOUT_ABORT_DICTIONARY'           => 0,
        'INSTANT_LOGOUT_CONTINUE_DICTIONARY'        => 1,
        'MAINTAIN_CONNECTION_ABORT_DICTIONARY'      => 2,
        'MAINTAIN_CONNECTION_CONTINUE_DICTIONARY'   => 3,
        'MAINTAIN_CONNECTION'                       => 4,
    },

    'OPENBL' => {
        'SSH_BLACKLIST_URL'         => "http://www.openbl.org/lists/base_all_ssh-only.txt",
        'SSH_BLACKLIST_LOCAL_PATH'  => $SSHCURE_DATA_DIR."/openbl_ssh_snapshot.txt",
        'UPDATE_TIME'               => "5:00", # Should be in the following format: %H:%M
    },
);

# DBG: debug options
%DBG = (
    # ENABLED: enables the 'debug' statement, writing messages to the FN_DEBUG_LOG file
    'ENABLED'       => 0,
    'ATTACKER_IP'   => '',
    'TARGET_IP'     => ''
);

1;
