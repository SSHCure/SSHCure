<?php
    
    $config['backend.path']             = '/data/nfsen/plugins/SSHCure/';
    $config['database.dsn']             = 'sqlite:'.$config['backend.path'].'data/SSHCure.sqlite3';
    $config['profiling-database.dsn']   = 'sqlite:'.$config['backend.path'].'data/SSHCure_profile.sqlite3';
    
?>