<?php
    
    $config['backend.path']             = '/data/nfsen/plugins/SSHCure/';
    $config['database.dsn']             = 'sqlite:'.$config['backend.path'].'data/SSHCure.sqlite3';
    $config['profiling-database.dsn']   = 'sqlite:'.$config['backend.path'].'data/SSHCure_profile.sqlite3';

    $config['maxmind_IPv4.path']        = 'lib/MaxMind/GeoLiteCity.dat';
    $config['maxmind_IPv6.path']        = 'lib/MaxMind/GeoLiteCityv6.dat';

    $config['nfsen.list-flows-max']     = 1000;
    
    $config['web.root']                 = '/nfsen/plugins/SSHCure';
?>
