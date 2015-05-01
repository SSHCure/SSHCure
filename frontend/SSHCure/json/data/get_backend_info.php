<?php
/******************************************************
 # backendinittime.action.php
 # Authors:		Rick Hofstede <r.j.hofstede@utwente.nl>
 #              Luuk Hendriks
 # University of Twente, The Netherlands
 #
 # LICENSE TERMS: 3-clause BSD license (outlined in license.html)
 *****************************************************/

    require_once("../../config.php");
    header("content-type: application/json");
    require_once("/var/www/nfsen/conf.php");
    require_once("/var/www/nfsen/nfsenutil.php");

    if (!function_exists('ReportLog')) {
        function ReportLog() {
            // dummy function to avoid PHP errors
        }
    }

    $data = array();

    $out_list = nfsend_query("SSHCure::get_backend_profile", array());
    $data['profile'] = $out_list['backend_profile'];
    
    $out_list = nfsend_query("SSHCure::get_backend_sources", array());
    $data['sources'] = $out_list['backend_sources'];


    $out_list = nfsend_query("SSHCure::get_backend_configs", array());
    $data['configs'] = $out_list['backend_configs'];


    $db = new PDO($config['profiling-database.dsn']);

    $query = "
        SELECT      p.time AS time,
                    p.db_size AS db_size
        FROM        profile p
        ORDER BY    time DESC
        LIMIT       5000
    ";

    $stmnt = $db->prepare($query);
    $stmnt->execute();

    $result = $stmnt->fetchAll(PDO::FETCH_ASSOC);
    unset($stmnt);

    // Convert all timestamps to UNIX timestamps
    foreach ($result as &$row) {
        $row['db_size'] = intval($row['db_size']);
        
        // Convert to UNIX timestamps
        $row['time'] = strtotime($row['time']);
        
        // flot expects millisecond timestamps
        $row['time'] *= 1000;
    }

    $old_result = $result;
    $result = array();

    // Find maxima and minima
    $db_size_min = -1; $db_size_max = -1;
    $time_min = -1; $time_max = -1;
    foreach ($old_result as $row) {
        if ($time_min == -1 || $row['time'] < $time_min) {
            $time_min = $row['time'];
        }
        if ($time_max == -1 || $row['time'] > $time_max) {
            $time_max = $row['time'];
        }
        
        if ($db_size_min == -1 || $row['db_size'] < $db_size_min) {
            $db_size_min = $row['db_size'];
        }
        if ($db_size_max == -1 || $row['db_size'] > $db_size_max) {
            $db_size_max = $row['db_size'];
        }
        
        array_push($result, array($row['time'], $row['db_size']));
    }

    $data['db'] = array('db_size_min' => $db_size_min, 'db_size_max' => $db_size_max, 'time_min' => $time_min, 'time_max' => $time_max);
    $data['db']['data'] = $result;
    // error_log("--> dbsize - end (duration: ".(time() - $start)."s)");
    echo json_encode($data);
    die();
?>
