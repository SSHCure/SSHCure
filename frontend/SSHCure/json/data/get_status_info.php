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

    $db = new PDO($config['profiling-database.dsn']);
    $data = array();

    $query = "
        SELECT      p.time AS time,
                    p.target_count_scan AS target_count_scan,
                    p.target_count_bruteforce AS target_count_bruteforce,
                    p.target_count_compromise AS target_count_compromise
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
        $row['target_count_scan'] = intval($row['target_count_scan']);
        $row['target_count_bruteforce'] = intval($row['target_count_bruteforce']);
        $row['target_count_compromise'] = intval($row['target_count_compromise']);
        
        // Convert to UNIX timestamps
        $row['time'] = strtotime($row['time']);
        
        // flot expects millisecond timestamps
        $row['time'] *= 1000;
    }

    $old_result = $result;
    $result = array('scan' => array(), 'bruteforce' => array(), 'compromise' => array());

    // Find maxima and minima
    $target_min = -1; $target_max = -1;
    $time_min = -1; $time_max = -1;
    foreach ($old_result as $row) {
        if ($time_min == -1 || $row['time'] < $time_min) {
            $time_min = $row['time'];
        }
        if ($time_max == -1 || $row['time'] > $time_max) {
            $time_max = $row['time'];
        }
        
        if ($target_min == -1 || min($row['target_count_scan'], $row['target_count_bruteforce'], $row['target_count_compromise']) < $target_min) {
            $target_min = min($row['target_count_scan'], $row['target_count_bruteforce'], $row['target_count_compromise']);
        }
        if ($target_max == -1 || max($row['target_count_scan'], $row['target_count_bruteforce'], $row['target_count_compromise']) > $target_max) {
            $target_max = max($row['target_count_scan'], $row['target_count_bruteforce'], $row['target_count_compromise']);
        }
        
        array_push($result['scan'], array($row['time'], $row['target_count_scan']));
        array_push($result['bruteforce'], array($row['time'], $row['target_count_bruteforce']));
        array_push($result['compromise'], array($row['time'], $row['target_count_compromise']));
    }


    $data['target'] = array('target_min' => $target_min, 'target_max' => $target_max, 'time_min' => $time_min, 'time_max' => $time_max);
    $data['target']['data'] = $result;



    $query = "
        SELECT      p.time AS time,
                    p.flow_records AS flow_records,
                    p.run_time AS run_time
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
        $row['flow_records'] = intval($row['flow_records']);
        $row['run_time'] = intval($row['run_time']);
        
        // Convert to UNIX timestamps
        $row['time'] = strtotime($row['time']);
        
        // flot expects millisecond timestamps
        $row['time'] *= 1000;
    }

    $old_result = $result;
    $result = array('flow_records' => array(), 'run_time' => array());

    // Find maxima and minima
    $flow_records_min = -1; $flow_records_max = -1;
    $time_min = -1; $time_max = -1;
    foreach ($old_result as $row) {
        if ($time_min == -1 || $row['time'] < $time_min) {
            $time_min = $row['time'];
        }
        if ($time_max == -1 || $row['time'] > $time_max) {
            $time_max = $row['time'];
        }
        
        if ($flow_records_min == -1 || $row['flow_records'] < $flow_records_min) {
            $flow_records_min = $row['flow_records'];
        }
        if ($flow_records_max == -1 || $row['flow_records'] > $flow_records_max) {
            $flow_records_max = $row['flow_records'];
        }
        
        array_push($result['flow_records'], array($row['time'], $row['flow_records']));
        array_push($result['run_time'], array($row['time'], $row['run_time']));
    }

    $data['performance'] = array('flow_records_min' => $flow_records_min, 'flow_records_max' => $flow_records_max, 'time_min' => $time_min, 'time_max' => $time_max);
    $data['performance']['data'] = $result;


    echo json_encode($data);
    die();
?>
