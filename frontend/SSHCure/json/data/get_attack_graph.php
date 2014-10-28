<?php

    if (isset($_GET['timezone_offset'])) {
        $timezone_offset = $_GET['timezone_offset'];
    } else {
        echo json_encode(array('error' => 1, 'meta' => array('timezone_offset' => null)));
        die();
    }

    require_once("../../config.php");
    header("content-type: application/json");

    // Parse and process parameters
    $attack_id = $_GET['attack_id'];

    $query = "
        SELECT      t.target_ip AS target_ip,
        t.last_scan_activity AS last_scan_activity,
        t.last_bruteforce_activity AS last_bruteforce_activity,
        t.last_compromise_activity AS last_compromise_activity
        FROM		target t
        WHERE		t.attack_id = :attack_id
        LIMIT       100000";

    // TODO Investigate 'ORDER BY' performance, because 'ORDER BY t.certainty DESC' is very slow in the query above.

    $db = new PDO($config['database.dsn']);
    $stmnt = $db->prepare($query);
    $stmnt->bindParam(":attack_id", $attack_id);
    $stmnt->execute();

    // error_log("--> attackprofileplot - query completed (duration: ".(time() - $start)."s)");

    $result = $stmnt->fetchAll(PDO::FETCH_ASSOC);

    $scan_targets = 0;
    $bruteforce_targets = 0;
    $dieoff_targets = 0;

    foreach ($result as $row) {
        if ($row['last_scan_activity'] !== null) $scan_targets++;
        if ($row['last_bruteforce_activity'] !== null) $bruteforce_targets++;
        if ($row['last_compromise_activity'] !== null) $dieoff_targets++;    
    }
    unset($row);

    $total_targets = $scan_targets + $bruteforce_targets + $dieoff_targets;
    $max_targets = 5000; //FIXME $system->config('attackprofile.maxpoints', 5000);

    // Set default sampling rates. 1:1 (1) means no sampling.
    $scan_sampling_rate = 1;
    $bruteforce_sampling_rate = 1;
    $dieoff_sampling_rate = 1;

    $scan_activity = array();
    $bruteforce_activity = array();
    $dieoff_activity = array();

    // Check whether targets (i.e. points in attack profile plot) have to be sampled
    if ($total_targets > $max_targets) {
        $expected_dieoff_targets = $dieoff_targets;
        $expected_bruteforce_targets = $bruteforce_targets;
        $expected_scan_targets = $scan_targets;

        // Check whether sampling rate has to be adjusted
        // Priority 1: die-off traffic (max. 3/6 of all points)
        $allowed_dieoff_targets = (3 / 6) * $max_targets;
        if ($dieoff_targets > $max_targets) {
            $dieoff_sampling_rate = ceil($dieoff_targets / $allowed_dieoff_targets);
            $expected_dieoff_targets = (1 / $dieoff_sampling_rate) * $dieoff_targets;
        }

        // Priority 2: brute-force traffic (max. 2/6 of all points)
        $allowed_bruteforce_targets = ((5 / 6) * $max_targets) - $expected_dieoff_targets;
        if ($bruteforce_targets > $allowed_bruteforce_targets) {
            $bruteforce_sampling_rate = ceil($bruteforce_targets / $allowed_bruteforge_targets);
            $expected_bruteforce_targets = (1 / $bruteforce_sampling_rate) * $bruteforce_targets;
        }

        // Priority 3: scan traffic (max. 1/6 of all points)
        $allowed_scan_targets = $max_targets - $expected_dieoff_targets - $expected_bruteforce_targets;
        if ($scan_targets > $allowed_scan_targets) {
            $scan_sampling_rate = ceil($scan_targets / $allowed_scan_targets);
            $expected_scan_targets = (1 / $scan_sampling_rate) * $scan_targets;
        }
    }

    foreach ($result as $row) {
        $random_number = rand(0, 1000) / 1000;
        if ($row['last_scan_activity'] !== null && $random_number < (1 / $scan_sampling_rate)) {
            array_push($scan_activity, array($row['last_scan_activity'] * 1000, $row['target_ip']));
        }
        if ($row['last_bruteforce_activity'] !== null && $random_number < (1 / $bruteforce_sampling_rate)) {
            array_push($bruteforce_activity, array($row['last_bruteforce_activity'] * 1000, $row['target_ip']));
        }
        if ($row['last_compromise_activity'] !== null && $random_number < (1 / $dieoff_sampling_rate)) {
            array_push($dieoff_activity, array($row['last_compromise_activity'] * 1000, $row['target_ip']));
        }
    }
    unset($row);

    // Determine min/max timestamps and min/max IP addresses
    $time_min = -1;
    $time_max = -1;
    $ip_min = -1;
    $ip_max = -1;

    foreach (array($scan_activity, $bruteforce_activity, $dieoff_activity) as $data) {
        foreach ($data as $plot_point) {
            $time = $plot_point[0];

            // Determine time_min and time_max
            if ($time_min === -1 || $time_max === -1) { // Initial values
                $time_min = $time;
                $time_max = $time;
            } else {
                if ($time < $time_min) {
                    $time_min = $time;
                }
                if ($time > $time_max) {
                    $time_max = $time;
                }
            }

            $ip = $plot_point[1];

            // Determine ip_min and ip_max
            if (intval($ip) != 4294967295) { // Skip 255.255.255.255
                if ($ip_min === -1 || $ip_max === -1) { // Initial values
                    $ip_min = $ip;
                    $ip_max = $ip;
                } else {
                    if ($ip < $ip_min) {
                        $ip_min = $ip;
                    }
                    if ($ip > $ip_max) {
                        $ip_max = $ip;
                    }
                }
            }
        }
        unset($plot_point);
    }
    unset($data);

    // Apply the client's timezone offset and normalize IP addresses
    $activities = array(&$scan_activity, &$bruteforce_activity, &$dieoff_activity);
    foreach ($activities as &$data) {
        foreach ($data as &$plot_point) {
            $plot_point[0] = intval($plot_point[0]) + (-1 * $timezone_offset * 60 * 1000);
            $plot_point[1] = intval($plot_point[1]) - $ip_min;
        }
        unset($plot_point);
    }
    unset($data);

    $time_min += (-1 * $timezone_offset * 60 * 1000);
    $time_max += (-1 * $timezone_offset * 60 * 1000);

    echo json_encode(array('error' => 0,
        'meta' => array('attack_id' => $attack_id, 'time_min' => intval($time_min), 'time_max' => intval($time_max), 'ip_min' => intval($ip_min), 'ip_max' => intval($ip_max)), 
        'data' => array('scan' => $scan_activity, 'bruteforce' => $bruteforce_activity, 'dieoff' => $dieoff_activity)));

    die();
?>
