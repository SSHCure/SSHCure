<?php

    require_once("../config.php");
    header("content-type: application/json");

    $db = new PDO($config['database.dsn']);

    $min_start_time = isset($_GET['min_start_time']) ? $_GET['min_start_time'] : 0;
    $max_start_time = isset($_GET['max_start_time']) ? $_GET['max_start_time'] : time();

    $query_string = "
    SELECT		a.id as id,
                a.start_time AS start_time,
                a.end_time AS end_time,
                a.certainty AS certainty
    FROM		attack a
    WHERE		a.start_time >= :min_start_time
    		AND a.start_time <= :max_start_time";

    $query_string = str_replace(':min_start_time', $min_start_time, $query_string);
    $query_string = str_replace(':max_start_time', $max_start_time, $query_string);

    // Prepare query string for easy readability (for debugging purposes)
    $query_string = preg_replace('!\s+!', ' ', $query_string); // Replaces multiple spaces by single space
    $query_string = str_replace(' ,', ',', $query_string);
    $query_string = trim($query_string);

    $query = $db->query($query_string);
    $db_result = $query->fetchAll(PDO::FETCH_ASSOC);
    unset($query);

    $time_range = $max_start_time - $min_start_time;
    if ($time_range >= 2592000) { // 30 days
        $bin_size = 3 * 60 * 60; // 3 hours
    } else if ($time_range >= 176400) { // 7 days
        $bin_size = 60 * 60; // 1 hour
    } else if ($time_range >= 86400) { // 1 day
        $bin_size = 10 * 60; // 10 minutes
    } else {
        $bin_size = 1 * 60; // 1 minute
    }

    $scan_attacks = array();
    $bruteforce_attacks = array();
    $compromise_attacks = array();

    foreach ($db_result as $row) {
        $attack_start_time = intval($row['start_time']);
        $attack_end_time = ($row['end_time'] === null) ? $max_start_time : intval($row['end_time']);
        $certainty = floatval($row['certainty']);
        for ($i = $attack_start_time; $i <= $attack_end_time; $i++) {
            if ($i % $bin_size == 0) {
                if ($certainty == 0.25) { // Scan attacks
                    if (isset($scan_attacks[$i])) {
                        $scan_attacks[$i]++;
                    } else {
                        $scan_attacks[$i] = 1;
                    }
                } else if ($certainty == 0.4 || $certainty == 0.5) { // Brute-force attacks
                    if (isset($bruteforce_attacks[$i])) {
                        $bruteforce_attacks[$i]++;
                    } else {
                        $bruteforce_attacks[$i] = 1;
                    }
                } else if ($certainty == 0.65 || $certainty == 0.75) { // Compromise attacks
                    if (isset($compromise_attacks[$i])) {
                        $compromise_attacks[$i]++;
                    } else {
                        $compromise_attacks[$i] = 1;
                    }
                }
            }
        }
    }

    // Make sure that all arrays use the same set of keys
    foreach ($scan_attacks as $time => $attacks) {
        if (!isset($bruteforce_attacks[$time])) $bruteforce_attacks[$time] = 0;
        if (!isset($compromise_attacks[$time])) $compromise_attacks[$time] = 0;
    }
    foreach ($bruteforce_attacks as $time => $attacks) {
        if (!isset($scan_attacks[$time])) $scan_attacks[$time] = 0;
        if (!isset($compromise_attacks[$time])) $compromise_attacks[$time] = 0;
    }
    foreach ($compromise_attacks as $time => $attacks) {
        if (!isset($scan_attacks[$time])) $scan_attacks[$time] = 0;
        if (!isset($bruteforce_attacks[$time])) $bruteforce_attacks[$time] = 0;
    }

    // Make sure that arrays are sorted by their keys (time), as that is a requirement of flot's 'stack' plugin
    ksort($scan_attacks);
    ksort($bruteforce_attacks);
    ksort($compromise_attacks);

    $result['status'] = 0;
    $result['data']['scan'] = $scan_attacks;
    $result['data']['bruteforce'] = $bruteforce_attacks;
    $result['data']['compromise'] = $compromise_attacks;

    echo json_encode(($result));
    die();

?>