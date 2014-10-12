<?php
    
    require_once("../../config.php");
    header("content-type: application/json");

    // Parse and process parameters
    $internal_networks = (isset($_GET['internal_networks'])) ? $_GET['internal_networks'] : "";

    if ($internal_networks === "") {
        // No internal networks specified
        $query = "
            SELECT      a.id AS id,
                        a.start_time AS start_time,
                        a.end_time AS end_time,
                        a.certainty AS certainty,
                        a.attacker_ip AS attacker,
                        a.target_count AS target_count
            FROM        attack a
            ORDER BY    a.certainty DESC,
                        a.start_time DESC,
                        a.target_count DESC
            LIMIT       5";
    } else {
        $internal_networks = explode(',', $internal_networks);
        $networks_filter = "";
        foreach ($internal_networks as $network) {
            $network_address = substr($network, 0, strrpos($network, '/'));
            $subnet = substr($network, strrpos($network, '/') + 1);
            $range_start = ip2long($network_address);
            $range_end = $range_start + pow(2, $subnet) - 1;

            if ($networks_filter != "") $networks_filter .= " AND ";
            $networks_filter .= "a.attacker_ip >= $range_start AND a.attacker_ip <= $range_end";
        }

        $query = "
            SELECT      a.id AS id,
                        a.start_time AS start_time,
                        a.end_time AS end_time,
                        a.certainty AS certainty,
                        a.attacker_ip AS attacker,
                        a.target_count AS target_count
            FROM        attack a
            WHERE       $networks_filter
            ORDER BY    a.certainty DESC,
                        a.start_time DESC,
                        a.target_count DESC
            LIMIT       5";
    }

    $db = new PDO($config['database.dsn']);

    $stmnt = $db->prepare($query);
    $stmnt->execute();

    $db_result = $stmnt->fetchAll(PDO::FETCH_ASSOC);
    unset($stmnt);

    // Prepare query string for easy readability (for debugging purposes)
    $query = preg_replace('!\s+!', ' ', $query); // Replaces multiple spaces by single space
    $query = str_replace(' ,', ',', $query);
    $query = trim($query);

    $result['status'] = 0;
    $result['query'] = $query;
    $result['data'] = [];

    foreach ($db_result as $row) {
        $record = [];
        $record['start_time'] = $row['start_time'];
        $record['ongoing'] = $row['end_time'] == 0;
        $record['certainty'] = $row['certainty'];
        $record['attacker'] = long2ip($row['attacker']);
        $record['target_count'] = $row['target_count'];

        array_push($result['data'], $record);
    }

    echo json_encode($result);
    die();

?>