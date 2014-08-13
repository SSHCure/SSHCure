<?php
    
    require_once("../config.php");
    header("content-type: application/json");

    $db = new PDO($config['database.dsn']);

    $query = "
    SELECT		a.id AS id,
                a.start_time AS start_time,
    			a.end_time AS end_time,
    			a.certainty AS certainty,
    			a.attacker_ip AS attacker,
    			a.target_count AS target_count
    FROM		attack a
    ORDER BY	a.certainty DESC,
                a.start_time DESC,
                a.target_count DESC
    LIMIT       5";

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
