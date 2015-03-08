<?php
    
    require_once("../../config.php");
    header("content-type: application/json");

    // Parse and process parameters
    $direction = isset($_GET['outgoing']) ? 1 : 0;
    $limit = isset($_GET['limit']) ? $_GET['limit'] : 5;


    $query = "
        SELECT      a.id AS id,
                    a.start_time AS start_time,
                    a.end_time AS end_time,
                    a.certainty AS certainty,
                    a.attacker_ip AS attacker,
                    a.target_count AS target_count
        FROM        attack a
        WHERE       a.direction = ?
        ORDER BY    a.certainty DESC,
                    a.start_time DESC,
                    a.target_count DESC
        LIMIT       ?";

    $db = new PDO($config['database.dsn']);

    $stmnt = $db->prepare($query);
    $stmnt->execute([$direction, $limit]);

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
        $record['attack_id']    = $row['id'];
        $record['start_time']   = $row['start_time'];
        $record['ongoing']      = $row['end_time'] == 0;
        $record['certainty']    = $row['certainty'];
        $record['attacker']     = long2ip($row['attacker']);
        $record['target_count'] = $row['target_count'];

        array_push($result['data'], $record);
    }

    echo json_encode($result);
    die();

?>
