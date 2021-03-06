<?php
    
    require_once("../../config.php");
    header("content-type: application/json");

    $query = "
        SELECT      t.target_ip AS target,
                    (SELECT COUNT(*) FROM target t2 WHERE t2.target_ip = t.target_ip) AS attack_count,
                    COUNT(*) AS compromise_count
        FROM        target t
        WHERE       t.certainty >= 0.4
                AND t.certainty <= 0.5
        GROUP BY    t.target_ip
        ORDER BY    attack_count DESC,
                    compromise_count DESC
        LIMIT       5";
    
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
    $result['data'] = array();

    foreach ($db_result as $row) {
        $record = array();
        $record['target'] = long2ip($row['target']);
        $record['attack_count'] = $row['attack_count'];
        $record['compromise_count'] = $row['compromise_count'];

        array_push($result['data'], $record);
    }

    echo json_encode($result);
    die();

?>