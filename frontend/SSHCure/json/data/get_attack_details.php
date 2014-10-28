<?php
    
    require_once("../../config.php");
    header("content-type: application/json");

    // Parse and process parameters
    $attack_id = $_GET['attack_id'];

    
    $query = "SELECT * FROM attack a WHERE a.id = ?";

    $db = new PDO($config['database.dsn']);

    $stmnt = $db->prepare($query);
    $stmnt->execute([$attack_id]);

    $db_result = $stmnt->fetchAll(PDO::FETCH_ASSOC);
    unset($stmnt);

    // Prepare query string for easy readability (for debugging purposes)
    $query = preg_replace('!\s+!', ' ', $query); // Replaces multiple spaces by single space
    $query = str_replace(' ,', ',', $query);
    $query = trim($query);

    $result['status'] = 0;
    $result['query'] = $query;
    $result['data'] = [];

    //foreach ($db_result as $row) {
    //    $record = [];
    //    $record['start_time'] = $row['start_time'];
    //    $record['ongoing'] = $row['end_time'] == 0;
    //    $record['certainty'] = $row['certainty'];
    //    $record['attacker'] = long2ip($row['attacker']);
    //    $record['target_count'] = $row['target_count'];

    //    array_push($result['data'], $record);
    //}

    $result['data'] = $db_result;
    echo json_encode($result);
    die();

?>
