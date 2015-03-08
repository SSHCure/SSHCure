<?php
    
    require_once("../../config.php");
    define("TWIG_PATH", "../../lib/Twig");
    define("TEMPLATE_PATH", "../../templates");
    header("content-type: application/json");

    // Parse and process parameters
    $attack_id = $_GET['attack_id'];

    
    $query = "SELECT * FROM target t WHERE t.attack_id = ? ORDER BY certainty DESC LIMIT 1000";

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

    foreach ($db_result as &$row) {
        $row['raw_ip'] = $row['target_ip'];
        $row['target_ip'] = long2ip($row['target_ip']);
    }
    unset($row);

    $query_atk = "SELECT * FROM attack a WHERE a.id = ?";
    $stmnt = $db->prepare($query_atk);
    $stmnt->execute([$attack_id]);

    $attack = $stmnt->fetchAll(PDO::FETCH_ASSOC)[0];
    unset($stmnt);

    //foreach ($db_result as $row) {
    //    $record = [];
    //    $record['start_time'] = $row['start_time'];
    //    $record['ongoing'] = $row['end_time'] == 0;
    //    $record['certainty'] = $row['certainty'];
    //    $record['attacker'] = long2ip($row['attacker']);
    //    $record['target_count'] = $row['target_count'];

    //    array_push($result['data'], $record);
    //}

    //$result['data'] = $db_result;
    //echo json_encode($result);
    //die();


    // instead of returning JSON, we now directly use it
    // render via twig
    // and return ready-to-use HTML
    /* Render page */
    require_once(TWIG_PATH.'/Autoloader.php');


    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());
    $result['data'] = $twig->render('targets-details.twig', array(
        'attack'        => $attack,
        'targets'       => $db_result
    ));

    $result['debug'] = count($db_result);

    echo json_encode($result);
    die();

?>
