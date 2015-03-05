<?php
    
    require_once("../../config.php");
    define("TWIG_PATH", "../../lib/Twig");
    define("TEMPLATE_PATH", "../../templates");
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

    $row = $db_result[0];
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

    // instead of returning JSON, we now directly use it
    // render via twig
    // and return ready-to-use HTML
    /* Render page */
    require_once(TWIG_PATH.'/Autoloader.php');


    $end_time = ($row['end_time'] == 0) ? 'Ongoing' : $row['end_time'];

    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());
    $result['data'] = $twig->render('attack-details.twig', array(
        'attacker'      => long2ip($row['attacker_ip']),
        'certainty'     => $row['certainty'], //'TODO',
        'start_time'    => (new DateTime("@" . (int)$row['start_time'] * 1))->format("D. M j, Y H:i"),
        'end_time'      => $end_time,
        'total_flows'   => 'TODO',
        'total_packets' => 'TODO',
        'total_bytes'   => 'TODO',
    ));

    //TODO add also all the points for flot, and return in json

 
    echo json_encode($result);
    die();
?>
