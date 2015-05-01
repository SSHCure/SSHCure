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
    $result['data'] = array();

    $row = $db_result[0];

    require_once(TWIG_PATH.'/Autoloader.php');

    $end_time = ($row['end_time'] == 0) ? 'Ongoing' : (new DateTime("@" . (int)$row['end_time'] * 1))->format("D. M j, Y H:i");

    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());
    $result['data'] = $twig->render('attack-details.twig', array(
        'attacker'      => long2ip($row['attacker_ip']),
        'certainty'     => $row['certainty'], //'TODO',
        'start_time'    => (new DateTime("@" . (int)$row['start_time'] * 1))->format("D. M j, Y H:i"),
        'end_time'      => $end_time,
        'blacklisted'   => $row['attacker_blacklisted']
    ));

    //TODO add also all the points for flot, and return in json
 
    echo json_encode($result);
    die();
?>
