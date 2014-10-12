<?php
    
    define("TWIG_PATH", "../../lib/Twig");
    define("TEMPLATE_PATH", "../../templates");

    require_once("../../config.php");
    header("content-type: application/json");

    // Parse and process parameters
    if (isset($_GET['host'])) {
        $host = $_GET['host'];
    } else {
        $result['status'] = 1;
        echo json_encode($result);
        die();
    }
    
    $country = "The Netherlands";

    // $db = new PDO($config['database.dsn']);

    // $stmnt = $db->prepare($query);
    // $stmnt->execute();

    // $db_result = $stmnt->fetchAll(PDO::FETCH_ASSOC);
    // unset($stmnt);

    // // Prepare query string for easy readability (for debugging purposes)
    // $query = preg_replace('!\s+!', ' ', $query); // Replaces multiple spaces by single space
    // $query = str_replace(' ,', ',', $query);
    // $query = trim($query);

    require_once(TWIG_PATH.'/Autoloader.php');

    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());

    $result['status'] = 0;
    $result['data'] = $twig->render('host-details.twig', array('host' => $host, 'country' => $country));

    // foreach ($db_result as $row) {
    //     $record = [];
    //     $record['start_time'] = $row['start_time'];
    //     $record['ongoing'] = $row['end_time'] == 0;
    //     $record['certainty'] = $row['certainty'];
    //     $record['attacker'] = long2ip($row['attacker']);
    //     $record['target_count'] = $row['target_count'];

    //     array_push($result['data'], $record);
    // }

    echo json_encode($result);
    die();

?>