<?php
    
    define("TWIG_PATH", "../../lib/Twig");
    define("TEMPLATE_PATH", "../../templates");

    require_once("../../config.php");
    require_once("../../lib/MaxMind/geoipcity.inc");
    header("content-type: application/json");

    // Parse and process parameters
    if (isset($_GET['host'])) {
        $host = $_GET['host'];
    } else {
        $result['status'] = 1;
        echo json_encode($result);
        die();
    }

    // Check whether host has IPv4 or IPv6 address
    if (substr_count($host, '.') == 3) {
        $geo_db_handle = geoip_open("../../".$config['maxmind_IPv4.path'], GEOIP_STANDARD);
        $host_address_db = ip2long($host);
    } else if (substr_count($host, ':') == 1) {
        $geo_db_handle = geoip_open("../../".$config['maxmind_IPv6.path'], GEOIP_STANDARD);
        $host_address_db = $host;
    } else {
        $result['status'] = 1;
        echo json_encode($result);
        die();
    }

    $db = new PDO($config['database.dsn']);

    /* Perform geolocation */
    $geo_record = geoip_record_by_addr($geo_db_handle, $host);
    //TODO let this timeout or something (check Surfmap code)
    $country = $geo_record->country_name;

    if (isset($geo_record->country_name)) {
        $country = $geo_record->country_name;
    } else {
        $country = "--";
    }

    if (isset($geo_record->city)) {
        $city = $geo_record->city;
    } else {
        $city = "--";
    }

    geoip_close($geo_db_handle);

    /* Find attacks in which the current host is an attacker */
    $query_attacks_attacker = "
    SELECT      a.id,
                a.attacker_ip,
                a.start_time,
                a.certainty,
                a.direction
    FROM        attack a
    WHERE       a.attacker_ip = :attacker_ip
    LIMIT       100";

    $stmnt = $db->prepare($query_attacks_attacker);
    $stmnt->bindParam(":attacker_ip", $host_address_db);
    $stmnt->execute();

    $db_result_attacks_attacker = $stmnt->fetchAll(PDO::FETCH_ASSOC);
    unset($stmnt);

    $attacks_attacker = array();
    foreach ($db_result_attacks_attacker as $row) {
        $record = [];

        if (is_numeric($row['attacker_ip'])) { // IPv4
            $record['attacker'] = long2ip($row['attacker_ip']);
        } else { // IPv6
            $record['attacker'] = $row['attacker_ip'];
        }
        
        $record['start_time']   = (int) $row['start_time']; // cast to int to round it, so Twig can use it's date function
        $record['certainty']    = $row['certainty'];
        $record['id']    = $row['id'];
        $record['direction']    = ($row['direction'] == 0) ? 'incoming' : 'outgoing';

        array_push($attacks_attacker, $record);
    }

    // Prepare query string for easy readability (for debugging purposes)
    $query_attacks_attacker = preg_replace('!\s+!', ' ', $query_attacks_attacker); // Replaces multiple spaces by single space
    $query_attacks_attacker = str_replace(' ,', ',', $query_attacks_attacker);
    $query_attacks_attacker = trim($query_attacks_attacker);

    /* Find attacks in which the current host is a target */
    $query_attacks_target = "
    SELECT      a.id,
                a.attacker_ip,
                a.start_time,
                t.certainty,
                a.direction
    FROM        attack a
    INNER JOIN  target t
            ON  a.id = t.attack_id
    WHERE       t.target_ip = :target_ip
    LIMIT       100";

    $stmnt = $db->prepare($query_attacks_target);
    $stmnt->bindParam(":target_ip", $host_address_db);
    $stmnt->execute();

    $db_result_attacks_target = $stmnt->fetchAll(PDO::FETCH_ASSOC);
    unset($stmnt);

    $attacks_target = array();
    foreach ($db_result_attacks_target as $row) {
        $record = [];

        if (is_numeric($row['attacker_ip'])) { // IPv4
            $record['attacker'] = long2ip($row['attacker_ip']);
        } else { // IPv6
            $record['attacker'] = $row['attacker_ip'];
        }
        
        $record['start_time']   = (int)$row['start_time']; // cast to int to round it, so Twig can use it's date function
        $record['certainty']    = $row['certainty'];
        $record['id']    = $row['id'];
        $record['direction']    = ($row['direction'] == 0) ? 'incoming' : 'outgoing';

        array_push($attacks_target, $record);
    }

    // Prepare query string for easy readability (for debugging purposes)
    $query_attacks_target = preg_replace('!\s+!', ' ', $query_attacks_target); // Replaces multiple spaces by single space
    $query_attacks_target = str_replace(' ,', ',', $query_attacks_target);
    $query_attacks_target = trim($query_attacks_target);

    // Perform reverse DNS lookup
    $domain = gethostbyaddr($host);

    /* Render page */
    require_once(TWIG_PATH.'/Autoloader.php');

    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());

    $result['status'] = 0;
    $result['query'] = array($query_attacks_attacker, $query_attacks_target);
    $result['data'] = $twig->render('host-details.twig', array(
            'host' => $host,
            'domain' => $domain,
            'country' => $country,
            'city' => $city,
            'attacks_attacker' => $attacks_attacker,
            'attacks_target' => $attacks_target
    ));

    echo json_encode($result);
    die();

?>
