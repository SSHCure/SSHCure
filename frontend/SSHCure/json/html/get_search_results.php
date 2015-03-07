<?php
/******************************************************
 # search.action.php
 # Authors:		Rick Hofstede <r.j.hofstede@utwente.nl>
 #              Luuk Hendriks
 # University of Twente, The Netherlands
 #
 # LICENSE TERMS: 3-clause BSD license (outlined in license.html)
 *****************************************************/

require_once("../../config.php");
define("TWIG_PATH", "../../lib/Twig");
define("TEMPLATE_PATH", "../../templates");
header("content-type: application/json");


// Prepare IP search string
$ip_search_string_min = "";
$ip_search_string_max = $ip_search_string_min;
$ip = $_GET['ip'];
//if ($system->getIPVersion($_REQUEST['q']) == 4) { // IPv4
if (strpos($ip, ':') === false ) { // IPv4
    $octets = explode(".", $ip);
    
    for ($i = 0; $i < 4; $i++) {
        if ($ip_search_string_min !== "" || $ip_search_string_max !== "") {
            $ip_search_string_min .= ".";
            $ip_search_string_max .= ".";
        }
        
        if ($i < sizeof($octets) && $octets[$i] !== "%" && $octets[$i] !== "") {
            $ip_search_string_min .= $octets[$i];
            $ip_search_string_max .= $octets[$i];
        } else {
            $ip_search_string_min .= "0";
            $ip_search_string_max .= "255";
        }
    }
//} else if ($system->getIPVersion($_REQUEST['q']) == 6) { // IPv6
} else {
    $octets = explode(":", $ip);
    
    for ($i = 0; $i < 8; $i++) {
        if ($ip_search_string_min !== "" || $ip_search_string_max !== "") {
            $ip_search_string_min .= ":";
            $ip_search_string_max .= ":";
        }
        
        if ($i < sizeof($octets) && $octets[$i] !== "%" && $octets[$i] !== "") {
            $ip_search_string_min .= $octets[$i];
            $ip_search_string_max .= $octets[$i];
        } else {
            $ip_search_string_min .= "0";
            $ip_search_string_max .= "ffff";
        }
    }
}


$db = new PDO($config['database.dsn']);
// Target instances
$query = "
SELECT			t.target_ip as ip
			,	count(*) as nr_of_target_occurrences
FROM			target t
WHERE			t.target_ip >= :ip_min
            and t.target_ip <= :ip_max
GROUP BY		t.target_ip
ORDER BY		t.target_ip asc
LIMIT 1000";


$stmnt = $db->prepare($query);


$stmnt->execute(array(
	'ip_min'						=> ip2long($ip_search_string_min),
    'ip_max'						=> ip2long($ip_search_string_max)
));
$db_result = $stmnt->fetchAll(PDO::FETCH_ASSOC);

$ret = array();
foreach($db_result as &$row) {
	//$row['label'] = $system->prepareIP($row['ip']);
	$row['label'] = long2ip($row['ip']);
	$row['ranking'] = $row['target_count'] = $row['nr_of_target_occurrences'];
	$row['attacker_count'] = 0;
	//$row['url'] = $system->getURLForAction('host',array('id'=>$row['ip']));
	$row['type'] = 'host';
	
	$ret[$row['ip']] = $row;
}
unset($row);

// Attacker instances
$queryString = "
SELECT			a.attacker_ip as ip
			,	count(*) as nr_of_attacker_occurrences
FROM			attack a
WHERE			a.attacker_ip >= :ip_min
            and a.attacker_ip <= :ip_max
GROUP BY		a.attacker_ip
ORDER BY		a.attacker_ip asc
LIMIT 1000";

$stmnt = $db->prepare($queryString) or die("Error in query: ".print_r($db->errorInfo(),true));
$stmnt->execute(array(
	'ip_min'						=> ip2long($ip_search_string_min),
    'ip_max'						=> ip2long($ip_search_string_max)
));
$db_result = $stmnt->fetchAll(PDO::FETCH_ASSOC);

foreach($db_result as &$row) {
	//$row['label'] = $system->prepareIP($row['ip']);
	$row['label'] = long2ip($row['ip']);
	$row['ranking'] = $row['attacker_count'] = $row['nr_of_attacker_occurrences'];
	$row['target_count'] = 0;
	//$row['url'] = $system->getURLForAction('host', array('id' => $row['ip']));
	$row['type'] = 'host';
	
	if (isset($ret[$row['ip']])) {
		$ret[$row['ip']]['ranking'] += $row['ranking'];
		$ret[$row['ip']]['attacker_count'] += $row['attacker_count'];
	} else {
		$ret[$row['ip']] = $row;
	}
}
unset($row);

function sort_by_ranking($a,$b) {
	return $b['ranking'] - $a['ranking'];
}

usort($ret,'sort_by_ranking');

//$table = $system->generateTableJSON($ret, array('label' => 'Label', 'ranking' => 'Ranking', 'type' => 'Type'));
//$system->respondJSON(array('error' => 0, 'type' => 'table', 'table' => $table));


    require_once(TWIG_PATH.'/Autoloader.php');
    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());
    $result['data'] = $twig->render('search_results.twig', array(
        'results' => $ret
    ));

    //TODO add also all the points for flot, and return in json

 
    echo json_encode($result);
    die();
