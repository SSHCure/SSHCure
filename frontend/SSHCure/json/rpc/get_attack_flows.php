<?php
/******************************************************
 # attackflow.action.php
 # Authors:		Rick Hofstede <r.j.hofstede@utwente.nl>
 #              Luuk Hendriks
 # University of Twente, The Netherlands
 #
 # LICENSE TERMS: 3-clause BSD license (outlined in license.html)
 *****************************************************/

require_once("../../config.php");
require_once("/var/www/nfsen/conf.php");
require_once("/var/www/nfsen/nfsenutil.php");
//header("content-type: application/json");

define("TWIG_PATH", "../../lib/Twig");
define("TEMPLATE_PATH", "../../templates");
header("content-type: application/json");


if (!function_exists('ReportLog')) {
	function ReportLog() {
	    // dummy function to avoid PHP errors
	}
}

$attack_ID = $_GET['attack_id'];
$target_ID = (isset($_GET['target_ip']) ? $_GET['target_ip'] : false);
$start_time = (isset($_GET['start_time']) ? $_GET['start_time'] : false);
$end_time = (isset($_GET['end_time']) ? $_GET['end_time'] : false);
$attacker_IP = (isset($_GET['attacker_IP']) ? $_GET['attacker_IP'] : false);

/* NfSen backend RPC calls */
$nfdump_version = nfsend_query("SSHCure::get_nfdump_version", array('options' => array()));
$nfdump_version = $nfdump_version['nfdump_version'];

$nfsen_profiledatadir = nfsend_query("SSHCure::get_nfsen_profiledatadir", array('options' => array()));
$nfsen_profiledatadir = $nfsen_profiledatadir['nfsen_profiledatadir'];

$profile = nfsend_query("SSHCure::get_backend_profile", array('options' => array()));
$profile = $profile['backend_profile'];

$sources = nfsend_query("SSHCure::get_backend_sources", array('options' => array()));
$sources = $sources['backend_sources'];

// Retrieve attack data if attack start and end time have not been provided in advance
if ($start_time == false || $end_time == false || $attacker_IP == false) {
    $db = new PDO($config['database.dsn']);
    $query = "SELECT * FROM attack a WHERE a.id = :attack_ID LIMIT 1";
    $stmnt = $db->prepare($query);
    $stmnt->bindParam(":attack_ID", $attack_ID);
    $stmnt->execute();
    
    $result = $stmnt->fetchAll(PDO::FETCH_ASSOC);

    // Since the query contains 'LIMIT 1', the loop will only execute once
    foreach($result as $row) {
        $start_time = $row['start_time'];
        $end_time = $row['end_time'];
        $attacker_IP = $row['attacker_ip'];
    } unset ($result);
}

$start_time = intval($start_time);
$start_file = get_nfcapd_file_name($start_time - (5 * 60), true); // Use 5 minutes buffer time

$end_time = intval($end_time);
if ($end_time == 0 || time() - $end_time < 600) { // Attack is ongoing or has just ended (within 10 minutes)
    $buffer_time = -1 * 60 * (intval(date('i')) % 5); // Go back to the last 5 minute interval
    $buffer_time += -5 * 60; // Go 5 minutes back in time to ensure nfcapd file exists

    if ($end_time == 0) $end_time = time();

    $end_file = get_nfcapd_file_name($end_time + $buffer_time, true);
} else {
    $end_file = get_nfcapd_file_name($end_time + (5 * 60), true); // Use 5 minutes buffer time
}

// Check nfdump version to determine correct parameter for start time sorting
if ($nfdump_version && intval(str_replace(".", "", $nfdump_version)) >= 168) {
    $sort_param = " -O tstart";
} else {
    $sort_param = " -m";
}

// Attacker IP address only has to be converted in case it is IPv4
if (strpos($attacker_IP, ':') === false ) {
    $attacker_ip = long2ip($attacker_IP);
}

// Prepare result array
$attack_data = array('info' => array(), 'data' => array(), 'attacker' => $attacker_ip);
if ($target_ID !== false) {
    $attack_data['target'] = $target_ID;
}

$filter = array(); $run = array();

if ($target_ID === false) { // attack statistics
	$filter[] = 'src ip '.$attacker_ip.' and port 22 and proto tcp';
    $run[] = '-A srcip';
    $run[] = '-Nq';
    $run[] = '-o "fmt:json://{\"start_time\":\"%ts\",\"end_time\":\"%te\",\"source_ip\":\"%sa\",\"packets\":\"%pkt\",\"bytes\":\"%byt\",\"flows\":\"%fl\"}"';
} else { // attacker <-> target flows
    //$target_ip = long2ip($target_ID);
    $target_ip = $target_ID;
	$filter[] = 'ip '.$attacker_ip.' and ip '.$target_ip.' and port 22 and proto tcp';
	$run[] = $sort_param;
    $run[] = '-q';
	//$run[] = '-c '.System::getInstance()->config('nfsen.list-flows-max', '5000');
	$run[] = '-c '.$config['nfsen.list-flows-max'];
	$run[] = '-o "fmt:json://{\"start_time\":\"%ts\",\"end_time\":\"%te\",\"duration\":\"%td\",\"flags\":\"%flg\",\"source_ip\":\"%sa\",\"source_port\":\"%sp\",\"destination_ip\":\"%da\",\"destination_port\":\"%dp\",\"packets\":\"%pkt\",\"bytes\":\"%byt\"}"';
    //$run[] = '-o pipe';
}

$run[] = '-R '.$start_file.':'.$end_file;
$options['args'] = implode(' ', $run);
$options['profile'] = $profile;

// Determine first source, in case multiple sources should be queried
if (strpos($sources, ':') === FALSE) {
    $first_source = $sources;
} else {
    $sources_tmp = explode(':', $sources);
    $first_source = $sources_tmp[0];
}

// Check whether the start and end file exist. If not, we're either 1) working with a shadow profile or 2) the files have been removed from the system.
// glob (and glob_recursive) is able to deal with the various NfSen SUBDIRLAYOUTs (configured in nfsen.conf).
$found_files_start = glob_recursive("$nfsen_profiledatadir/$profile/$first_source/$start_file");
$found_files_end = glob_recursive("$nfsen_profiledatadir/$profile/$first_source/$end_file");

if (sizeof($found_files_start) == 0 && sizeof($found_files_end) == 0) {
    // Check whether the files have been removed from the system by using the 'live' profile
    $found_files_start = glob_recursive("$nfsen_profiledatadir/live/$first_source/$start_file");
    $found_files_end = glob_recursive("$nfsen_profiledatadir/live/$first_source/$end_file");

    if (sizeof($found_files_start) == 0 && sizeof($found_files_end) == 0) {
        //$system->respondJSON(array('error' => 1, 'type' => 'flows', 'flows' => $attack_data));
        echo json_encode(array('error' => 1, 'type' => 'flows', 'flows' => $attack_data));
        die();
    } else {
        $options['type'] = 'shadow';
    }
} else {
    $options['type'] = 'real';
}

$options['srcselector'] = $sources;
$options['filter'] = array(implode(' and ', $filter));

$dump = nfsend_query('run-nfdump', $options);

foreach($dump['nfdump'] as $dr) {
	$dr = str_replace("\x01", "", $dr);
    if ('json://' == substr($dr, 0, 7)) {
		$obj = json_decode(substr($dr, 7), true);
		foreach($obj as $key => &$val) {
			$val = trim($val);
			if ($key == 'start_time' || $key == 'end_time') {
				$val = strtotime($val);
			}
		} unset($val);
			
        if ($target_ID === false) { // attack statistics
            $attack_data['info']['total flows'] = number_format_SI($obj['flows']);
            $attack_data['info']['total packets'] = number_format_SI($obj['packets']);
            $attack_data['info']['total bytes'] = number_format_SI($obj['bytes']);
        } else { // attacker <-> target flows
            $attack_data['data'][] = $obj;
        }
    }
}

$attack_data['success'] = ($dump['exit'] == 0);	
$attack_data['dump'] = $dump;
$attack_data['startcf'] = $start_file;
$attack_data['endcf'] = $end_file;

// Check for errors during nfdump data retrieval
$error = ($attack_data['success']) ? 0 : 1;

//$system->respondJSON(array('error' => $error, 'type' => 'flows', 'flows' => $attack_data));
//echo json_encode(array('error' => $error, 'type' => 'flows', 'flows' => $attack_data));

require_once(TWIG_PATH.'/Autoloader.php');


Twig_Autoloader::register();

$loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
$twig = new Twig_Environment($loader, array());
$html = $twig->render('attack-flows.twig', array(
    'flows'         => $attack_data['data']
));

echo json_encode(array('html' => $html, 'type' => 'flows', 'flows' => $attack_data));
die();


function get_nfcapd_file_name ($timestamp, $floor = false) {
    $nfcapd_file_rotation_time = 300;
    $closest_interval = $nfcapd_file_rotation_time * (($timestamp - ($timestamp % $nfcapd_file_rotation_time)) / $nfcapd_file_rotation_time);
    if (!$floor) {
        $closest_interval += $nfcapd_file_rotation_time;
    }

	$file_name = 'nfcapd.'.date('YmdHi', $closest_interval);
	return $file_name;
}

function number_format_SI ($number) {
    $KILO = 1000;
    $MEGA = $KILO * 1000;
    $GIGA = $MEGA * 1000;
    $TERA = $GIGA * 1000;

    if ($number >= $KILO && $number < $MEGA) {
        $formatted_number = round($number / $KILO, 2)." K";
    } else if ($number >= $MEGA && $number < $GIGA) {
        $formatted_number = round($number / $MEGA, 2)." M";
    } else if ($number >= $GIGA && $number < $TERA) {
        $formatted_number = round($number / $GIGA, 2)." G";
    } else if ($number >= $TERA) {
        $formatted_number = round($number / $TERA, 2)." T";
    } else {
        $formatted_number = $number;
    }

    return $formatted_number;
}

/*
 * Recursive variant of the PHP's glob function.
 */
function glob_recursive ($pattern, $flags = 0) {
    $files = glob($pattern, $flags);

    foreach (glob(dirname($pattern).'/*', GLOB_ONLYDIR|GLOB_NOSORT) as $dir) {
        $files = array_merge($files, glob_recursive($dir.'/'.basename($pattern), $flags));
    }

    return $files;
}
    
?>
