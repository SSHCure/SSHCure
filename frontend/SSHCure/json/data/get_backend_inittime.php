<?php
/******************************************************
 # backendinittime.action.php
 # Authors:		Rick Hofstede <r.j.hofstede@utwente.nl>
 #              Luuk Hendriks
 # University of Twente, The Netherlands
 #
 # LICENSE TERMS: 3-clause BSD license (outlined in license.html)
 *****************************************************/

    require_once("../../config.php");
    header("content-type: application/json");
    require_once("/var/www/nfsen/conf.php");
    require_once("/var/www/nfsen/nfsenutil.php");

    if (!function_exists('ReportLog')) {
        function ReportLog() {
            // dummy function to avoid PHP errors
        }
    }
    $out_list = nfsend_query("SSHCure::get_backend_init_time", array());
    echo json_encode($out_list);
    die();
?>
