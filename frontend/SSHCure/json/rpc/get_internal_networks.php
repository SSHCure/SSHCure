<?php

    require_once("../../config.php");
    require_once("/var/www/nfsen/conf.php");
    require_once("/var/www/nfsen/nfsenutil.php");
    header("content-type: application/json");

    if (!function_exists('ReportLog')) {
        function ReportLog() {
            // dummy function to avoid PHP errors
        }
    }

    // Resume session
    session_start();

    $out_list = nfsend_query("SSHCure::get_internal_networks", array());
    echo json_encode($out_list['internal_networks']);
    unset($_SESSION['nfsend']);
    
    die();

?>