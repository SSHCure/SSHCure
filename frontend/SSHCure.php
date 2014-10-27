<?php
/******************************************************
 # SSHCure.php
 # Authors:		Rick Hofstede <r.j.hofstede@utwente.nl>
 #              Luuk Hendriks
 # University of Twente, The Netherlands
 #
 # LICENSE TERMS: 3-clause BSD license (outlined in license.html)
 *****************************************************/

function SSHCure_ParseInput($plugin_id) {
	$_SESSION['refresh'] = 0;
}

function SSHCure_Run($plugin_id) {
	
	# System doesn't exist anymore
	#$system = (include 'SSHCure/system/system.php') or die('Failed to load system!');
    #$system->loadConfig(BASE_DIR.'/config/defaults.php') or die('Failed to load default configuration!');
    #$system->loadConfig(BASE_DIR.'/config.php') or die('Failed to load user configuration!');

    #$url = $system->config('frontend.baseurl', '/').'index.php';

    (include 'SSHCure/config.php') or die('Failed to load user configuration!');
    $url = $config["web.root"].'/index.php';
	echo "<iframe id=\"sshcure-frame\" src=\"{$url}\" frameborder=\"0\" style=\"width: 100%; min-height: 980px; height: 90%;\">Your browser does not support iframes.</iframe>";
}
