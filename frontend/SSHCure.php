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
    echo "<link href='https://fonts.googleapis.com/css?family=Roboto' rel='stylesheet'>";
    echo "<div style='
                background: linear-gradient(180deg, white, #d3d3d3) repeat scroll 0 0 rgba(0, 0, 0, 0);
                font-family:\"Roboto\",sans-serif;
                font-size:14px;
                height:100%;
                width:100%;
                text-align: center;
                padding-top: 50px; '>";
    echo    "<p>Click on the logo below to load SSHCure in a new window</p>";
    echo    "<a href='plugins/SSHCure/index.php' target='_blank'><img src='plugins/SSHCure/img/sshcure_logo.png' /></a>";
    echo "</div>";
}
