<?php

    define("TWIG_PATH", "lib/Twig");
    define("TEMPLATE_PATH", "templates");

    require_once(TWIG_PATH.'/Autoloader.php');

    Twig_Autoloader::register();

    $loader = new Twig_Loader_Filesystem(TEMPLATE_PATH);
    $twig = new Twig_Environment($loader, array());

    // Determine action and block name
    $action = (isset($_GET['action'])) ? preg_replace("/[^a-zA-Z]/", "", $_GET['action']) : NULL;
    if (is_null($action) || $action === "" || !file_exists("templates/".$action.".twig")) {
        $action = 'dashboard';
    }

    $block = (isset($_GET['block'])) ? $_GET['block'] : NULL;
    $template = $twig->loadTemplate($action.'.twig');

    if (is_null($block)) {
        echo $template->render(array());
    } else {
        echo $template->renderBlock($block, array());
    }

?>