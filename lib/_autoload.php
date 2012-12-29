<?php

require_once 'SplClassLoader.php';

$c1 = new SplClassLoader("RestService", dirname(__DIR__) . DIRECTORY_SEPARATOR . "extlib" . DIRECTORY_SEPARATOR . "php-rest-service" . DIRECTORY_SEPARATOR . "lib");
$c1->register();
$c3 = new SplClassLoader("SspApi", dirname(__DIR__) . DIRECTORY_SEPARATOR . "lib");
$c3->register();
