<?php

require_once 'SplClassLoader.php';

$c1 = new SplClassLoader("RestService", dirname(__DIR__) . "/extlib/php-rest-service/lib");
$c1->register();
$c2 = new SplClassLoader("OAuth", dirname(__DIR__) . "/extlib/php-oauth-lib-rs/lib");
$c2->register();
$c3 = new SplClassLoader("SspApi", dirname(__DIR__) . "/lib");
$c3->register();
