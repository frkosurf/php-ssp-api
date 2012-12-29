<?php

require_once 'lib/_autoload.php';

if ($argc < 2) {
    die("please specify the path to your current simpleSAMLphp installation" . PHP_EOL);
}

$pathToSsp = $argv[1];

use \RestService\Utils\Config as Config;
use \SspApi\PdoStorage as PdoStorage;

$config = new Config('config/config.ini');
$storage = new PdoStorage($config);

foreach (glob($pathToSsp . "/metadata/*.php") as $filename) {
    $metadata = array();
    require_once $filename;
    $set = basename($filename, ".php");
    echo "importing set '$set'..." . PHP_EOL;
    foreach ($metadata as $k => $v) {
        echo "\t$k" . PHP_EOL;
        $v['entityid'] = $k;
        $storage->postEntry($set, $v);
    }
}
