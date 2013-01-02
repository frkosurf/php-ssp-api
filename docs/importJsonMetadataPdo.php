<?php

require_once 'lib/_autoload.php';

if ($argc < 2) {
    die("please specify the path to the JSON metadata" . PHP_EOL);
}

$pathToMetadata = $argv[1];

use \RestService\Utils\Config as Config;
use \SspApi\PdoStorage as PdoStorage;

$config = new Config('config/config.ini');
$storage = new PdoStorage($config);

foreach (glob($pathToMetadata . "/*.json") as $filename) {
    $jsonMetadata = file_get_contents($filename);
    $metadata = json_decode($jsonMetadata, TRUE);
    $set = basename($filename, ".php");
    echo "importing set '$set'..." . PHP_EOL;
    foreach ($metadata as $m) {
        echo "\t" . $m['entityid'] . PHP_EOL;
        $storage->postEntry($set, $m);
    }
}
