<?php

require_once 'lib/_autoload.php';

if ($argc < 2) {
    die("please specify the path to the JSON metadata" . PHP_EOL);
}

$pathToMetadata = $argv[1];

use \RestService\Utils\Config as Config;
use \SspApi\PdoStorage as PdoStorage;
use \SspApi\Entity as Entity;
use \SspApi\EntityException as EntityException;

$config = new Config('config/config.ini');
$storage = new PdoStorage($config);

foreach (glob($pathToMetadata . "/*-remote.json") as $filename) {
    $jsonMetadata = file_get_contents($filename);
    $metadata = json_decode($jsonMetadata, TRUE);
    $set = basename($filename, ".json");
    echo "importing set '$set'..." . PHP_EOL;
    $e = new Entity($config);
    foreach ($metadata as $m) {
        echo "\t" . $m['entityid'] . PHP_EOL;
    $m['metadata-set'] = $set;
        try {
            $e->verify($set, $m);
        } catch (EntityException $ee) {
            echo "ERROR [verify]: " . $ee->getMessage() . PHP_EOL;
            continue;
        }

        try {
            $storage->postEntity($set, $m);
        } catch (PDOException $pe) {
            echo "ERROR [database]: " . $pe->getMessage() . PHP_EOL;
        }
    }
}
