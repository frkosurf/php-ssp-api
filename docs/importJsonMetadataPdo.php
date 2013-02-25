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

foreach (glob($pathToMetadata . "/*.json") as $filename) {
    $jsonMetadata = file_get_contents($filename);
    $metadata = json_decode($jsonMetadata, TRUE);
    $set = basename($filename, ".json");
    echo "importing set '$set'..." . PHP_EOL;
    foreach ($metadata as $m) {
        echo "\t" . $m['entityid'] . PHP_EOL;
        try {
            Entity::verify($set, $m);
        } catch (EntityException $e) {
            echo "ERROR [verify]: " . $e->getMessage() . PHP_EOL;
        }

        try {
            $storage->postEntity($set, $m);
        } catch (PDOException $e) {
            echo "ERROR [database]: " . $e->getMessage() . PHP_EOL;
        }
    }
}
