<?php

require_once 'lib/_autoload.php';

use \RestService\Utils\Config as Config;
use \SspApi\PdoStorage as PdoStorage;

$config = new Config(dirname(__DIR__) . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "config.ini");

$storage = new PdoStorage($config);
$sql = file_get_contents('schema/db.sql');
$storage->dbQuery($sql);
