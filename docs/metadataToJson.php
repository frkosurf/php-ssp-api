<?php
// script to convert SAML metadata from URL or file to JSON
if ($argc < 2) {
    die("please specify the metadata file or URL to parse." . PHP_EOL);
}

$metadataFile = $argv[1];
$baseDir = "/Library/WebServer/Documents/frkonext/ssp/proxy";

require_once $baseDir . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . '_autoload.php';
require_once $baseDir . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.php';

$x = SimpleSAML_Metadata_SAMLParser::parseFile($metadataFile);

$metadata = $x->getMetadata20IdP();
if (NULL === $metadata) {
    $metadata = $x->getMetadata20SP();
}
if (NULL === $metadata) {
    die("unable to find either IdP or SP metadata" . PHP_EOL);
}

if (array_key_exists("entityDescriptor", $metadata)) {
    unset ($metadata['entityDescriptor']);
}

if ("saml20-sp-remote" === $metadata['metadata-set']) {
    $metadata['IDPList'] = array();
}

echo json_encode(array($metadata));
