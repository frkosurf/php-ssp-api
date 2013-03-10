<?php
// script to convert SAML metadata to
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

cleanupArray($metadata);

if (array_key_exists("entityDescriptor", $metadata)) {
    unset ($metadata['entityDescriptor']);
}

// take keys and clean the certificate, and use old SSP format
if (array_key_exists("keys", $metadata)) {
    foreach ($metadata['keys'] as $key) {
        if (array_key_exists("signing", $key) && $key['signing']) {
            // we want signing key!
            $cert = $key['X509Certificate'];
            $cert = str_replace("\n", "", $cert);
            $cert = str_replace("\r", "", $cert);
            $derCert = base64_decode($cert);
            $fingerprint = sha1($derCert);
            $metadata['certData'] = array($cert);
            $metadata['certFingerprint'] = array ($fingerprint);
            unset($metadata['keys']);
        }
    }
}
$metadata['metadata-url'] = $metadataFile;
//echo $metadata['entityid'] . " expires in " . ($metadata['expire'] - time()) . "s" . PHP_EOL;
echo json_encode($metadata);

// remove empty values recursively
function cleanupArray(array &$a)
{
    foreach ($a as $k => $v) {
        if (empty($v)) {
            unset($a[$k]);
            continue;
        }
        if (is_array($v)) {
            cleanupArray($a[$k]);
        }
    }
}
