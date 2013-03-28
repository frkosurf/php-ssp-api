<?php

require_once '/Library/WebServer/Documents/frkonext/ssp/proxy/lib/_autoload.php';

$config = SimpleSAML_Configuration::getInstance();

if (2 >= $argc) {
    $xmldata = file_get_contents($argv[1]);

    SimpleSAML_Utilities::validateXMLDocument($xmldata, 'saml-meta');
    $entities = SimpleSAML_Metadata_SAMLParser::parseDescriptorsString($xmldata);

    /* Get all metadata for the entities. */
    foreach ($entities as &$entity) {
        $entity = array(
            'saml20-sp-remote' => $entity->getMetadata20SP(),
            'saml20-idp-remote' => $entity->getMetadata20IdP(),
            );

    }

    /* Transpose from $entities[entityid][type] to $output[type][entityid]. */
    $output = SimpleSAML_Utilities::transposeArray($entities);

    /* Merge all metadata of each type to a single string which should be
     * added to the corresponding file.
     */
    foreach ($output as $type => &$entities) {

        $jsonData = array();

        foreach ($entities as $entityId => $entityMetadata) {

            if ($entityMetadata === NULL) {
                continue;
            }

            /* Remove the entityDescriptor element because it is unused, and only
             * makes the output harder to read.
             */
            unset($entityMetadata['entityDescriptor']);

            //$text .= '$metadata[' . var_export($entityId, TRUE) . '] = ' .
            //	var_export($entityMetadata, TRUE) . ";\n";
            array_push($jsonData, $entityMetadata);
        }

        $entities = $jsonData;
    }

} else {
    $xmldata = '';
    $output = array();
}

echo json_encode($output);
