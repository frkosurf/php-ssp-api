<?php

namespace SspApi;

use \Exception as Exception;
use \RestService\Utils\Config as Config;
use \SimpleSAML_Metadata_SAMLBuilder as SimpleSAML_Metadata_SAMLBuilder;

class Entity
{
    private $_c;

    public function __construct(Config $c)
    {
        $this->_c = $c;

        $sspPath = $this->_c->getSectionValue('simpleSAMLphp', 'sspPath') . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . '_autoload.php';
        if (!file_exists($sspPath) || !is_file($sspPath) || !is_readable($sspPath)) {
            throw new EntityException("invalid path to simpleSAMLphp");
        }
        require_once $sspPath;
    }

    public function verifyJson($type, $entityJson)
    {
        $entityData = json_decode($entityJson, TRUE);
        if (NULL === $entityData || !is_array($entityData)) {
            throw new EntityException("unable to decode data");
        }
        $this->verify($type, $entityData);
    }

    public function verify($type, array $entityData)
    {
        if (!in_array($type, array ("saml20-idp-remote", "saml20-sp-remote"))) {
            throw new EntityException("unsupported metadata type");
        }

        // we need to have a non-empty entityid entry
        if (!array_key_exists("entityid", $entityData) || empty($entityData['entityid'])) {
            throw new EntityException("missing or empty entityid");
        }

        try {
            $builder = new SimpleSAML_Metadata_SAMLBuilder($entityData['entityid']);
            $builder->addMetadata($type, $entityData);
            $builder->addOrganizationInfo($entityData);
        } catch (Exception $ee) {
            throw new EntityException($ee->getMessage());
        }

        if ("saml20-sp-remote" === $type) {
            $this->verifySP($entityData);
        }
        if ("saml20-idp-remote" === $type) {
            $this->verifyIdP($entityData);
        }
    }

    public function verifySP(array $entityData)
    {
        // must have IDPList array entry and can have some IdPs listed there
        if (!array_key_exists("IDPList", $entityData) || !is_array($entityData['IDPList'])) {
            throw new EntityException("IDPList key must be set and must be an array");
        }

        $storage = new PdoStorage($this->_c);

        // all mentioned IdPs MUST exist
        foreach ($entityData['IDPList'] as $eid) {
            if (FALSE === $storage->getEntity("saml20-idp-remote", $eid)) {
                throw new EntityException("IdP in IDPList '" . $eid . "' does not exist");
            }
        }

        // SP MUST have "attributes"
        if (!array_key_exists("attributes", $entityData) || !is_array($entityData['attributes'])) {
            throw new EntityException("attributes key must be set and must be an array");
        }

#        // SP MUST have an ACS
#        if (!array_key_exists("AssertionConsumerService", $entityData)) {
#            throw new EntityException("missing AssertionConsumerService");
#        }
#        if (!is_array($entityData["AssertionConsumerService"])) {
#            throw new EntityException("invalid AssertionConsumerService");
#        }
#        if (0 === count($entityData["AssertionConsumerService"])) {
#            throw new EntityException("no AssertionConsumerService endpoints");
#        }

    }

    public function verifyIdP(array $entityData)
    {
#        // IdP MUST have a SSO
#        if (!array_key_exists("SingleSignOnService", $entityData)) {
#            throw new EntityException("missing SingleSignOnService");
#        }
#        if (!is_array($entityData["SingleSignOnService"])) {
#            throw new EntityException("invalid SingleSignOnService");
#        }
#        if (0 === count($entityData["SingleSignOnService"])) {
#            throw new EntityException("no SingleSignOnService endpoints");
#        }

#        // IdP MUST have a valid certificate
#        $validCert = FALSE;

#        // we need a string certData (non empty)
#        if (array_key_exists("certData", $entityData) && !empty($entityData['certData'])) {
#            $validCert = TRUE;
#        }

#        // or a signing 'keys' entry
#        if (array_key_exists("keys", $entityData) && is_array($entityData['keys'])) {
#            foreach ($entityData['keys'] as $key) {
#                if (is_array($key)) {
#                    if (array_key_exists("signing", $key) && $key['signing'] && array_key_exists("type",$key) && "X509Certificate" === $key['type'] && array_key_exists("X509Certificate", $key) && !empty($key['X509Certificate'])) {
#                        $validCert = TRUE;
#                    }
#                }
#            }
#        }

#        if (!$validCert) {
#            throw new EntityException("invalid certificate or fingerprint");
#        }
    }
}
