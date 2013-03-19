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

        // no whitespace allowed at beginning or end of entityid
        if (trim($entityData['entityid']) !== $entityData['entityid']) {
            throw new EntityException("invalid entityid, no whitespace allowed at beginning or end");
        }

        try {
            $builder = new SimpleSAML_Metadata_SAMLBuilder($entityData['entityid']);
            $builder->addMetadata($type, $entityData);
            $builder->addOrganizationInfo($entityData);
        } catch (Exception $ee) {
            throw new EntityException($ee->getMessage());
        }
    }

    public function verifyOld($type, array $entityData)
    {
        $samlBindings = array (
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
        );

        if (!in_array($type, array ("saml20-idp-remote", "saml20-sp-remote"))) {
            throw new EntityException("unsupported metadata type");
        }

        // we need to have a non-empty entityid entry
        if (!array_key_exists("entityid", $entityData) || empty($entityData['entityid'])) {
            throw new EntityException("missing or empty entityid");
        }

        // no whitespace allowed at beginning or end of entityid
        if (trim($entityData['entityid']) !== $entityData['entityid']) {
            throw new EntityException("invalid entityid, no whitespace allowed at beginning or end");
        }

        if ("saml20-idp-remote" === $type) {
            // IdP specific validation

            // SSO is required and needs to be a valid URL
            if (!array_key_exists("SingleSignOnService", $entityData)) {
                throw new EntityException("missing SingleSignOnService");
            }
            if (!is_array($entityData["SingleSignOnService"])) {
                throw new EntityException("invalid SingleSignOnService");
            }
            if (0 === count($entityData["SingleSignOnService"])) {
                throw new EntityException("no SingleSignOnService endpoints");
            }

            foreach ($entityData["SingleSignOnService"] as $sso) {
                if (!is_array($sso)) {
                    throw new EntityException("invalid SingleSignOnService entry");
                }
                if (!array_key_exists("Location", $sso)) {
                    throw new EntityException("missing SingleSignOnService Location");
                }
                if (FALSE === filter_var($sso["Location"], FILTER_VALIDATE_URL)) {
                    throw new EntityException("invalid SingleSignOnService Location");
                }
                if (!array_key_exists("Binding", $sso)) {
                    throw new EntityException("missing SingleSignOnService Binding");
                }
                if (!in_array($sso['Binding'], $samlBindings)) {
                    throw new EntityException("unsupported SingleSignOnService Binding '" . $sso['Binding'] . "'");
                }
            }

            $validCert = FALSE;
            // we need a string certData (non empty)
            if (array_key_exists("certData", $entityData) && !empty($entityData['certData'])) {
                $validCert = TRUE;
            }

            // or a certFingerprint (array) with at least one non empty element
            if (array_key_exists("certFingerprint", $entityData) && is_array($entityData['certFingerprint'])) {
                foreach ($entityData['certFingerprint'] as $fp) {
                    if (!empty($fp)) {
                        $validCert = TRUE;
                    }
                }
            }

            // or a signing 'keys' entry
            if (array_key_exists("keys", $entityData) && is_array($entityData['keys'])) {
                foreach ($entityData['keys'] as $key) {
                    if (is_array($key)) {
                        if (array_key_exists("signing", $key) && $key['signing'] && array_key_exists("type",$key) && "X509Certificate" === $key['type'] && array_key_exists("X509Certificate", $key) && !empty($key['X509Certificate'])) {
                            $validCert = TRUE;
                        }
                    }
                }
            }
            if (!$validCert) {
                throw new EntityException("invalid certificate or fingerprint");
            }

        } elseif ("saml20-sp-remote" === $type) {
            // SP specific validation

            // ACS is required and needs to be a valid URL
            if (!array_key_exists("AssertionConsumerService", $entityData)) {
                throw new EntityException("missing AssertionConsumerService");
            }
            if (!is_array($entityData["AssertionConsumerService"])) {
                throw new EntityException("invalid AssertionConsumerService");
            }
            if (0 === count($entityData["AssertionConsumerService"])) {
                throw new EntityException("no AssertionConsumerService endpoints");
            }

            foreach ($entityData["AssertionConsumerService"] as $acs) {
                // index is also allowed and should probably be checked
                if (!is_array($acs)) {
                    throw new EntityException("invalid AssertionConsumerService entry");
                }
                // location
                if (!array_key_exists("Location", $acs)) {
                    throw new EntityException("missing AssertionConsumerService Location");
                }
                if (FALSE === filter_var($acs["Location"], FILTER_VALIDATE_URL)) {
                    throw new EntityException("invalid AssertionConsumerService Location");
                }

                // binding
                if (!array_key_exists("Binding", $acs)) {
                    throw new EntityException("missing AssertionConsumerService Binding");
                }
                if (!in_array($acs['Binding'], $samlBindings)) {
                    throw new EntityException("unsupported AssertionConsumerService Binding '" . $acs['Binding'] . "'");
                }
            }

            // FIXME: all entries in IDPList *must* really exist

        } else {
            throw new EntityException("support for this type not implemented");
        }

    }

}
