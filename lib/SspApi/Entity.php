<?php

namespace SspApi;

class Entity
{

    public static function verifyJson($type, $entityJson)
    {
        $entityData = json_decode($entityJson, TRUE);
        if (NULL === $entityData) {
            throw new EntityException("unable to decode data");
        }
        self::verify($type, $entityData);
    }

    public static function verify($type, array $entityData)
    {
        if (!in_array($type, array ("saml20-idp-remote", "saml20-sp-remote"))) {
            throw new EntityException("unsupported type");
        }

        // we need to have an entityid entry
        if (!array_key_exists("entityid", $entityData)) {
            throw new EntityException("missing entityid");
        }

        // we need to have a name with at least an english language entry
        if (!array_key_exists("name", $entityData)) {
            throw new EntityException("missing name");
        }
        if (!array_key_exists("en", $entityData["name"]) || empty($entityData["name"]["en"])) {
            throw new EntityException("missing or empty english name");
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
                if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" !== $sso['Binding']) {
                    throw new EntityException("unsupported SingleSignOnService Binding");
                }
            }

            // certFingerprint checking
            if (!array_key_exists("certFingerprint", $entityData)) {
                throw new EntityException("missing certFingerprint");
            }
            if (!is_array($entityData["certFingerprint"])) {
                throw new EntityException("certFingerprint needs to be an array");
            }
            foreach ($entityData["certFingerprint"] as $fp) {
                if (empty($fp)) {
                    throw new EntityException("certFingerprint needs to contain certificate fingerprints");
                }
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

            foreach ($entityData["AssertionConsumerService"] as $acs) {
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
                if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" !== $acs['Binding']) {
                    throw new EntityException("unsupported AssertionConsumerService Binding");
                }
            }

        } else {
            throw new EntityException("support for this type not implemented");
        }

    }

}
