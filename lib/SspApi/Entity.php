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
            if (!is_string($entityData["SingleSignOnService"]) || FALSE === filter_var($entityData["SingleSignOnService"], FILTER_VALIDATE_URL)) {
                throw new EntityException("invalid SingleSignOnService");
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
            if (!is_string($entityData["AssertionConsumerService"]) || FALSE === filter_var($entityData["AssertionConsumerService"], FILTER_VALIDATE_URL)) {
                throw new EntityException("invalid AssertionConsumerService");
            }

        } else {
            throw new EntityException("support for this type not implemented");
        }

    }

}
