<?php

if ($argc < 2) {
    die("specify the directory to write the JSON data to" . PHP_EOL);
}

$data = array();

$pdo = new PDO("mysql:host=127.0.0.1;dbname=sr", "root", NULL);

// figure out all eids for both sp and idp that are prodaccepted and active
$sql = "SELECT eid FROM janus__entity GROUP BY eid ORDER BY eid";
$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

$data = array();

foreach ($result as $r) {
    $eid = $r['eid'];
    // figure out the latest revision of the eids and the entityid
    $sql = "SELECT entityid, revisionid, arp, state, active, type, metadataurl FROM janus__entity WHERE eid=:eid ORDER BY revisionid DESC LIMIT 0,1";
    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $eid);
    $sth->execute();
    $result = $sth->fetch(PDO::FETCH_ASSOC);

    if ("prodaccepted" !== $result['state'] || "yes" !== $result['active']) {
        // we only want prodaccepted and active entries
        continue;
    }

    $type = $result['type'];
    $data[$type][$eid]['entityid'] = $result['entityid'];

    $mdu = trim($result['metadataurl']);
    if (empty($mdu)) {

        $mdu = NULL;
    }
    if (!empty($mdu)) {
        // seems to be a metadata URL
        // check if it is valid
        if (FALSE === filter_var($mdu, FILTER_VALIDATE_URL)) {
            echo "WARNING: invalid metadata URL '" . $mdu . "'" . PHP_EOL;
            $mdu = NULL;
        }
        // echo "INFO: " . $type . " metadata URL: " . $mdu . PHP_EOL;
    } else {
        echo "WARNING: missing metadate URL for " . $result['entityid'] . PHP_EOL;
        $mdu = NULL;
    }

    $data[$type][$eid]['metadataurl'] = $mdu;

    // get ARP if entry is a service provider
    if ("saml20-sp" === $type) {
        $sql = "SELECT attributes FROM janus__arp WHERE aid = :aid";
        $sth = $pdo->prepare($sql);
        $sth->bindValue(":aid", $result['arp']);
        $sth->execute();
        $arpResult = $sth->fetch(PDO::FETCH_ASSOC);
        if (NULL !== $arpResult['attributes']) {
            $data[$type][$eid]['attributes'] = array_keys(unserialize($arpResult['attributes']));
        } else {
            $data[$type][$eid]['attributes'] = array();
        }
    }

    // figure out some metadata parameters
    $sql = "SELECT `key`, `value` FROM `janus__metadata` WHERE `eid` = :eid AND `revisionid` = :revisionid";
    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $eid);
    $sth->bindValue(":revisionid", $result['revisionid']);
    $sth->execute();
    $metadataResult = $sth->fetchAll(PDO::FETCH_ASSOC);

    $metadata = fetchMetadata($type, $metadataResult, $result['entityid']);
    if (FALSE === $metadata) {
//        echo "WARNING: " . $result['entityid'] . " missing required " . $type . " values" . PHP_EOL;
        unset($data[$type][$eid]);
        continue;
    }

    $data[$type][$eid] += $metadata;

    // get the ACL
    $sql = "SELECT `remoteeid` FROM `janus__allowedEntity` WHERE `eid` = :eid AND `revisionid` = :revisionid";
    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $eid);
    $sth->bindValue(":revisionid", $result['revisionid']);
    $sth->execute();
    $aclResult = $sth->fetchAll(PDO::FETCH_ASSOC);

    $aclList = array();
    foreach ($aclResult as $aclEntry) {
        array_push($aclList, $aclEntry['remoteeid']);
    }

    if ("saml20-sp" === $type) {
        $data[$type][$eid]['IDPList'] = $aclList;
    }
    if ("saml20-idp" === $type) {
        $data[$type][$eid]['SPList'] = $aclList;
    }
}

// now replace eids with entityids in the lists
foreach ($data as $type => $entries) {
    foreach ($entries as $eid => $values) {
        if ("saml20-sp" === $type) {
            // find the idpList
            foreach ($values['IDPList'] as $k => $v) {
                if (array_key_exists($v, $data['saml20-idp'])) {
                    $data["saml20-sp"][$eid]['IDPList'][$k] = $data['saml20-idp'][$v]['entityid'];
                } else {
                    echo "WARNING: SP " . $values['entityid'] . " (" . $eid . ") contains non-existing IdP $v" . PHP_EOL;
                    unset($data["saml20-sp"][$eid]['IDPList'][$k]);
                }
            }
        }
        if ("saml20-idp" === $type) {
            // find the spList
            foreach ($values['SPList'] as $k => $v) {
                if (array_key_exists($v, $data['saml20-sp'])) {
                    $data["saml20-idp"][$eid]['SPList'][$k] = $data['saml20-sp'][$v]['entityid'];
                } else {
                    echo "WARNING: IdP " . $values['entityid'] . " (" . $eid . ") contains non-existing SP $v" . PHP_EOL;
                    unset($data["saml20-idp"][$eid]['SPList'][$k]);
                }
            }
        }
    }
}

// verify whether ACL entries on the SP side have matching entry on the IdP side
foreach ($data['saml20-sp'] as $k => $v) {
    if (!empty($v['IDPList'])) {
        // echo "SP " . $spEntry['entityid'] . " has " . count($v['IDPList']) . " IdPs in the ACL" . PHP_EOL;
        foreach ($v['IDPList'] as $idp) {
        //    echo "\t" . $idp . PHP_EOL;
            // look for this SP in the idpList
            foreach ($data['saml20-idp'] as $idpEntry) {
                if ($idpEntry['entityid'] === $idp) {
                    if (!in_array($v['entityid'], $idpEntry['SPList'])) {
                        echo "WARNING: SP " . $v['entityid'] . " not found at IdP " . $idp . PHP_EOL;
                    }
                }
            }
        }
        // empty the idpList, we fill this from the IdP side later
        $data['saml20-sp'][$k]['IDPList'] = array();
    }
}

// now for every IdP add its entityid to the idpList of the SP it lists in its
// spList
foreach ($data['saml20-idp'] as $k => $v) {
    foreach ($v['SPList'] as $sp) {
        // look for $sp in the saml20-sp data structure
        foreach ($data['saml20-sp'] as $spKey => $spEntry) {
            if ($spEntry['entityid'] === $sp) {
                array_push($data['saml20-sp'][$spKey]['IDPList'], $v['entityid']);
            }
        }
    }

    // remove the spList entry as all ACLs are now configured at the SP
    unset($data['saml20-idp'][$k]['SPList']);
}

// print all list of unique attributes used in the ARPs of all SPs
$allAttributes = array();
foreach ($data['saml20-sp'] as $k => $v) {
    foreach ($v['attributes'] as $a) {
        if (!in_array($a, $allAttributes)) {
            array_push($allAttributes, $a);
        }
    }
}
echo "ALL ATTRIBUTES USED IN 'ARP':" . PHP_EOL;
echo json_encode($allAttributes) . PHP_EOL;

$idpList = array_values($data["saml20-idp"]);
$spList = array_values($data["saml20-sp"]);

// write data for IdPs to JSON file
$encoding = json_encode($idpList);
file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "saml20-idp-remote.json", $encoding);

// write data for SPs to JSON file
$encoding = json_encode($spList);
file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "saml20-sp-remote.json", $encoding);

function fetchMetadata($type, array $result, $entityId)
{
    $metadata = array();

    if ("saml20-idp" === $type) {

        $name = array();
        $displayName = array();

        $keywords = array();
        $contacts = array();

        $metadata['certFingerprint'] = array();

        foreach ($result as $entry) {
            if ($entry['key'] === 'SingleSignOnService:0:Location') {
                $metadata['SingleSignOnService'] = $entry['value'];
            }
            if ($entry['key'] === 'SingleLogoutService:0:Location') {
                $metadata['SingleLogoutService'] = $entry['value'];
            }

            // logo
            if ($entry['key'] === 'logo:0:url' && !empty($entry['value'])) {
                $metadata['UIInfo']['Logo']['url'] = $entry['value'];
            }

            if ($entry['key'] === 'logo:0:width' && is_numeric($entry['value'])) {
                $metadata['UIInfo']['Logo']['width'] = (int) $entry['value'];
            }

            if ($entry['key'] === 'logo:0:height' && is_numeric($entry['value'])) {
                $metadata['UIInfo']['Logo']['height'] = (int) $entry['value'];
            }

            // contacts
            if (strpos($entry['key'], 'contacts:') === 0) {
                // determine number
                list($c_foo, $c_no, $c_t) = explode(":", $entry['key']);
                $contacts[$c_no][$c_t] = $entry['value'];
            }

            // name
            if (strpos($entry['key'], 'name:') === 0) {
                list(, $c_lang) = explode(":", $entry['key']);
                $name[$c_lang] = $entry['value'];
            }
            // displayName
            if (strpos($entry['key'], 'displayName:') === 0) {
                list(, $c_lang) = explode(":", $entry['key']);
                $displayName[$c_lang] = $entry['value'];
            }

            // keywords
            if ($entry['key'] === 'keywords:en') {
                $keywords["en"] = explode(" ", $entry['value']);
            }
            if ($entry['key'] === 'keywords:nl') {
                $keywords["nl"] = explode(" ", $entry['value']);
            }

            // certificate
            if ($entry['key'] === "certData") {
                array_push($metadata['certFingerprint'], sha1(base64_decode($entry['value'])));
            }
            if ($entry['key'] === "certData2") {
                array_push($metadata['certFingerprint'], sha1(base64_decode($entry['value'])));
            }
        }

        cleanupName($entityId, $metadata, $name, $displayName);

        // cleanup contacts
        $metadata['contacts'] = cleanUpContacts($contacts);

        // SSO MUST be set
        if (!array_key_exists("SingleSignOnService", $metadata) || empty($metadata['SingleSignOnService'])) {
            echo "WARNING: SingleSignOnService not set for $entityId" . PHP_EOL;

            return FALSE;
        }
        // certFingerprint MUST be set
        if (!array_key_exists("certFingerprint", $metadata) || empty($metadata['certFingerprint'])) {
            echo "WARNING: certFingerprint not set for $entityId" . PHP_EOL;
            return FALSE;
        }

        if (!array_key_exists("UIInfo", $metadata)) {
            echo "WARNING: logo not set for " . $entityId . PHP_EOL;
        }

        // validate logo
        if (array_key_exists("UIInfo", $metadata) && array_key_exists("Logo", $metadata['UIInfo']) && array_key_exists("url", $metadata['UIInfo']['Logo'])) {
            // url available, height and width should be set
            $is = @getimagesize($metadata['UIInfo']['Logo']['url']);
            if (FALSE === $is || !is_array($is) || count($is) < 2) {
                echo "WARNING: unable to decode logo for " . $entityId . PHP_EOL;
                unset($metadata['UIInfo']['Logo']);
            } else { 
                list($width, $height) = $is;

                if (!array_key_exists("height", $metadata['UIInfo']['Logo'])) {
                    echo "WARNING: logo height not set for " . $entityId . ", is: " . $height . PHP_EOL;
                } else {
                    if ($height !== $metadata['UIInfo']['Logo']['height']) {
                        echo "WARNING: logo height does not match actual picture height for " . $entityId . ", is: " . $height . ", specified: " . $metadata['UIInfo']['Logo']['height'] . PHP_EOL;
                    }
                }
                if (!array_key_exists("width", $metadata['UIInfo']['Logo'])) {
                    echo "WARNING: logo width not set for " . $entityId . ", is: " . $width . PHP_EOL;
                } else {
                    if ($width !== $metadata['UIInfo']['Logo']['width']) {
                        echo "WARNING: logo width does not match actual picture width for " . $entityId . ", is: " . $width . ", specified: " . $metadata['UIInfo']['Logo']['width'] . PHP_EOL;
                    }
                }
                // override image size based on actual size of logo anyway
                $metadata['UIInfo']['Logo']['height'] = $height;
                $metadata['UIInfo']['Logo']['width'] = $width;
                // needs to be array, FIXME: make this nice!
                $metadata['UIInfo']['Logo'] = array($metadata['UIInfo']['Logo']);
            }
        }

        // keywords
        // remove empty keywords and keywords that contains a "+" symbol or need html encoding
        foreach ($keywords as $k => $v) {
            $keywords[$k] = array_filter($keywords[$k], function($v) use ($entityId) {
                if (empty($v)) {
                    echo "WARNING: empty keyword for " . $entityId . PHP_EOL;

                    return FALSE;
                }
                if (strpos($v, "+") !== FALSE) {
                    echo "WARNING: keyword contains '+' for " . $entityId . PHP_EOL;

                    return FALSE;
                }
                if (htmlentities($v) !== $v) {
                    echo "WARNING: keyword '" . $v . "' contains special characters for " . $entityId . PHP_EOL;

                    return FALSE;
                }

                return TRUE;
            });
        }
        sort($keywords["en"]);
        sort($keywords["nl"]);

        $metadata['UIInfo']['Keywords']["en"] = array_values(array_unique($keywords["en"]));
        $metadata['UIInfo']['Keywords']["nl"] = array_values(array_unique($keywords["nl"]));
    }

    if ("saml20-sp" === $type) {

        $name = array();
        $displayName = array();

        $contacts = array();

        foreach ($result as $entry) {
            if ($entry['key'] === 'AssertionConsumerService:0:Location') {
                $metadata['AssertionConsumerService'] = $entry['value'];
            }
            if ($entry['key'] === 'AssertionConsumerService:0:Binding') {
                if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" !== $entry['value']) {
                    echo "WARNING: " . $entityId . " does not use HTTP-POST binding, but '" . $entry['value'] . "' instead" . PHP_EOL;
                }
            }
            if ($entry['key'] === 'NameIDFormat') {
                $validNameIDs = array (
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

                // fix unspecified format, 2.0 --> 1.1
                if ("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified" === $entry['value']) {
                    $entry['value'] = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
                }

                if (!in_array($entry['value'], $validNameIDs)) {
                    echo "WARNING: " . $entityId . " has invalid NameIDFormat '" . $entry['value'] . "'" . PHP_EOL;
                }

                $metadata['NameIDFormat'] = $entry['value'];
            }

            // contacts
            if (strpos($entry['key'], 'contacts:') === 0) {
                // determine number
                list($c_foo, $c_no, $c_t) = explode(":", $entry['key']);
                $contacts[$c_no][$c_t] = $entry['value'];
            }

            // name
            if (strpos($entry['key'], 'name:') === 0) {
                list(, $c_lang) = explode(":", $entry['key']);
                $name[$c_lang] = $entry['value'];
            }
            // displayName
            if (strpos($entry['key'], 'displayName:') === 0) {
                list(, $c_lang) = explode(":", $entry['key']);
                $displayName[$c_lang] = $entry['value'];
            }

        }

        cleanupName($entityId, $metadata, $name, $displayName);

        // cleanup contacts
        $metadata['contacts'] = cleanUpContacts($contacts);

        // ACS must be set
        if (!array_key_exists("AssertionConsumerService", $metadata) || empty($metadata['AssertionConsumerService'])) {
            echo "WARNING: AssertionConsumerService not set for $entityId" . PHP_EOL;

            return FALSE;
        }
        if (empty($metadata['AssertionConsumerService'])) {
            echo "WARNING: AssertionConsumerService not set for $entityId" . PHP_EOL;

            return FALSE;
        }
        if (!array_key_exists("NameIDFormat", $metadata) || empty($metadata['NameIDFormat'])) {
            $metadata['NameIDFormat'] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
        }
    }

    return $metadata;
}

function cleanUpContacts(array $contacts)
{
    $cleanedContacts = array();
    foreach ($contacts as $k => $v) {
        if (array_key_exists("contactType", $v)) {
            if (in_array($v['contactType'], array("technical", "administrative", "support"))) {
                if (array_key_exists("emailAddress", $v) && !empty($v['emailAddress'])) {
                    if (FALSE !== filter_var($v['emailAddress'], FILTER_VALIDATE_EMAIL)) {
                        // valid email address, valid contact type
                        $c = array("emailAddress" => $v['emailAddress'], "contactType" => $v['contactType']);
                        if (array_key_exists("givenName", $v) && !empty($v['givenName'])) {
                            $c['givenName'] = $v['givenName'];
                        }
                        if (array_key_exists("surName", $v) && !empty($v['surName'])) {
                            $c['surName'] = $v['surName'];
                        }
                        array_push($cleanedContacts, $c);
                    }
                }
            }
        }
    }

    return $cleanedContacts;
}

function cleanupName($entityId, array &$metadata, array $name, array $displayName)
{
    // remove empty names
    foreach ($name as $lang => $value) {
        if (empty($value)) {
            unset($name[$lang]);
        }
    }

    // remove empty displayNames
    foreach ($displayName as $lang => $value) {
        if (empty($value)) {
            unset($displayName[$lang]);
        }
    }

    if (count(array_diff(array_keys($name), array_keys($displayName))) !== 0) {
        echo "WARNING: name and displayName do not have same languages for " . $entityId . PHP_EOL;
    } else {
        // same languages
        foreach ($name as $lang => $value) {
            if ($value !== $displayName[$lang]) {
                echo "WARNING: mismatch between name and displayName '" . $lang . "' [" . $value . "," . $displayName[$lang] . "] for " . $entityId . PHP_EOL;
            }
        }
    }

    // fill displayName based on name if displayName for that language is not set...
    foreach ($name as $lang => $value) {
        if (!array_key_exists($lang, $displayName)) {
            $displayName[$lang] = $value;
        }
    }

    // fill name based on displayName if name for that language is not set...
    foreach ($displayName as $lang => $value) {
        if (!array_key_exists($lang, $name)) {
            $name[$lang] = $value;
        }
    }

    if (!array_key_exists("en", $name)) {
        echo "WARNING: missing EN name for " . $entityId . PHP_EOL;
    }

    if (!array_key_exists("en", $displayName)) {
        echo "WARNING: missing EN displayName for " . $entityId . PHP_EOL;
    }

    if (!empty($name)) {
        $metadata['name'] = $name;
    }
    if (!empty($displayName)) {
        $metadata['UIInfo']['DisplayName'] = $displayName;
    }
}
