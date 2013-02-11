<?php

if ($argc < 2) {
    die("specify the directory to write the JSON data to" . PHP_EOL);
}

$data = array();

$pdo = new PDO("mysql:host=localhost;dbname=janus", "janus", "janus");

// figure out all eids for both sp and idp that are prodaccepted and active
$sql = "SELECT eid FROM janus__entity GROUP BY eid ORDER BY eid";
$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

$data = array();

foreach ($result as $r) {
    $eid = $r['eid'];
    // figure out the latest revision of the eids and the entityid
    $sql = "SELECT entityid, revisionid, arp, state, active, type FROM janus__entity WHERE eid=:eid ORDER BY revisionid DESC LIMIT 0,1";
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
                    //echo "WARNING: SP " . $values['entityid'] . " (" . $eid . ") contains non-existing IdP $v" . PHP_EOL;
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
                    //echo "WARNING: IdP " . $values['entityid'] . " (" . $eid . ") contains non-existing SP $v" . PHP_EOL;
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
                        //echo "SP " . $v['entityid'] . " not found at IdP " . $idp . PHP_EOL;
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
// echo json_encode($allAttributes) . PHP_EOL;

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

        $nameEn = "";
        $nameNl = "";

        $metadata['certFingerprint'] = array();

        foreach ($result as $entry) {
            if ($entry['key'] === 'SingleSignOnService:0:Location') {
                $metadata['SingleSignOnService'] = $entry['value'];
            }
            if ($entry['key'] === 'SingleLogoutService:0:Location') {
                $metadata['SingleLogoutService'] = $entry['value'];
            }

            if ($entry['key'] === 'name:en') {
                $nameEn = $entry['value'];
            }
            if ($entry['key'] === 'name:nl') {
                $nameNl = $entry['value'];
            }
            if ($entry['key'] === "certData") {
                array_push($metadata['certFingerprint'], sha1(base64_decode($entry['value'])));
            }
            if ($entry['key'] === "certData2") {
                array_push($metadata['certFingerprint'], sha1(base64_decode($entry['value'])));
            }
        }

//        if (!empty($nameEn) && !empty($nameNl) && $nameEn !== $nameNl) {
//            echo "EN: " . $nameEn . PHP_EOL . "NL: " . $nameNl . PHP_EOL . PHP_EOL;
//        }

        // name fiddling
        if (empty($nameEn)) {
        //    echo "WARNING: EN SP  name not set [$entityId]" . PHP_EOL;
        }
        if (empty($nameNl)) {
        //    echo "WARNING: NL SP  name not set [$entityId]" . PHP_EOL;
        }
        // first set Dutch name
        if (!empty($nameNl)) {
            $metadata['name'] = $nameEn;
        }
        // override with English if it is available
        if (!empty($nameEn)) {
            $metadata['name'] = $nameEn;
        }

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

    }

    if ("saml20-sp" === $type) {

        $nameEn = "";
        $nameNl = "";

        foreach ($result as $entry) {
            if ($entry['key'] === 'AssertionConsumerService:0:Location') {
                $metadata['AssertionConsumerService']['Location'] = $entry['value'];
            }
            if ($entry['key'] === 'AssertionConsumerService:0:Binding') {
                if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" !== $entry['value']) {
                    // echo "WARNING: " . $entityId . " does not use HTTP-POST binding, but '" . $entry['value'] . "' instead" . PHP_EOL;
                }
                $metadata['AssertionConsumerService']['Binding'] = $entry['value'];
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

            if ($entry['key'] === 'name:en') {
                $nameEn = $entry['value'];
            }
            if ($entry['key'] === 'name:nl') {
                $nameNl = $entry['value'];
            }
        }

//        if (!empty($nameEn) && !empty($nameNl) && $nameEn !== $nameNl) {
//            echo "EN: " . $nameEn . PHP_EOL . "NL: " . $nameNl . PHP_EOL . PHP_EOL;
//        }

        // name fiddling
        if (empty($nameEn)) {
        //    echo "WARNING: EN SP  name not set [$entityId]" . PHP_EOL;
        }
        if (empty($nameNl)) {
        //    echo "WARNING: NL SP  name not set [$entityId]" . PHP_EOL;
        }
        // first set Dutch name
        if (!empty($nameNl)) {
            $metadata['name'] = $nameEn;
        }
        // override with English if it is available
        if (!empty($nameEn)) {
            $metadata['name'] = $nameEn;
        }

        // ACS must be set
        if (!array_key_exists("AssertionConsumerService", $metadata) || empty($metadata['AssertionConsumerService'])) {
            echo "WARNING: AssertionConsumerService not set for $entityId" . PHP_EOL;
            return FALSE;
        }
        if (!array_key_exists("Location", $metadata['AssertionConsumerService']) || empty($metadata['AssertionConsumerService']['Location'])) {
            echo "WARNING: AssertionConsumerService Location not set for $entityId" . PHP_EOL;
            return FALSE;
        }
        if (!array_key_exists("Binding", $metadata['AssertionConsumerService']) || empty($metadata['AssertionConsumerService']['Binding'])) {
            $metadata['AssertionConsumerService']['Binding'] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        }
        if (!array_key_exists("NameIDFormat", $metadata) || empty($metadata['NameIDFormat'])) {
            $metadata['NameIDFormat'] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
        }
    }

    return $metadata;
}
