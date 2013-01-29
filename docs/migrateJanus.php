<?php

if ($argc < 2) {
    die("specify the directory to write the JSON data to" . PHP_EOL);
}

$data = array();

$pdo = new PDO("mysql:host=localhost;dbname=janus", "janus", "janus");

// figure out all eids for both sp and idp that are prodaccepted and active
$sql = "SELECT eid,type FROM janus__entity WHERE active='yes' AND state='prodaccepted' GROUP BY eid ORDER BY eid";
$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

foreach ($result as $r) {
    $data[$r['type']][$r['eid']] = array();
}

foreach ($data as $type => $entries) {
    foreach ($entries as $eid => $values) {
        // figure out the latest revision of the eids and the entityid
        $sql = "SELECT entityid,revisionid,arp FROM janus__entity WHERE eid=:eid ORDER BY revisionid DESC LIMIT 0,1";
        $sth = $pdo->prepare($sql);
        $sth->bindValue(":eid", $eid);
        $sth->execute();
        $result = $sth->fetch(PDO::FETCH_ASSOC);
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

        $metadata = fetchMetadata($type, $metadataResult);
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
            $data[$type][$eid]['idpList'] = $aclList;
        }
        if ("saml20-idp" === $type) {
            $data[$type][$eid]['spList'] = $aclList;
        }
    }
}

// now fiddle with ACL
foreach ($data as $type => $entries) {
    foreach ($entries as $eid => $values) {
        if ("saml20-sp" === $type) {
            // find the idpList
            foreach ($values['idpList'] as $k => $v) {
                if (array_key_exists($v, $data['saml20-idp'])) {
                    $data["saml20-sp"][$eid]['idpList'][$k] = $data['saml20-idp'][$v]['entityid'];
                }
            }
        }
        if ("saml20-idp" === $type) {
            // find the spList
            foreach ($values['spList'] as $k => $v) {
                if (array_key_exists($v, $data['saml20-sp'])) {
                    $data["saml20-idp"][$eid]['spList'][$k] = $data['saml20-sp'][$v]['entityid'];
                }
            }
        }
    }
}

// write data for IdPs to JSON file
$encoding = json_encode(array_values($data["saml20-idp"]));
file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "saml20-idp-remote.json", $encoding);

// write data for SPs to JSON file
$encoding = json_encode(array_values($data["saml20-sp"]));
file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "saml20-sp-remote.json", $encoding);

function fetchMetadata($type, array $result)
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

    }

    if ("saml20-sp" === $type) {

        $nameEn = "";
        $nameNl = "";

        foreach ($result as $entry) {
            if ($entry['key'] === 'AssertionConsumerService:0:Location') {
                $metadata['AssertionConsumerService'] = $entry['value'];
            }
            if ($entry['key'] === 'name:en') {
                $nameEn = $entry['value'];
            }
            if ($entry['key'] === 'name:nl') {
                $nameNl = $entry['value'];
            }
        }

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

    }

    return $metadata;
}
