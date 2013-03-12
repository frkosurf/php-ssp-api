<?php

if ($argc < 2) {
    die("specify the file to write the JSON data to" . PHP_EOL);
}
$fileName = $argv[1];

$data = array();

$pdo = new PDO("mysql:host=127.0.0.1;dbname=sr", "root", NULL);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$sql = <<< EOF
    SELECT
        metadataurl, arp, eid, type, entityid, state, revisionid
    FROM
        janus__entity e
    WHERE
        revisionid = (SELECT
                MAX(revisionid)
            FROM
                janus__entity
            WHERE
                eid = e.eid)
EOF;

$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

$entities = array();
$idpCount = 0;
$spCount = 0;

// for every entry fetch the metadata
foreach ($result as $r) {
    $metadata = array();

$sql = <<< EOF
    SELECT
        `key`, `value`
    FROM
        janus__metadata
    WHERE
        eid = :eid AND revisionid = :revisionid
EOF;

    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $r['eid']);
    $sth->bindValue(":revisionid", $r['revisionid']);
    $sth->execute();
    $m = $sth->fetchAll(PDO::FETCH_ASSOC);
    foreach ($m as $kv) {
        $metadata[$kv['key']] = $kv['value'];
    }

    // turn all entries with a ":" into proper arrays
    arrayizeMetadata($metadata);

    // add ARP if SP
    if ("saml20-sp" === $r['type']) {
        $sql = "SELECT attributes FROM janus__arp WHERE aid = :aid";
        $sth = $pdo->prepare($sql);
        $sth->bindValue(":aid", $r['arp']);
        $sth->execute();
        $arpResult = $sth->fetch(PDO::FETCH_ASSOC);
        if (NULL !== $arpResult['attributes']) {
            $metadata['attributes'] = array_keys(unserialize($arpResult['attributes']));
        } else {
            $metadata['attributes'] = array();
        }
    }

$sql = <<< EOF
    SELECT
        e.entityid
    FROM
        `janus__entity` e,
        `janus__allowedEntity` a
    WHERE
        a.eid = :eid AND a.revisionid = :revisionid
            AND e.eid = a.remoteeid
            AND e.revisionid = (SELECT
                MAX(revisionid)
            FROM
                `janus__entity`
            WHERE
                eid = a.remoteeid)
EOF;

    $sth = $pdo->prepare($sql);
    $sth->bindValue(":eid", $r['eid']);
    $sth->bindValue(":revisionid", $r['revisionid']);
    $sth->execute();
    $a = $sth->fetchAll(PDO::FETCH_COLUMN);

    $metadata['entityid'] = $r['entityid'];
    if (!empty($r['metadataurl'])) {
        $metadata['metadata-url'] = $r['metadataurl'];
    }
    $metadata['metadata-set'] = $r['type'] . "-remote";
    $metadata['state'] = $r['state'];

    if ($metadata['metadata-set'] === "saml20-sp-remote") {
        $metadata['IDPList'] = $a;
        $spCount++;
        array_push($entities, $metadata);
    } elseif ($metadata['metadata-set'] === "saml20-idp-remote") {
        $metadata['SPList'] = $a;
        $idpCount++;
        array_push($entities, $metadata);
    } else {
        throw new Exception("unsupported entity type");
    }
}

echo $idpCount . " IdPs" . PHP_EOL;
echo $spCount . " SPs" . PHP_EOL;

$idpWithACL = findIdPWithACL($entities);
$spWithACL = findSPWithACL($entities);

findConflictingACL($idpWithACL, $spWithACL);

file_put_contents($argv[1], json_encode($entities));

function arrayizeMetadata(&$metadata)
{
    foreach ($metadata as $k => $v) {
        // if k contain as colon there may be multiple values underneath
        if (empty($v)) {
            unset($metadata[$k]);
        } else {
            if (FALSE !== strpos($k, ":")) {
                $e = explode(":", $k);
                if (2 === count($e)) {
                    // only simple case for now
                    $metadata[$e[0]][$e[1]] = $v;
                    unset($metadata[$k]);
                } elseif (3 === count($e)) {
                    $metadata[$e[0]][$e[1]][$e[2]] = $v;
                    unset($metadata[$k]);
                } elseif (4 === count($e)) {
                    $metadata[$e[0]][$e[1]][$e[2]][$e[4]] = $v;
                    unset($metadata[$k]);
                } else {
                    throw new Exception("unsupported array depth in metadata");
                }
            }
        }
    }
}

function findIdPWithACL(&$entities)
{
    $idpWithACL = array();
    foreach ($entities as $e) {
        if (array_key_exists("SPList", $e) && 0 !== count($e['SPList'])) {
            $idpWithACL[$e['entityid']] = $e['SPList'];
        }
    }

    return $idpWithACL;
}

function findSPWithACL(&$entities)
{
    $spWithACL = array();
    foreach ($entities as $e) {
        if (array_key_exists("IDPList", $e) && 0 !== count($e['IDPList'])) {
            $spWithACL[$e['entityid']] = $e['IDPList'];
        }
    }

    return $spWithACL;
}

function findConflictingACL(&$idpWithACL, &$spWithACL)
{
    // the ACL at the SP MUST match with the ACL at the IdP
    //
    // if there is an ACL at the SP:
    // 1. the IdP entities mentioned MUST have this SP entityId in the SPList
    // 2. the other IdP entities MUST NOT have this SP entityId in the SPList

    foreach ($spWithACL as $eid => $list) {
        foreach ($list as $l) {
            if (!array_key_exists($l, $idpWithACL)) {
                echo "[WARNING] mentioned IdP '" . $l . "' at SP '" . $eid . "' does not exist, or has no ACL" . PHP_EOL;
                continue;
            }
            if (!in_array($eid, $idpWithACL[$l])) {
                echo "[ERROR]   the mentioned IdP '" . $l . "' at SP '" . $eid . "' is not in the IdP ACL" . PHP_EOL;
            }
        }
    }
}
