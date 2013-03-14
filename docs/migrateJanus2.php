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
        metadataurl, arp, eid, type, allowedall, entityid, state, revisionid
    FROM
        janus__entity e
    WHERE
        active = "yes" AND state = "prodaccepted" AND revisionid = (SELECT
                MAX(revisionid)
            FROM
                janus__entity
            WHERE
                eid = e.eid)
EOF;

$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

$saml20_idp = array();
$saml20_sp = array();

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

    $metadata['allowAll'] = "yes" === $r['allowedall'];

    $metadata['entityid'] = $r['entityid'];
    if (!empty($r['metadataurl'])) {
        $metadata['metadata-url'] = $r['metadataurl'];
    }
    $metadata['metadata-set'] = $r['type'] . "-remote";
    $metadata['state'] = $r['state'];

    if ($metadata['metadata-set'] === "saml20-sp-remote") {
        $metadata['IDPList'] = $a;
        $saml20_sp[$r['entityid']] = $metadata;
    } elseif ($metadata['metadata-set'] === "saml20-idp-remote") {
        $metadata['SPList'] = $a;
        $saml20_idp[$r['entityid']] = $metadata;
    } else {
        throw new Exception("unsupported entity type");
    }
}

echo count($saml20_idp) . " IdPs" . PHP_EOL;
echo count($saml20_sp) . " SPs" . PHP_EOL;

findAclConflict($saml20_idp, $saml20_sp);

file_put_contents($argv[1], json_encode(array_values($saml20_idp) + array_values($saml20_sp)));

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

function findAclConflict(&$idp, &$sp)
{

    // for every SP where allowAll = FALSE
    //      for every IdP in the IDPList:
    //          check if IdP exists
    //              NO : print error + next IdP
    //              YES: check whether IdP has this SP in its SPList
    //                  NO : print error + next IdP
    //                  YES: next IdP
    //
    //
    foreach ($sp as $eid => $metadata) {
        if (!$metadata['allowAll']) {
            echo "[ERROR  ] SP '" . $eid . "' does not have 'Allow All' set" . PHP_EOL;
            foreach ($metadata['IDPList'] as $i) {
                if (!array_key_exists($i, $idp)) {
                    echo "\t[WARNING] IdP '" . $i . "' listed for SP '" . $eid . "' does not exist" . PHP_EOL;
                    continue;
                }
                if (!in_array($eid, $idp[$i]['SPList'])) {
                    echo "\t[WARNING] IdP '" . $i . "' does not have SP '" . $eid . "' in its ACL" . PHP_EOL;
                    continue;
                }
            }
        }
    }

    // for every IdP
    //     has allowAll = TRUE:
    //          YES:
    //              ....
    //          NO:
    //               for every IdP with an SPList
    //                  check if the SP has an ACL
    //                      YES: check if this IdP is in the list
    //                          YES: OK
    //                          NO: print error (SP does not list IdP)
    //                      NO: continue next SP
    //
    foreach ($idp as $eid => $metadata) {
        echo "[INFO] IdP '" . $eid . "'" . PHP_EOL;
        if ($metadata['allowAll']) {
            echo "[ERROR  ] IdP '" . $eid . "' has 'Allow All' set" . PHP_EOL;
            continue;
        }
        foreach ($metadata['SPList'] as $s) {
            if (!array_key_exists($s, $sp)) {
                echo "\t[WARNING] SP '" . $s . "' listed for IdP '" . $eid . "' does not exist" . PHP_EOL;
                continue;
            }
            if ($sp[$s]['allowAll']) {
                continue;
            }
            if (!in_array($eid, $sp[$s]['IDPList'])) {
                echo "\t[WARNING] SP '" . $s . "' does not have IdP '" . $eid . "' in its ACL" . PHP_EOL;
            }
        }
    }
}
