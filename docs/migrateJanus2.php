<?php

if ($argc < 2) {
    die("specify the file to write the JSON data to" . PHP_EOL);
}
$fileName = $argv[1];

$data = array();

$pdo = new PDO("mysql:host=127.0.0.1;dbname=sr", "root", NULL);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// fetch all entries and their latest revision
$sql = "SELECT metadataurl, arp, eid, type, entityid, state, revisionid FROM janus__entity e WHERE revisionid = (SELECT MAX(revisionid) FROM janus__entity WHERE eid = e.eid)";
$sth = $pdo->prepare($sql);
$sth->execute();
$result = $sth->fetchAll(PDO::FETCH_ASSOC);

$saml20_idp_remote = array();
$saml20_sp_remote = array();

// for every entry fetch the metadata
foreach ($result as $r) {
    $metadata = array();

    $sql = "SELECT `key`, `value` FROM janus__metadata WHERE eid = :eid AND revisionid = :revisionid";
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

    $metadata['entityid'] = $r['entityid'];
    if (!empty($r['metadataurl'])) {
        $metadata['metadata-url'] = $r['metadataurl'];
    }
    $metadata['metadata-set'] = $r['type'] . "-remote";
    $metadata['state'] = $r['state'];

    // FIXME: add ACL

    if ($metadata['metadata-set'] === "saml20-sp-remote") {
        array_push($saml20_sp_remote, $metadata);
    } elseif ($metadata['metadata-set'] === "saml20-idp-remote") {
        array_push($saml20_idp_remote, $metadata);
    } else {
        throw new Exception("unsupported entity type");
    }
}

echo count($saml20_idp_remote) . " IdPs" . PHP_EOL;
echo count($saml20_sp_remote) . " SPs" . PHP_EOL;

file_put_contents($argv[1], json_encode($saml20_idp_remote + $saml20_sp_remote));

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
