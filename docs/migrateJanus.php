<?php

if ($argc < 2) {
    die("specify the directory to write the JSON data to" . PHP_EOL);
}

$dirName = $argv[1];
$requestedState = ($argc > 2) ? $argv[2] : NULL;

$data = array();

$pdo = new PDO("mysql:host=127.0.0.1;dbname=sr", "root", NULL);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$sql = <<< EOF
    SELECT
        metadataurl, arp, eid, type, allowedall, entityid, state, revisionid
    FROM
        janus__entity e
    WHERE
        active = "yes" AND revisionid = (SELECT
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
$allAttributes = array();
$log = array();

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
            $allAttributes = array_unique(array_merge($allAttributes, $metadata['attributes']));
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
    $metadata['eid'] = $r['eid'];

    if (!empty($r['metadataurl'])) {
        $metadata['metadata-url'] = $r['metadataurl'];
    }
    $metadata['metadata-set'] = $r['type'] . "-remote";
    $metadata['state'] = $r['state'];

    $log[$metadata['metadata-set']][$metadata['entityid']]['messages'] = array();
    $log[$metadata['metadata-set']][$metadata['entityid']]['state'] = $metadata['state'];
    $log[$metadata['metadata-set']][$metadata['entityid']]['eid'] = $metadata['eid'];
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

findAclConflicts($saml20_idp, $saml20_sp);
moveAclToSP($saml20_idp, $saml20_sp);

convertToUIInfo($saml20_idp);
convertToUIInfo($saml20_sp);

validateContacts($saml20_idp);
validateContacts($saml20_sp);

validateEndpoints($saml20_idp);
validateEndpoints($saml20_sp);

checkName($saml20_idp);
checkName($saml20_sp);

checkOrganizationDisplayName($saml20_idp);
checkOrganizationDisplayName($saml20_sp);

removeSecrets($saml20_sp);

if (NULL !== $requestedState) {
    filterState($saml20_idp, $requestedState);
    filterState($saml20_sp, $requestedState);
}

if (FALSE === @file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "saml20-idp-remote.json", json_encode(array_values($saml20_idp)))) {
    throw new Exception("unable to write 'saml20-idp-remote.json'");
}
if (FALSE === @file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "saml20-sp-remote.json", json_encode(array_values($saml20_sp)))) {
    throw new Exception("unable to write 'saml20-sp-remote.json'");
}

sort($allAttributes);
if (FALSE === @file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "allAttributes.json", json_encode(array_values($allAttributes)))) {
    throw new Exception("unable to write 'allAttributes.json'");
}

cleanLog();
if (FALSE === @file_put_contents($argv[1] . DIRECTORY_SEPARATOR . "entityLog.json", json_encode($log))) {
    throw new Exception("unable to write 'entityLog.json'");
}

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

function findAclConflicts(&$idp, &$sp)
{
    foreach ($sp as $eid => $metadata) {
        if (!$metadata['allowAll']) {
            _l($metadata, "WARNING", "'allowAll' not set");
            foreach ($metadata['IDPList'] as $i) {
                if (!array_key_exists($i, $idp)) {
                    _l($metadata, "WARNING", "IdP '$i' does not exist");
                    continue;
                }
                if (!in_array($eid, $idp[$i]['SPList']) && !$idp[$i]['allowAll']) {
                    _l($metadata, "WARNING", "IdP '$i' does not have this SP listed");
                    // FIXME: add also IdP log item?
                    continue;
                }
            }
        }
    }

    foreach ($idp as $eid => $metadata) {
        if ($metadata['allowAll']) {
            _l($metadata, "WARNING", "'allowAll' set");
            continue;
        }
        foreach ($metadata['SPList'] as $s) {
            if (!array_key_exists($s, $sp)) {
                _l($metadata, "WARNING", "SP $s does not exist");
                continue;
            }
            if ($sp[$s]['allowAll']) {
                continue;
            }
            if (!in_array($eid, $sp[$s]['IDPList'])) {
                _l($metadata, "WARNING", "SP $s does not have this IdP listed");
            }
        }
    }
}

function validateContacts(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (array_key_exists("contacts", $metadata)) {
            foreach ($metadata['contacts'] as $k => $v) {
                $filteredContact = filterContact($v);
                if (FALSE !== $filteredContact) {
                    $entities[$eid]["contacts"][$k] = $filteredContact;
                } else {
                    unset($entities[$eid]["contacts"][$k]);
                }
            }
            $entities[$eid]['contacts'] = array_values($entities[$eid]['contacts']);
        }
    }
}

function validateEndpoints(&$entities)
{
    $endpointTypes = array("SingleLogoutService", "SingleSignOnService", "AssertionConsumerService");

    foreach ($entities as $eid => $metadata) {
        foreach ($endpointTypes as $type) {
            if (array_key_exists($type, $metadata)) {
                foreach ($metadata[$type] as $k => $v) {
                    $filteredEndpoint = filterEndpoint($v);
                    if (FALSE !== $filteredEndpoint) {
                        $entities[$eid][$type][$k] = $filteredEndpoint;
                    } else {
                        _l($metadata, "WARNING", "invalid endpoint configuration");
                        unset($entities[$eid][$type][$k]);
                    }
                }
                $entities[$eid][$type] = array_values($entities[$eid][$type]);
                if (0 === count($entities[$eid][$type])) {
                    unset($entities[$eid][$type]);
                }
            }
        }
    }
}

function convertToUIInfo(&$entities)
{
    // some keys belong in UIInfo (under a different name)
    foreach ($entities as $eid => $metadata) {
        $uiInfo = array();
        $discoHints = array();

        if (array_key_exists("displayName", $metadata)) {
            $uiInfo['DisplayName'] = $metadata['displayName'];
            unset($entities[$eid]['displayName']);
        }
        if (array_key_exists("keywords", $metadata)) {
            foreach ($metadata['keywords'] as $language => $keywords) {
                $filteredKeywords = filterKeywords($keywords);
                if (0 !== count($filteredKeywords)) {
                    $uiInfo['Keywords'][$language] = $filteredKeywords;
                }
            }
            unset($entities[$eid]['keywords']);
        }
        if (array_key_exists("geoLocation", $metadata)) {
            $geo = validateGeo($metadata['geoLocation']);
            if (FALSE !== count($geo)) {
                $discoHints['GeolocationHint'] = array($geo);
            } else {
                _l($metadata, "WARNING", "invalid GeolocationHint");
            }
            unset($entities[$eid]['geoLocation']);
        }
        if (array_key_exists("logo", $metadata)) {
            $errorMessage = array();
            $logo = validateLogo($metadata["logo"][0], $errorMessage);
            if (FALSE !== $logo) {
                $uiInfo['Logo'] = array($logo);
            } else {
                _l($metadata, "WARNING", "invalid Logo configuration (" . implode(", ", $errorMessage) . ")");
            }
            unset($entities[$eid]['logo']);
        }
        if (0 !== count($uiInfo)) {
            $entities[$eid]['UIInfo'] = $uiInfo;
        }
        if (0 !== count($discoHints)) {
            $entities[$eid]['DiscoHints'] = $discoHints;
        }

    }
}

function validateLogo(array $logo, array &$errorMessage)
{
    if (!array_key_exists("url", $logo)) {
        array_push($errorMessage, "missing URL");
    } else {
        if (FALSE === filter_var($logo['url'], FILTER_VALIDATE_URL, FILTER_FLAG_PATH_REQUIRED)) {
            array_push($errorMessage, "invalid URL");
        }
    }
    if (!array_key_exists("width", $logo) || !is_numeric($logo['width'])) {
        array_push($errorMessage, "missing or invalid width");
    }
    if (!array_key_exists("height", $logo) || !is_numeric($logo['height'])) {
        array_push($errorMessage, "missing or invalid height");
    }

    if (0 !== count($errorMessage)) {
        return FALSE;
    }

    $l = array ("url" => $logo['url'], "width" => (int) $logo['width'], "height" => (int) $logo['height']);
    if (array_key_exists("lang", $logo) && !empty($logo['lang'])) {
        $l['lang'] = $logo['lang'];
    }

    return $l;
}

function moveAclToSP(&$idp, &$sp)
{
    // remove the ACL from all SPs
    foreach ($sp as $eid => $metadata) {
        $sp[$eid]["IDPList"] = array();
    }

    // for every IdP take the ACL and add its eid to the SP "IDPList" in the ACL list
    foreach ($idp as $eid => $metadata) {
        foreach ($metadata['SPList'] as $s) {
            if (!array_key_exists($s, $sp)) {
                _l($metadata, "WARNING", "SP $s does not exist");
                continue;
            }
            array_push($sp[$s]["IDPList"], $eid);
        }
        // remove the ACL from the IdP
        unset($idp[$eid]['SPList']);
    }
}

function filterKeywords($keywords)
{
    $keywordsArray = explode(" ", $keywords);
    foreach ($keywordsArray as $k) {
        $keywordsArray = array_filter($keywordsArray, function($v) {
            if (empty($v)) {
                return FALSE;
            }
            if (strpos($v, "+") !== FALSE) {
                return FALSE;
            }
            if (htmlentities($v) !== $v) {
                return FALSE;
            }

            return TRUE;
        });
    }
    sort($keywordsArray);

    return array_values(array_unique($keywordsArray));
}

function filterContact(array $contact)
{
    $validContactTypes = array ("technical", "administrative", "support");
    if (!array_key_exists("contactType", $contact)) {
        return FALSE;
    }
    if (!in_array($contact['contactType'], $validContactTypes)) {
        return FALSE;
    }
    if (!array_key_exists("emailAddress", $contact)) {
        return FALSE;
    }
    $c = array("contactType" => $contact['contactType'], "emailAddress" => $contact['emailAddress']);
    if (array_key_exists("givenName", $contact) && !empty($contact['givenName'])) {
        $c['givenName'] = $contact['givenName'];
    }
    if (array_key_exists("surName", $contact) && !empty($contact['surName'])) {
        $c['surName'] = $contact['surName'];
    }

    return $c;
}

function filterEndpoint(array $ep)
{
    // an ACS, SSO or SLO should have a "Binding" and a "Location" field
    if (!array_key_exists("Location", $ep)) {
        return FALSE;
    }
    if (!array_key_exists("Binding", $ep)) {
        return FALSE;
    }
    $validatedEndpoint = array("Location" => $ep['Location'], "Binding" => $ep['Binding']);
    if (array_key_exists("Index", $ep) && !empty($ep['Index'])) {
        $validatedEndpoint['Index'] = $ep['Index'];
    }

    return $validatedEndpoint;
}

function checkOrganizationDisplayName(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (array_key_exists("OrganizationDisplayName", $metadata) && is_array($metadata['OrganizationDisplayName']) && array_key_exists("en", $metadata["OrganizationDisplayName"]) && !empty($metadata["OrganizationDisplayName"]["en"])) {
            // all is fine
            continue;
        } else {
            _l($metadata, "WARNING", "no OrganizationDisplayName:en set");
        }
    }
}

function removeSecrets(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (isset($metadata['coin']['oauth']['secret'])) {
            $entities[$eid]['coin']['oauth']['secret'] = 'REPLACED_BY_MIGRATE_SCRIPT';
        }
        if (isset($metadata['coin']['oauth']['consumer_secret'])) {
            $entities[$eid]['coin']['oauth']['consumer_secret'] = 'REPLACED_BY_MIGRATE_SCRIPT';
        }
        if (isset($metadata['coin']['provision_password'])) {
            $entities[$eid]['coin']['provision_password'] = 'REPLACED_BY_MIGRATE_SCRIPT';
        }
    }
}

function filterState(&$entities, $requestedState)
{
    global $log;
    foreach ($entities as $eid => $metadata) {
        if ($requestedState !== $metadata['state']) {
            unset($entities[$eid]);
            unset($log[$metadata['metadata-set']][$eid]);
        }
    }
}

function checkName(&$entities)
{
    foreach ($entities as $eid => $metadata) {
        if (array_key_exists("name", $metadata) && is_array($metadata['name']) && array_key_exists("en", $metadata["name"]) && !empty($metadata["name"]["en"])) {
            // all is fine
            continue;
        } else {
            _l($metadata, "WARNING", "no name:en set");
        }
    }
}

function validateGeo($geoHints)
{
    if (!empty($geoHints)) {
        $e = explode(",", $geoHints);
        if (2 !== count($e) && 3 !== count($e)) {
            return FALSE;
        }
        if (2 === count($e)) {
            list($lat, $lon) = $e;
            $lat = trim($lat);
            $lon = trim($lon);

            return "geo:$lat,$lon";
        }
        if (3 === count($e)) {
            list($lat, $lon, $alt) = $e;
            $lat = trim($lat);
            $lon = trim($lon);
            $alt = trim($alt);

            return "geo:$lat,$lon,$alt";
        }
    }
}

function _l($metadata, $level, $message)
{
    global $log;
    array_push($log[$metadata['metadata-set']][$metadata['entityid']]['messages'], array("level" => $level, "message" => $message));
}

// remove entries that do not have a log message
function cleanLog()
{
    global $log;
    foreach ($log as $set => $entities) {
        foreach ($entities as $k => $v) {
            if (0 === count($v['messages'])) {
                unset($log[$set][$k]);
            }
        }
    }
}
