<?php

namespace SspApi;

use \RestService\Utils\Config as Config;
use \PDO as PDO;

class PdoStorage
{
    private $_c;
    private $_pdo;

    /**
     * All the metadata sets simpleSAMLphp supports
     */
    public $supportedSets = array (
        'adfs-idp-hosted',
        'adfs-sp-remote',
        'saml20-idp-hosted',
        'saml20-idp-remote',
        'saml20-sp-remote',
        'shib13-idp-hosted',
        'shib13-idp-remote',
        'shib13-sp-hosted',
        'shib13-sp-remote',
        'wsfed-idp-remote',
        'wsfed-sp-hosted'
    );

    public function __construct(Config $c)
    {
        $this->_c = $c;

        $driverOptions = array();
        if ($this->_c->getSectionValue('PdoStorage', 'persistentConnection')) {
            $driverOptions[PDO::ATTR_PERSISTENT] = TRUE;
        }

        $dsn = $this->_c->getSectionValue('PdoStorage', 'dsn');

        $this->_pdo = new PDO($dsn, $this->_c->getSectionValue('PdoStorage', 'username', FALSE), $this->_c->getSectionValue('PdoStorage', 'password', FALSE), $driverOptions);
        $this->_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public function getEntities($metadataSet, $searchQuery = NULL)
    {
        $entities = array();

        if (NULL === $searchQuery) {
            $stmt = $this->_pdo->prepare("SELECT entity_id, entity_data FROM metadata WHERE metadata_set = :metadata_set");
        } else {
            $stmt = $this->_pdo->prepare("SELECT entity_id, entity_data FROM metadata WHERE metadata_set = :metadata_set AND entity_data LIKE :searchQuery");
            $stmt->bindValue(":searchQuery", '%' . $searchQuery . '%', PDO::PARAM_STR);
        }
        $stmt->bindValue(":metadata_set", $metadataSet, PDO::PARAM_STR);
        $stmt->execute();
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        // FIXME: can data return FALSE?
        foreach ($data as $d) {
            $e = json_decode($d['entity_data'], TRUE);
            $e['entityid'] = $d['entity_id'];
            array_push($entities, $e);
        }

        return $entities;
    }

    public function getEntity($metadataSet, $entityId)
    {
        $stmt = $this->_pdo->prepare("SELECT entity_data FROM metadata WHERE metadata_set = :metadata_set AND entity_id = :entity_id");
        $stmt->bindValue(":metadata_set", $metadataSet, PDO::PARAM_STR);
        $stmt->bindValue(":entity_id", $entityId, PDO::PARAM_STR);
        $stmt->execute();
        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        // if entity was not found, return FALSE
        return (FALSE !== $data && 1 === count($data)) ? json_decode($data['entity_data'], TRUE) : FALSE;
    }

    public function putEntity($metadataSet, $entityId, $entityData)
    {
        $stmt = $this->_pdo->prepare("UPDATE metadata SET entity_data = :entity_data WHERE metadata_set = :metadata_set AND entity_id = :entity_id");
        $stmt->bindValue(":metadata_set", $metadataSet, PDO::PARAM_STR);
        $stmt->bindValue(":entity_id", $entityId, PDO::PARAM_STR);
        $stmt->bindValue(":entity_data", $entityData, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function deleteEntity($metadataSet, $entityId)
    {
        $stmt = $this->_pdo->prepare("DELETE FROM metadata WHERE metadata_set = :metadata_set AND entity_id = :entity_id");
        $stmt->bindValue(":metadata_set", $metadataSet, PDO::PARAM_STR);
        $stmt->bindValue(":entity_id", $entityId, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function postEntity($metadataSet, $entityData)
    {
        $stmt = $this->_pdo->prepare("INSERT INTO metadata (metadata_set, entity_id, entity_data) VALUES(:metadata_set, :entity_id, :entity_data)");
        $stmt->bindValue(":metadata_set", $metadataSet, PDO::PARAM_STR);
        $stmt->bindValue(":entity_id", $entityData['entityid'], PDO::PARAM_STR);
        $stmt->bindValue(":entity_data", json_encode($entityData), PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function getChangeInfo()
    {
        $stmt = $this->_pdo->prepare("SELECT MAX(patch_number) AS patch_number, description FROM db_changelog WHERE patch_number IS NOT NULL");
        $stmt->execute();
        // ugly hack because query will always return a result, even if there is none...
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return NULL === $result['patch_number'] ? FALSE : $result;
    }

    public function addChangeInfo($patchNumber, $description)
    {
        $stmt = $this->_pdo->prepare("INSERT INTO db_changelog (patch_number, description) VALUES(:patch_number, :description)");
        $stmt->bindValue(":patch_number", $patchNumber, PDO::PARAM_INT);
        $stmt->bindValue(":description", $description, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function dbQuery($query)
    {
        $this->_pdo->exec($query);
    }

}
