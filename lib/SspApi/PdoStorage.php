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
            $driverOptions = array(PDO::ATTR_PERSISTENT => TRUE);
        }

        $this->_pdo = new PDO($this->_c->getSectionValue('PdoStorage', 'dsn'), $this->_c->getSectionValue('PdoStorage', 'username', FALSE), $this->_c->getSectionValue('PdoStorage', 'password', FALSE), $driverOptions);

        if (0 === strpos($this->_c->getSectionValue('PdoStorage', 'dsn'), "sqlite:")) {
            // only for SQlite
            $this->_pdo->exec("PRAGMA foreign_keys = ON");
        }
    }

    public function getEntries($set)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $entries = array();

        $stmt = $this->_pdo->prepare("SELECT * FROM `$set`");
        if (FALSE === $stmt) {
            // error in query, pretend we found no entries...
            // FIXME: log error
            return array();
        }
        $result = $stmt->execute();
        if (FALSE === $result) {
            // query failed, pretend we found no entries...
            // FIXME: log error
            return array();
        }
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($data as $d) {
            $e = json_decode($d['entityData'], TRUE);
            $e['entityid'] = $d['entityId'];
            array_push($entries, $e);
        }

        return $entries;
    }

    public function getEntry($set, $entityId)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("SELECT * FROM `$set` WHERE entityId = :entityId");
        $stmt->bindValue(":entityId", $entityId, PDO::PARAM_STR);
        $result = $stmt->execute();
        if (FALSE === $result) {
            // error in query
            // FIXME: log/throw error
            return FALSE;
        }
        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        $entry = json_decode($data['entityData'], TRUE);

        return $entry;
    }

    public function putEntry($set, $entityId, $entityData)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("UPDATE `$set` SET entityData = :entityData WHERE entityId = :entityId");
        $stmt->bindValue(":entityId", $entityId, PDO::PARAM_STR);
        $stmt->bindValue(":entityData", json_encode($entityData), PDO::PARAM_STR);
        $result = $stmt->execute();
        if (FALSE === $result) {
            // error in query
            // FIXME: log/throw error
            return FALSE;
        }

        return 1 === $stmt->rowCount();
    }

    public function deleteEntry($set, $entityId)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("DELETE FROM `$set` WHERE entityId = :entityId");
        $stmt->bindValue(":entityId", $entityId, PDO::PARAM_STR);
        $result = $stmt->execute();
        if (FALSE === $result) {
            // error in query
            // FIXME: log/throw error
            return FALSE;
        }

        return 1 === $stmt->rowCount();
    }

    public function postEntry($set, $entityData)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("INSERT INTO `$set` ('entityId', 'entityData') VALUES(:entityId, :entityData)");
        $stmt->bindValue(":entityId", $entityData['entityid'], PDO::PARAM_STR);
        $stmt->bindValue(":entityData", json_encode($entityData), PDO::PARAM_STR);
        $result = $stmt->execute();
        if (FALSE === $result) {
            // error in query
            // FIXME: log/throw error
            return FALSE;
        }

        return 1 === $stmt->rowCount();
    }

    public function initDatabase()
    {
        foreach ($this->supportedSets as $s) {
            $result = $this->_pdo->exec("CREATE TABLE IF NOT EXISTS `$s` (id INTEGER PRIMARY KEY, entityId TEXT UNIQUE NOT NULL, entityData TEXT NOT NULL)");
            if (FALSE === $result) {
                throw new PdoStorageException("DB error: " . var_export($this->_pdo->errorInfo(), TRUE));
            }
            $indexName = $s . "-index";
            $result = $this->_pdo->exec("CREATE INDEX IF NOT EXISTS `$indexName` ON `$s` (entityId)");
            if (FALSE === $result) {
                throw new PdoStorageException("DB error: " . var_export($this->_pdo->errorInfo(), TRUE));
            }
        }
    }

}
