<?php

namespace SspApi;

use \RestService\Utils\Config as Config;
use \PDO as PDO;

class PdoStorage
{
    private $_c;
    private $_pdo;
    private $_dsn;

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

        $this->_dsn = $this->_c->getSectionValue('PdoStorage', 'dsn');

        $this->_pdo = new PDO($this->_dsn, $this->_c->getSectionValue('PdoStorage', 'username', FALSE), $this->_c->getSectionValue('PdoStorage', 'password', FALSE), $driverOptions);
        $this->_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    public function getEntries($set, $searchQuery)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $entries = array();

        $tablePrefix = $this->_c->getSectionValue('PdoStorage', 'tablePrefix', FALSE);
        $tableName = $tablePrefix . $set;

        if (NULL === $searchQuery) {
            $stmt = $this->_pdo->prepare("SELECT `entity_id`, `entity_data` FROM `$tableName`");
        } else {
            $stmt = $this->_pdo->prepare("SELECT `entity_id`, `entity_data` FROM `$tableName` WHERE entity_data LIKE :searchQuery");
            $stmt->bindValue(":searchQuery", '%' . $searchQuery . '%', PDO::PARAM_STR);
        }
        $stmt->execute();
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($data as $d) {
            $e = json_decode($d['entity_data'], TRUE);
            $e['entityid'] = $d['entity_id'];
            array_push($entries, $e);
        }

        return $entries;
    }

    public function getEntry($set, $id)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $tablePrefix = $this->_c->getSectionValue('PdoStorage', 'tablePrefix', FALSE);
        $tableName = $tablePrefix . $set;

        $stmt = $this->_pdo->prepare("SELECT `entity_data` FROM `$tableName` WHERE `entity_id` = :entity_id");
        $stmt->bindValue(":entity_id", $id, PDO::PARAM_STR);
        $stmt->execute();
        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        $entry = json_decode($data['entity_data'], TRUE);

        return $entry;
    }

    public function putEntry($set, $id, $entityData)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $tablePrefix = $this->_c->getSectionValue('PdoStorage', 'tablePrefix', FALSE);
        $tableName = $tablePrefix . $set;

        $stmt = $this->_pdo->prepare("UPDATE `$tableName` SET `entity_data` = :entity_data WHERE `entity_id` = :entity_id");
        $stmt->bindValue(":entity_id", $id, PDO::PARAM_STR);
        $stmt->bindValue(":entity_data", $entityData, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function deleteEntry($set, $id)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $tablePrefix = $this->_c->getSectionValue('PdoStorage', 'tablePrefix', FALSE);
        $tableName = $tablePrefix . $set;

        $stmt = $this->_pdo->prepare("DELETE FROM `$tableName` WHERE `entity_id` = :entity_id");
        $stmt->bindValue(":entity_id", $id, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function postEntry($set, $entityData)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $tablePrefix = $this->_c->getSectionValue('PdoStorage', 'tablePrefix', FALSE);
        $tableName = $tablePrefix . $set;

        $stmt = $this->_pdo->prepare("INSERT INTO `$tableName` (`entity_id`, `entity_data`) VALUES(:entity_id, :entity_data)");
        $stmt->bindValue(":entity_id", $entityData['entityid'], PDO::PARAM_STR);
        $stmt->bindValue(":entity_data", json_encode($entityData), PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->rowCount();
    }

    public function initDatabase()
    {
        $tablePrefix = $this->_c->getSectionValue('PdoStorage', 'tablePrefix', FALSE);

        foreach ($this->supportedSets as $s) {
            $tableName = $tablePrefix . $s;
            $query = "CREATE TABLE IF NOT EXISTS `$tableName` (`entity_id` VARCHAR(255) PRIMARY KEY NOT NULL, `entity_data` TEXT NOT NULL)";
            $this->_pdo->exec($query);
        }
    }

}
