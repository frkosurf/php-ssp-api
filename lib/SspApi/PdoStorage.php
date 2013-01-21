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
            $e = json_decode($d['entity_data'], TRUE);
            $e['entityid'] = $d['entity_id'];
            $e['id'] = $d['id'];
            //$entries[$d['id']] = $e;
            array_push($entries, $e);
        }

        return $entries;
    }

    public function getEntry($set, $id)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("SELECT * FROM `$set` WHERE id = :id");
        $stmt->bindValue(":id", $id, PDO::PARAM_INT);
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

    public function putEntry($set, $id, $entityData)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("UPDATE `$set` SET `entity_id` = :entity_id AND `entity_data` = :entity_data WHERE id = :id");
        $stmt->bindValue(":id", $id, PDO::PARAM_INT);
        $stmt->bindValue(":entity_id", $entityData['entityid'], PDO::PARAM_STR);
        $stmt->bindValue(":entity_data", json_encode($entityData), PDO::PARAM_STR);
        $result = $stmt->execute();
        if (FALSE === $result) {
            // error in query
            // FIXME: log/throw error
            return FALSE;
        }

        return 1 === $stmt->rowCount();
    }

    public function deleteEntry($set, $id)
    {
        if (!in_array($set, $this->supportedSets)) {
            return array();
        }

        $stmt = $this->_pdo->prepare("DELETE FROM `$set` WHERE id = :id");
        $stmt->bindValue(":id", $id, PDO::PARAM_INT);
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

        $stmt = $this->_pdo->prepare("INSERT INTO `$set` (`entity_id`, `entity_data`) VALUES(:entity_id, :entity_data)");
        $stmt->bindValue(":entity_id", $entityData['entityid'], PDO::PARAM_STR);
        $stmt->bindValue(":entity_data", json_encode($entityData), PDO::PARAM_STR);
        $result = $stmt->execute();
        if (FALSE === $result) {
            // error in query
            // FIXME: log/throw error
            return FALSE;
        }

        return 1 === $stmt->rowCount();
    }

    public function createTableQuery($tableName)
    {
        // create table queries for specific databases
        if (0 === strpos($this->_dsn, "sqlite")) {
            return "CREATE TABLE IF NOT EXISTS `$tableName` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `entity_id` VARCHAR(255) UNIQUE NOT NULL, `entity_data` TEXT NOT NULL)";
        }
        if (0 === strpos($this->_dsn, "mysql")) {
            return "CREATE TABLE IF NOT EXISTS `$tableName` (`id` INTEGER PRIMARY KEY AUTO_INCREMENT, `entity_id` VARCHAR(255) UNIQUE NOT NULL, `entity_data` TEXT NOT NULL)";
        }
        throw new Exception("DB error: database not supported");
    }

    public function initDatabase()
    {
        foreach ($this->supportedSets as $s) {
            $tableName = $s;
            $result = $this->_pdo->exec($this->createTableQuery($tableName));
            if (FALSE === $result) {
                throw new Exception("DB error: " . var_export($this->_pdo->errorInfo(), TRUE));
            }
            $indexName = $s . "_index";
            $result = $this->_pdo->exec("CREATE INDEX `$indexName` ON `$tableName` (`entity_id`)");
            if (FALSE === $result) {
                throw new Exception("DB error: " . var_export($this->_pdo->errorInfo(), TRUE));
            }
        }
    }

}
