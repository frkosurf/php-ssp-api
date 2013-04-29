<?php

namespace SspApi;

use \RestService\Http\HttpRequest as HttpRequest;
use \RestService\Http\HttpResponse as HttpResponse;
use \RestService\Utils\Config as Config;
use \RestService\Utils\Logger as Logger;

use \OAuth\RemoteResourceServer as RemoteResourceServer;

class SspApi
{
    private $_config;
    private $_logger;
    private $_storage;
    private $_resourceServer;

    public function __construct(Config $c, Logger $l = NULL)
    {
        $this->_config = $c;
        $this->_logger = $l;

        $this->_storage = new PdoStorage($this->_config);

        $rsConfig = $this->_config->getSectionValues("OAuth");

        $this->_resourceServer = new RemoteResourceServer($rsConfig);
    }

    public function getEntities($set, HttpRequest $request)
    {
        $response = new HttpResponse(200, "application/json");

        $introspection = $this->_resourceServer->verifyRequest($request->getHeaders(), $request->getQueryParameters());
        $introspection->requireScope("ssp");

        $searchQuery = $request->getQueryParameter('searchQuery');

        $entities = $this->_storage->getEntities($set, $searchQuery);

        $response->setContent(json_encode($entities));

        return $response;
    }

    public function getEntity($set, HttpRequest $request)
    {
        $response = new HttpResponse(200, "application/json");

        $introspection = $this->_resourceServer->verifyRequest($request->getHeaders(), $request->getQueryParameters());
        $introspection->requireScope("ssp");

        $entityId = $request->getQueryParameter('id');
        if (NULL === $entityId) {
           throw new SspApiException("not_found", "resource not specified");
        }

        $entity = $this->_storage->getEntity($set, $entityId);
        if (FALSE === $entity) {
            throw new SspApiException("not_found", "resource '" . $entityId . "' not found");
        }

        $response->setContent(json_encode($entity));

        return $response;
    }

    public function deleteEntity($set, HttpRequest $request)
    {
        $response = new HttpResponse(200, "application/json");

        $introspection = $this->_resourceServer->verifyRequest($request->getHeaders(), $request->getQueryParameters());
        $introspection->requireScope("ssp");

        $entityId = $request->getQueryParameter('id');
        if (NULL === $entityId) {
           throw new SspApiException("not_found", "resource not specified");
        }

        if (FALSE === $this->_storage->deleteEntity($set, $entityId)) {
           throw new SspApiException("not_found", "resource not found");
        }

        return $response;
    }

    public function putEntity($set, HttpRequest $request)
    {
        $response = new HttpResponse(200, "application/json");

        $introspection = $this->_resourceServer->verifyRequest($request->getHeaders(), $request->getQueryParameters());
        $introspection->requireScope("ssp");

        $entityId = $request->getQueryParameter('id');
        if (NULL === $entityId) {
           throw new SspApiException("not_found", "resource not specified");
        }

        $e = new Entity($this->_config);
        try {
            $e->verifyJson($set, $request->getContent());
        } catch (EntityException $e) {
            throw new SspApiException("invalid_request", "invalid entity data [" . $e->getMessage() . "]") ;
        }

        if (FALSE === $this->_storage->putEntity($set, $entityId, $request->getContent())) {
            // FIXME: unable to put?!
        }

        return $response;
    }

    public function postEntity($set, HttpRequest $request)
    {
        $response = new HttpResponse(200, "application/json");

        $introspection = $this->_resourceServer->verifyRequest($request->getHeaders(), $request->getQueryParameters());
        $introspection->requireScope("ssp");

        $e = new Entity($this->_config);
        try {
            $e->verifyJson($set, $request->getContent());
        } catch (EntityException $e) {
            throw new SspApiException("invalid_request", "invalid entity data [" . $e->getMessage() . "]") ;
        }

        if (FALSE === $this->_storage->postEntity($set, $request->getContent())) {
            // FIXME: unable to post?!
        }

        return $response;
    }
}
