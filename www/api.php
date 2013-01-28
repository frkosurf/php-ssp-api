<?php

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "_autoload.php";

use \RestService\Http\HttpRequest as HttpRequest;
use \RestService\Http\HttpResponse as HttpResponse;
use \RestService\Http\IncomingHttpRequest as IncomingHttpRequest;
use \RestService\Utils\Config as Config;
use \RestService\Utils\Logger as Logger;

use \SspApi\PdoStorage as PdoStorage;
use \SspApi\ApiException as ApiException;

$logger = NULL;
$request = NULL;
$response = NULL;

try {
    $config = new Config(dirname(__DIR__) . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "config.ini");
    $logger = new Logger($config->getSectionValue('Log', 'logLevel'), $config->getValue('serviceName'), $config->getSectionValue('Log', 'logFile'), $config->getSectionValue('Log', 'logMail', FALSE));

    $storage = new PdoStorage($config);

    $request = HttpRequest::fromIncomingHttpRequest(new IncomingHttpRequest());

    $response = new HttpResponse(200, "application/json");

    $request->matchRest("GET", "/:set/", function($set) use ($storage, $response) {
        //$rs->requireScope("ssp");
        //$rs->requireEntitlement("urn:x-oauth:entitlement:ssp");

        $response->setContent(json_encode($storage->getEntries($set)));
    });

    $request->matchRest("GET", "/:set/entity", function($set) use ($storage, $response, $request) {
        //$rs->requireScope("ssp");
        //$rs->requireEntitlement("urn:x-oauth:entitlement:ssp");
        // Apache rewrites URLs to not contain double "//". So we need to restore this... HOW ugly...
        $id = $request->getQueryParameter("id");
        if (NULL === $id) {
           throw new ApiException("not_found", "resource not found");
        }
        $response->setContent(json_encode($storage->getEntry($set, $id)));
    });

    $request->matchRest("DELETE", "/:set/entity", function($set) use ($storage, $response, $request) {
        //$rs->requireScope("ssp");
        //$rs->requireEntitlement("urn:x-oauth:entitlement:ssp");
        $id = $request->getQueryParameter("id");
        if (NULL === $id) {
           throw new ApiException("not_found", "resource not found");
        }
        $response->setContent(json_encode($storage->deleteEntry($set, $id)));
    });

    $request->matchRest("PUT", "/:set/entity", function($set) use ($storage, $request, $response) {
        //$rs->requireScope("ssp");
        //$rs->requireEntitlement("urn:x-oauth:entitlement:ssp");
        $id = $request->getQueryParameter("id");
        if (NULL === $id) {
           throw new ApiException("not_found", "resource not found");
        }
        $response->setContent(json_encode($storage->putEntry($set, $id, $request->getContent())));
    });

    $request->matchRest("POST", "/:set/", function($set) use ($storage, $request, $response) {
        //$rs->requireScope("ssp");
        //$rs->requireEntitlement("urn:x-oauth:entitlement:ssp");

        $response->setContent(json_encode($storage->putEntry($set, $request->getContent())));
    });

    $request->matchRestDefault(function($methodMatch, $patternMatch) use ($request, $response) {
        if (in_array($request->getRequestMethod(), $methodMatch)) {
            if (!$patternMatch) {
                throw new ApiException("not_found", "resource not found");
            }
        } else {
            throw new ApiException("method_not_allowed", "request method not allowed");
        }
    });

} catch (ApiException $e) {
    $response = new HttpResponse($e->getResponseCode(), "application/json");
    $response->setContent(json_encode(array("error" => $e->getMessage(), "error_description" => $e->getDescription())));
    if (NULL !== $logger) {
        $logger->logFatal($e->getLogMessage(TRUE) . PHP_EOL . $request . PHP_EOL . $response);
    }
} catch (Exception $e) {
    $response = new HttpResponse(500, "application/json");
    $response->setContent(json_encode(array("error" => "internal_server_error", "error_description" => $e->getMessage())));
    if (NULL !== $logger) {
        $logger->logFatal($e->getMessage() . PHP_EOL . $request . PHP_EOL . $response);
    }
}

if (NULL !== $logger) {
    $logger->logDebug($request);
}
if (NULL !== $logger) {
    $logger->logDebug($response);
}
if (NULL !== $response) {
    $response->sendResponse();
}
