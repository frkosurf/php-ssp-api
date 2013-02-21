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

require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "SplClassLoader.php";

$c1 = new SplClassLoader("RestService", "../extlib/php-rest-service/lib");
$c1->register();
$c2 = new SplClassLoader("OAuth", "../extlib/php-lib-remote-rs/lib");
$c2->register();
$c3 = new SplClassLoader("SspApi", "../lib");
$c3->register();

use \RestService\Http\HttpRequest as HttpRequest;
use \RestService\Http\HttpResponse as HttpResponse;
use \RestService\Http\IncomingHttpRequest as IncomingHttpRequest;
use \RestService\Utils\Config as Config;
use \RestService\Utils\Logger as Logger;

use \SspApi\SspApi as SspApi;
use \SspApi\SspApiException as SspApiException;

use \OAuth\RemoteResourceServerException as RemoteResourceServerException;

$logger = NULL;
$request = NULL;
$response = NULL;

try {
    $config = new Config(dirname(__DIR__) . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "config.ini");
    $logger = new Logger($config->getSectionValue('Log', 'logLevel'), $config->getValue('serviceName'), $config->getSectionValue('Log', 'logFile'), $config->getSectionValue('Log', 'logMail', FALSE));

    $service = new SspApi($config, $logger);

    $request = HttpRequest::fromIncomingHttpRequest(new IncomingHttpRequest());

    $request->matchRest("GET", "/:set/", function($set) use ($request, &$response, $service) {
        $response = $service->getEntities($set, $request);
    });

    $request->matchRest("GET", "/:set/entity", function($set) use ($request, &$response, $service) {
        $response = $service->getEntity($set, $request);
    });

    $request->matchRest("DELETE", "/:set/entity", function($set) use ($request, &$response, $service) {
        $response = $service->deleteEntity($set, $request);
    });

    $request->matchRest("PUT", "/:set/entity", function($set) use ($request, &$response, $service) {
        $response = $service->putEntity($set, $request);
    });

    $request->matchRest("POST", "/:set/", function($set) use ($request, &$response, $service) {
        $response = $service->postEntity($set, $request);
    });

    $request->matchRestDefault(function($methodMatch, $patternMatch) use ($request) {
        if (in_array($request->getRequestMethod(), $methodMatch)) {
            if (!$patternMatch) {
                throw new SspApiException("not_found", "resource not found");
            }
        } else {
            throw new SspApiException("method_not_allowed", "request method not allowed");
        }
    });

} catch (SspApiException $e) {
    $response = new HttpResponse($e->getResponseCode());
    $response->setHeader("Content-Type", "application/json");
    $response->setContent(json_encode(array("error" => $e->getMessage(), "error_description" => $e->getMessage())));
    if (NULL !== $logger) {
        $logger->logFatal($e->getLogMessage(TRUE) . PHP_EOL . $request . PHP_EOL . $response);
    }
} catch (RemoteResourceServerException $e) {
    $response = new HttpResponse($e->getResponseCode());
    $response->setHeader("WWW-Authenticate", $e->getAuthenticateHeader());
    $response->setHeader("Content-Type", "application/json");
    $response->setContent($e->getContent());
    if (NULL !== $logger) {
        $logger->logWarn($e->getMessage() . PHP_EOL . $e->getDescription() . PHP_EOL . $request . PHP_EOL . $response);
    }
} catch (Exception $e) {
    $response = new HttpResponse(500);
    $response->setHeader("Content-Type", "application/json");
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
