<?php

declare(strict_types=1);

namespace Marko\Security\Tests\Unit\CsrfUnmatchedRequest;

use Marko\Core\Container\Container;
use Marko\Core\Container\PreferenceRegistry;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\RouteCollection;
use Marko\Routing\RouteDefinition;
use Marko\Routing\RouteMatcher;
use Marko\Routing\Router;
use Marko\Security\Contracts\CsrfTokenManagerInterface;
use Marko\Security\Middleware\CsrfMiddleware;
use Marko\Security\Tests\Helpers;

class StoredTokenManager implements CsrfTokenManagerInterface
{
    public function get(): string
    {
        return 'stored-token';
    }

    public function validate(
        string $token,
    ): bool {
        return $token === 'stored-token';
    }

    public function regenerate(): string
    {
        return 'stored-token';
    }
}

/**
 * @noinspection PhpUnused - Actions invoked by the router
 */
class CsrfUnmatchedController
{
    public function show(): Response
    {
        return new Response('Shown');
    }

    public function store(): Response
    {
        return new Response('Stored', 201);
    }
}

function csrfRouter(): Router
{
    $routes = new RouteCollection();
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/posts',
        controller: CsrfUnmatchedController::class,
        action: 'show',
    ));
    $routes->add(new RouteDefinition(
        method: 'POST',
        path: '/comments',
        controller: CsrfUnmatchedController::class,
        action: 'store',
    ));

    $container = new Container(new PreferenceRegistry());
    $container->instance(CsrfMiddleware::class, Helpers::createCsrfMiddleware(new StoredTokenManager()));
    $container->instance(CsrfUnmatchedController::class, new CsrfUnmatchedController());

    return new Router(
        matcher: new RouteMatcher($routes),
        container: $container,
        globalMiddleware: [CsrfMiddleware::class],
    );
}

function postRequest(
    string $uri,
): Request {
    return new Request(server: [
        'REQUEST_METHOD' => 'POST',
        'REQUEST_URI' => $uri,
        'HTTP_ACCEPT' => 'application/json',
    ]);
}

it('returns 404 rather than 419 for a POST to an unknown path', function (): void {
    $response = csrfRouter()->handle(postRequest('/wp-login.php'));

    expect($response->statusCode())->toBe(404);
});

it('returns 405 with Allow rather than 419 for a POST to a GET-only path', function (): void {
    $response = csrfRouter()->handle(postRequest('/posts'));

    expect($response->statusCode())->toBe(405)
        ->and($response->headers()['Allow'])->toBe('GET, HEAD, OPTIONS');
});

it('still rejects a POST without a token to a matched route with 419', function (): void {
    $response = csrfRouter()->handle(postRequest('/comments'));

    expect($response->statusCode())->toBe(419);
});
