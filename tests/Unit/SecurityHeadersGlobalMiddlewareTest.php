<?php

declare(strict_types=1);

namespace Marko\Security\Tests\Unit\SecurityHeadersGlobalMiddleware;

use Marko\Core\Container\Container;
use Marko\Core\Container\PreferenceRegistry;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\RouteCollection;
use Marko\Routing\RouteDefinition;
use Marko\Routing\RouteMatcher;
use Marko\Routing\Router;
use Marko\Security\Middleware\SecurityHeadersMiddleware;
use Marko\Security\Tests\Helpers;

/**
 * @noinspection PhpUnused - Actions invoked by the router
 */
class GlobalHeadersController
{
    public function show(): Response
    {
        return new Response('Shown');
    }

    public function embed(): Response
    {
        return new Response('Embeddable');
    }
}

/**
 * A router wired the way marko/security's module.php wires it:
 * SecurityHeadersMiddleware is global and no route opts in with #[Middleware].
 */
function globalHeadersRouter(): Router
{
    $routes = new RouteCollection();
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/account',
        controller: GlobalHeadersController::class,
        action: 'show',
    ));
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/widget',
        controller: GlobalHeadersController::class,
        action: 'embed',
        withoutMiddleware: [SecurityHeadersMiddleware::class],
    ));

    $container = new Container(new PreferenceRegistry());
    $container->instance(
        SecurityHeadersMiddleware::class,
        new SecurityHeadersMiddleware(Helpers::createSecurityConfig(Helpers::defaultHeadersConfig())),
    );
    $container->instance(GlobalHeadersController::class, new GlobalHeadersController());

    return new Router(
        matcher: new RouteMatcher($routes),
        container: $container,
        globalMiddleware: [SecurityHeadersMiddleware::class],
    );
}

function httpsGet(
    string $uri,
): Request {
    return new Request(server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $uri, 'HTTPS' => 'on']);
}

describe('SecurityHeadersMiddleware as global middleware', function (): void {
    it('adds the security headers to a route that never opted in', function (): void {
        $response = globalHeadersRouter()->handle(httpsGet('/account'));

        expect($response->body())->toBe('Shown')
            ->and($response->headers())->toMatchArray([
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'SAMEORIGIN',
                'X-XSS-Protection' => '0',
                'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
                'Content-Security-Policy' => "default-src 'self'",
            ]);
    });

    it('adds the security headers to a 404 for an unknown path', function (): void {
        $response = globalHeadersRouter()->handle(httpsGet('/does-not-exist'));

        expect($response->statusCode())->toBe(404)
            ->and($response->headers())->toHaveKey('X-Content-Type-Options')
            ->and($response->headers())->toHaveKey('Content-Security-Policy');
    });

    it('lets a route exempted with WithoutMiddleware skip the security headers', function (): void {
        $response = globalHeadersRouter()->handle(httpsGet('/widget'));

        expect($response->body())->toBe('Embeddable')
            ->and($response->headers())->not->toHaveKey('X-Frame-Options')
            ->and($response->headers())->not->toHaveKey('Content-Security-Policy');
    });
});
