<?php

declare(strict_types=1);

namespace Marko\Security\Tests\Unit\CsrfHttpMapping;

use Marko\Core\Container\Container;
use Marko\Core\Container\PreferenceRegistry;
use Marko\Core\Exceptions\HttpExceptionInterface;
use Marko\Cors\Config\CorsConfig;
use Marko\Cors\Middleware\CorsMiddleware;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;
use Marko\Routing\Middleware\MiddlewarePipeline;
use Marko\Security\Contracts\CsrfTokenManagerInterface;
use Marko\Security\Exceptions\CsrfTokenMismatchException;
use Marko\Security\Middleware\CsrfMiddleware;
use Marko\Security\Tests\Helpers;
use Marko\Testing\Fake\FakeConfigRepository;

class OuterHeaderMiddleware implements MiddlewareInterface
{
    public function handle(
        Request $request,
        callable $next,
    ): Response {
        return $next($request)->withHeader('X-Frame-Options', 'DENY');
    }
}

class RejectingTokenManager implements CsrfTokenManagerInterface
{
    public function get(): string
    {
        return 'stored-token';
    }

    public function validate(
        string $token,
    ): bool {
        return false;
    }

    public function regenerate(): string
    {
        return 'stored-token';
    }
}

function csrfPipeline(): MiddlewarePipeline
{
    $container = new Container(new PreferenceRegistry());
    $container->instance(OuterHeaderMiddleware::class, new OuterHeaderMiddleware());
    $container->instance(CorsMiddleware::class, new CorsMiddleware(new CorsConfig(new FakeConfigRepository([
        'cors.allowed_origins' => ['https://app.example.com'],
        'cors.allowed_methods' => ['GET', 'POST'],
        'cors.allowed_headers' => ['Content-Type'],
        'cors.expose_headers' => [],
        'cors.supports_credentials' => false,
        'cors.max_age' => 0,
        'cors.paths' => ['*'],
    ]))));
    $container->instance(CsrfMiddleware::class, Helpers::createCsrfMiddleware(new RejectingTokenManager()));

    return new MiddlewarePipeline($container);
}

describe('CsrfTokenMismatchException HTTP mapping', function (): void {
    it('implements HttpExceptionInterface with status 419', function (): void {
        $exception = CsrfTokenMismatchException::invalidToken();

        expect($exception)->toBeInstanceOf(HttpExceptionInterface::class)
            ->and($exception->getStatusCode())->toBe(419)
            ->and($exception->getHeaders())->toBeEmpty()
            ->and($exception->getResponseData())->toBe(['message' => 'CSRF token mismatch.']);
    });

    it('returns 419 when CsrfMiddleware rejects a request through the pipeline', function (): void {
        $response = csrfPipeline()->process(
            [CsrfMiddleware::class],
            new Request(server: ['REQUEST_METHOD' => 'POST', 'HTTP_ACCEPT' => 'application/json']),
            fn (Request $request): Response => new Response('should not run'),
        );

        expect($response->statusCode())->toBe(419)
            ->and(json_decode($response->body(), true))->toBe(['message' => 'CSRF token mismatch.']);
    });

    it('lets an outer header middleware and CorsMiddleware decorate the 419 response', function (): void {
        $response = csrfPipeline()->process(
            [OuterHeaderMiddleware::class, CorsMiddleware::class, CsrfMiddleware::class],
            new Request(server: [
                'REQUEST_METHOD' => 'POST',
                'HTTP_ORIGIN' => 'https://app.example.com',
            ]),
            fn (Request $request): Response => new Response('should not run'),
        );

        expect($response->statusCode())->toBe(419)
            ->and($response->headers())->toMatchArray([
                'X-Frame-Options' => 'DENY',
                'Access-Control-Allow-Origin' => 'https://app.example.com',
                'Vary' => 'Origin',
            ]);
    });
});
