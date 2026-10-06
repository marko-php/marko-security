<?php

declare(strict_types=1);

use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;
use Marko\Security\Contracts\CsrfTokenManagerInterface;
use Marko\Security\Exceptions\CsrfSessionUnavailableException;
use Marko\Security\Exceptions\CsrfTokenMismatchException;
use Marko\Security\Tests\Helpers;
use Marko\Testing\Fake\FakeSession;

function createStubTokenManager(
    string $storedToken = 'valid-csrf-token',
): CsrfTokenManagerInterface {
    return new class ($storedToken) implements CsrfTokenManagerInterface
    {
        public function __construct(
            private readonly string $storedToken,
        ) {}

        public function get(): string
        {
            return $this->storedToken;
        }

        public function validate(
            string $token,
        ): bool {
            return hash_equals($this->storedToken, $token);
        }

        public function regenerate(): string
        {
            return $this->storedToken;
        }
    };
}

describe('CsrfMiddleware', function (): void {
    it('validates token from X-XSRF-TOKEN header on POST request', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('my-token'));

        $request = new Request(
            server: [
                'REQUEST_METHOD' => 'POST',
                'HTTP_X_XSRF_TOKEN' => 'my-token',
            ],
        );

        $response = $middleware->handle($request, fn (Request $r) => new Response('OK', 200));

        expect($response->statusCode())->toBe(200)
            ->and($response->body())->toBe('OK');
    });

    it('rejects an empty token even when one is submitted', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager(''));

        $request = new Request(
            server: ['REQUEST_METHOD' => 'POST'],
            post: ['_token' => ''],
        );

        $middleware->handle($request, fn (Request $r) => new Response('OK', 200));
    })->throws(CsrfTokenMismatchException::class);

    it('issues a readable XSRF-TOKEN cookie when the request resumes a session', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('session-token'));

        $response = $middleware->handle(
            new Request(server: ['REQUEST_METHOD' => 'GET'], cookies: Helpers::resumedSessionCookies()),
            fn (Request $r) => new Response('OK', 200),
        );

        $cookie = Helpers::findXsrfCookie($response);

        expect($cookie)->not->toBeNull()
            ->and($cookie?->value())->toBe('session-token')
            ->and($cookie?->httpOnly())->toBeFalse()
            ->and($cookie?->sameSite())->toBe('Lax')
            ->and($cookie?->secure())->toBeTrue()
            ->and($cookie?->path())->toBe('/');
    });

    it('issues the XSRF-TOKEN cookie when the request starts and modifies a new session', function (): void {
        $session = new FakeSession();
        $session->arm();
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('session-token'), $session);

        $response = $middleware->handle(
            new Request(server: ['REQUEST_METHOD' => 'GET']),
            function (Request $r) use ($session): Response {
                $session->set('cart', ['sku-1']);

                return new Response('OK', 200);
            },
        );

        expect(Helpers::findXsrfCookie($response)?->value())->toBe('session-token');
    });

    it('issues no XSRF-TOKEN cookie when a session is only read and will be discarded', function (): void {
        $session = new FakeSession();
        $session->setId('fresh-id-replacing-a-stale-cookie');
        $session->start();
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('session-token'), $session);

        $response = $middleware->handle(
            new Request(server: ['REQUEST_METHOD' => 'GET'], cookies: Helpers::resumedSessionCookies()),
            fn (Request $r) => new Response('OK', 200),
        );

        expect(Helpers::findXsrfCookie($response))->toBeNull()
            ->and($session->isModified())->toBeFalse();
    });

    it('follows the session cookie secure flag for the XSRF-TOKEN cookie', function (): void {
        $middleware = Helpers::createCsrfMiddleware(
            createStubTokenManager('session-token'),
            sessionCookieConfig: ['session.cookie.secure' => false],
        );

        $response = $middleware->handle(
            new Request(server: ['REQUEST_METHOD' => 'GET'], cookies: Helpers::resumedSessionCookies()),
            fn (Request $r) => new Response('OK', 200),
        );

        expect(Helpers::findXsrfCookie($response)?->secure())->toBeFalse();
    });

    it('does not resend the XSRF-TOKEN cookie when the client already holds the current token', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('session-token'));

        $response = $middleware->handle(
            new Request(
                server: ['REQUEST_METHOD' => 'GET'],
                cookies: [...Helpers::resumedSessionCookies(), 'XSRF-TOKEN' => 'session-token'],
            ),
            fn (Request $r) => new Response('OK', 200),
        );

        expect(Helpers::findXsrfCookie($response))->toBeNull();
    });

    it('issues no XSRF-TOKEN cookie on a request that never used the session', function (): void {
        $session = new FakeSession();
        $session->arm();

        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('session-token'), $session);

        $response = $middleware->handle(
            new Request(server: ['REQUEST_METHOD' => 'GET']),
            fn (Request $r) => new Response('OK', 200),
        );

        expect(Helpers::findXsrfCookie($response))->toBeNull()
            ->and($session->started)->toBeFalse();
    });

    it('throws a loud error when a state-changing request has no session to verify against', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager(), new FakeSession());

        $middleware->handle(
            new Request(server: ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/webhooks/stripe']),
            fn (Request $r) => new Response('OK', 200),
        );
    })->throws(CsrfSessionUnavailableException::class, 'CSRF protection cannot verify POST /webhooks/stripe');

    it('implements MiddlewareInterface', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager());

        expect($middleware)->toBeInstanceOf(MiddlewareInterface::class);
    });

    it('passes GET requests through without validation', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager());

        $request = new Request(server: ['REQUEST_METHOD' => 'GET']);
        $next = fn (Request $r) => new Response('OK', 200);

        $response = $middleware->handle($request, $next);

        expect($response->statusCode())->toBe(200)
            ->and($response->body())->toBe('OK');
    });

    it('passes HEAD and OPTIONS requests through without validation', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager());

        $headRequest = new Request(server: ['REQUEST_METHOD' => 'HEAD']);
        $optionsRequest = new Request(server: ['REQUEST_METHOD' => 'OPTIONS']);
        $next = fn (Request $r) => new Response('OK', 200);

        $headResponse = $middleware->handle($headRequest, $next);
        $optionsResponse = $middleware->handle($optionsRequest, $next);

        expect($headResponse->statusCode())->toBe(200)
            ->and($optionsResponse->statusCode())->toBe(200);
    });

    it('validates token from _token POST field on POST request', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('my-token'));

        $request = new Request(
            server: ['REQUEST_METHOD' => 'POST'],
            post: ['_token' => 'my-token'],
        );
        $next = fn (Request $r) => new Response('OK', 200);

        $response = $middleware->handle($request, $next);

        expect($response->statusCode())->toBe(200)
            ->and($response->body())->toBe('OK');
    });

    it('validates token from X-CSRF-TOKEN header on POST request', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('my-token'));

        $request = new Request(
            server: [
                'REQUEST_METHOD' => 'POST',
                'HTTP_X_CSRF_TOKEN' => 'my-token',
            ],
        );
        $next = fn (Request $r) => new Response('OK', 200);

        $response = $middleware->handle($request, $next);

        expect($response->statusCode())->toBe(200)
            ->and($response->body())->toBe('OK');
    });

    it('throws CsrfTokenMismatchException when token is missing on POST', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager());

        $request = new Request(server: ['REQUEST_METHOD' => 'POST']);
        $next = fn (Request $r) => new Response('OK', 200);

        $middleware->handle($request, $next);
    })->throws(CsrfTokenMismatchException::class);

    it('throws CsrfTokenMismatchException when token is invalid on PUT PATCH DELETE', function (): void {
        $middleware = Helpers::createCsrfMiddleware(createStubTokenManager('valid-token'));

        $next = fn (Request $r) => new Response('OK', 200);

        // Test PUT
        $putRequest = new Request(
            server: ['REQUEST_METHOD' => 'PUT'],
            post: ['_token' => 'wrong-token'],
        );

        $threw = false;

        try {
            $middleware->handle($putRequest, $next);
        } catch (CsrfTokenMismatchException) {
            $threw = true;
        }

        expect($threw)->toBeTrue();

        // Test PATCH
        $patchRequest = new Request(
            server: ['REQUEST_METHOD' => 'PATCH'],
            post: ['_token' => 'wrong-token'],
        );

        $threw = false;

        try {
            $middleware->handle($patchRequest, $next);
        } catch (CsrfTokenMismatchException) {
            $threw = true;
        }

        expect($threw)->toBeTrue();

        // Test DELETE
        $deleteRequest = new Request(
            server: ['REQUEST_METHOD' => 'DELETE'],
            post: ['_token' => 'wrong-token'],
        );

        $threw = false;

        try {
            $middleware->handle($deleteRequest, $next);
        } catch (CsrfTokenMismatchException) {
            $threw = true;
        }

        expect($threw)->toBeTrue();
    });
});
