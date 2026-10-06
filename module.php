<?php

declare(strict_types=1);

use Marko\Core\Container\ContainerInterface;
use Marko\Encryption\Contracts\EncryptorInterface;
use Marko\Security\Config\SecurityConfig;
use Marko\Security\Contracts\CsrfTokenManagerInterface;
use Marko\Security\CsrfTokenManager;
use Marko\Security\Middleware\CsrfMiddleware;
use Marko\Security\Middleware\SecurityHeadersMiddleware;
use Marko\Session\Contracts\SessionInterface;

return [
    // CsrfMiddleware reads the token from the session, so SessionMiddleware
    // (registered globally by the session drivers) must run first.
    'sequence' => [
        'after' => ['marko/session-file', 'marko/session-database'],
    ],
    'bindings' => [
        CsrfTokenManagerInterface::class => function (ContainerInterface $container): CsrfTokenManagerInterface {
            return new CsrfTokenManager(
                session: $container->get(SessionInterface::class),
                encryptor: $container->get(EncryptorInterface::class),
                sessionKey: $container->get(SecurityConfig::class)->csrfSessionKey(),
            );
        },
    ],
    // Every matched route is protected; opt a route out with
    // #[WithoutMiddleware(CsrfMiddleware::class)] or
    // #[WithoutMiddleware(SecurityHeadersMiddleware::class)].
    // SecurityHeadersMiddleware comes first so it wraps CsrfMiddleware and
    // also decorates the 419 a token mismatch renders.
    'globalMiddleware' => [
        SecurityHeadersMiddleware::class,
        CsrfMiddleware::class,
    ],
];
