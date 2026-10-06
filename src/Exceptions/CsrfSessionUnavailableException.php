<?php

declare(strict_types=1);

namespace Marko\Security\Exceptions;

/**
 * Thrown when CsrfMiddleware must verify a state-changing request but the
 * route runs without a session, so there is no stored token to compare to.
 */
class CsrfSessionUnavailableException extends SecurityException
{
    public static function forRequest(
        string $method,
        string $path,
    ): self {
        return new self(
            message: "CSRF protection cannot verify $method $path: no session is available.",
            context: 'CsrfMiddleware is registered globally by marko/security and compares the submitted token with the one stored in the session, but this route runs without SessionMiddleware (for example it is excluded with #[WithoutMiddleware(SessionMiddleware::class)]).',
            suggestion: 'Routes that do not use cookie sessions (webhooks, token-authenticated APIs) should also opt out of CSRF: add #[WithoutMiddleware(CsrfMiddleware::class)] to the route or its controller. Otherwise remove the SessionMiddleware exclusion.',
        );
    }
}
