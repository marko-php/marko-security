<?php

declare(strict_types=1);

namespace Marko\Security\Exceptions;

use Marko\Core\Exceptions\HttpExceptionInterface;

/**
 * Rendered by the routing pipeline as 419 Page Expired.
 */
class CsrfTokenMismatchException extends SecurityException implements HttpExceptionInterface
{
    public static function invalidToken(): self
    {
        return new self(
            message: 'CSRF token validation failed.',
            context: 'The submitted CSRF token does not match the token stored in the session. This can happen when the session has expired, the token was not included in the request, or the token has been tampered with.',
            suggestion: 'Ensure your form includes a valid CSRF token field (_token), or send it in the X-CSRF-TOKEN or X-XSRF-TOKEN header. If the session has expired, refresh the page to get a new token. Routes that cannot carry a token (webhooks, token-authenticated APIs) opt out with #[WithoutMiddleware(CsrfMiddleware::class)].',
        );
    }

    public function getStatusCode(): int
    {
        return 419;
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return [];
    }

    /**
     * @return array<string, mixed>
     */
    public function getResponseData(): array
    {
        return ['message' => 'CSRF token mismatch.'];
    }
}
