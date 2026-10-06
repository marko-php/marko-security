# marko/security

CSRF protection and security headers middleware -- secure your routes with drop-in middleware. For CORS, use [marko/cors](https://marko.build/docs/packages/cors/).

## Installation

```bash
composer require marko/security
```

## Quick Example

`CsrfMiddleware` is registered globally, so every state-changing route is protected. Opt a route out explicitly:

```php
use Marko\Routing\Attributes\Post;
use Marko\Routing\Attributes\WithoutMiddleware;
use Marko\Security\Middleware\CsrfMiddleware;

class WebhookController
{
    #[Post('/webhooks/stripe')]
    #[WithoutMiddleware(CsrfMiddleware::class)]
    public function receive(): Response
    {
        return new Response('Received');
    }
}
```

## Documentation

Full usage, API reference, and examples: [marko/security](https://marko.build/docs/packages/security/)
