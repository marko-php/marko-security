<?php

declare(strict_types=1);

namespace Marko\Security\Observer;

use Marko\Authentication\Event\LoginEvent;
use Marko\Core\Attributes\Observer;
use Marko\Security\Contracts\CsrfTokenManagerInterface;

/**
 * Issues a new CSRF token when a user logs in.
 *
 * The session ID is regenerated on login but the session data carries over,
 * so without this a CSRF token known before login (for example from a session
 * planted by a sibling subdomain) would stay valid for the logged-in user.
 *
 * LoginEvent comes from marko/authentication; without that package installed
 * it is never dispatched and this observer never runs.
 */
#[Observer(event: LoginEvent::class)]
readonly class RotateCsrfTokenOnLogin
{
    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager,
    ) {}

    public function handle(
        LoginEvent $event,
    ): void {
        $this->csrfTokenManager->regenerate();
    }
}
