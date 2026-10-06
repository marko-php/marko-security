<?php

declare(strict_types=1);

namespace Marko\Security\Observer;

use Marko\Authentication\Event\LogoutEvent;
use Marko\Core\Attributes\Observer;
use Marko\Security\Contracts\CsrfTokenManagerInterface;

/**
 * Issues a new CSRF token when a user logs out.
 *
 * The next person on a shared machine must not inherit the CSRF token of the
 * user who just logged out.
 *
 * LogoutEvent comes from marko/authentication; without that package installed
 * it is never dispatched and this observer never runs.
 */
#[Observer(event: LogoutEvent::class)]
readonly class RotateCsrfTokenOnLogout
{
    public function __construct(
        private CsrfTokenManagerInterface $csrfTokenManager,
    ) {}

    public function handle(
        LogoutEvent $event,
    ): void {
        $this->csrfTokenManager->regenerate();
    }
}
