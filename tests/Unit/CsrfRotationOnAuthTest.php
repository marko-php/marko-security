<?php

declare(strict_types=1);

use Marko\Authentication\Event\LoginEvent;
use Marko\Authentication\Event\LogoutEvent;
use Marko\Authentication\Guard\SessionGuard;
use Marko\Core\Attributes\Observer;
use Marko\Core\Container\Container;
use Marko\Core\Event\EventDispatcher;
use Marko\Core\Event\ObserverDefinition;
use Marko\Core\Event\ObserverRegistry;
use Marko\Security\Contracts\CsrfTokenManagerInterface;
use Marko\Security\CsrfTokenManager;
use Marko\Security\Observer\RotateCsrfTokenOnLogin;
use Marko\Security\Observer\RotateCsrfTokenOnLogout;
use Marko\Testing\Fake\FakeAuthenticatable;
use Marko\Testing\Fake\FakeEncryptor;
use Marko\Testing\Fake\FakeSession;
use Marko\Testing\Fake\FakeUserProvider;

function csrfRotationManager(
    FakeSession $session,
): CsrfTokenManager {
    return new CsrfTokenManager($session, new FakeEncryptor());
}

/**
 * A SessionGuard whose events reach the security package's CSRF observers,
 * wired the way observer discovery registers them.
 */
function csrfRotatingGuard(
    FakeSession $session,
    CsrfTokenManager $csrf,
): SessionGuard {
    $container = new Container();
    $container->instance(CsrfTokenManagerInterface::class, $csrf);

    $registry = new ObserverRegistry();
    $registry->register(new ObserverDefinition(
        observerClass: RotateCsrfTokenOnLogin::class,
        eventClass: LoginEvent::class,
    ));
    $registry->register(new ObserverDefinition(
        observerClass: RotateCsrfTokenOnLogout::class,
        eventClass: LogoutEvent::class,
    ));

    return new SessionGuard(
        session: $session,
        provider: new FakeUserProvider([42 => new FakeAuthenticatable(id: 42)]),
        name: 'web',
        eventDispatcher: new EventDispatcher($container, $registry),
    );
}

describe('CSRF token rotation on login and logout', function (): void {
    it('observes LoginEvent and LogoutEvent', function (): void {
        $loginObserver = new ReflectionClass(RotateCsrfTokenOnLogin::class)
            ->getAttributes(Observer::class)[0]->newInstance();
        $logoutObserver = new ReflectionClass(RotateCsrfTokenOnLogout::class)
            ->getAttributes(Observer::class)[0]->newInstance();

        expect($loginObserver->event)->toBe(LoginEvent::class)
            ->and($logoutObserver->event)->toBe(LogoutEvent::class);
    });

    it('invalidates a CSRF token issued before login', function (): void {
        $session = new FakeSession();
        $session->start();
        $csrf = csrfRotationManager($session);
        $preLoginToken = $csrf->get();

        csrfRotatingGuard($session, $csrf)->login(new FakeAuthenticatable(id: 42));

        expect($csrf->validate($preLoginToken))->toBeFalse()
            ->and($csrf->get())->not->toBe($preLoginToken);
    });

    it('invalidates the logged-in CSRF token on logout', function (): void {
        $session = new FakeSession();
        $session->start();
        $csrf = csrfRotationManager($session);
        $guard = csrfRotatingGuard($session, $csrf);
        $guard->login(new FakeAuthenticatable(id: 42));
        $loggedInToken = $csrf->get();

        $guard->logout();

        expect($csrf->validate($loggedInToken))->toBeFalse()
            ->and($csrf->get())->not->toBe($loggedInToken);
    });
});
