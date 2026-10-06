<?php

declare(strict_types=1);

namespace Marko\Security;

use Marko\Encryption\Contracts\EncryptorInterface;
use Marko\Security\Contracts\CsrfTokenManagerInterface;
use Marko\Session\Contracts\SessionInterface;

class CsrfTokenManager implements CsrfTokenManagerInterface
{
    /**
     * @param string $sessionKey Session key holding the token (security.csrf.session_key)
     */
    public function __construct(
        private readonly SessionInterface $session,
        private readonly EncryptorInterface $encryptor,
        private readonly string $sessionKey = '_csrf_token',
    ) {}

    public function get(): string
    {
        $existing = $this->session->get($this->sessionKey);

        if ($existing !== null) {
            return (string) $existing;
        }

        return $this->generateToken();
    }

    public function validate(
        string $token,
    ): bool {
        $stored = $this->session->get($this->sessionKey);

        if ($stored === null) {
            return false;
        }

        return hash_equals((string) $stored, $token);
    }

    public function regenerate(): string
    {
        return $this->generateToken();
    }

    private function generateToken(): string
    {
        $randomBytes = random_bytes(32);
        $token = $this->encryptor->encrypt($randomBytes);

        $this->session->set($this->sessionKey, $token);

        return $token;
    }
}
