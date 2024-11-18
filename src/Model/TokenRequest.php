<?php

declare(strict_types=1);

namespace Gadget\Oauth\Model;

class TokenRequest
{
    /**
     * @param string $grantType
     * @param string $clientId
     * @param string $clientSecret
     * @param string|null $code
     * @param string|null $redirectUri
     * @param PKCE|null $pkce
     * @param string|null $refreshToken
     */
    public function __construct(
        public string $grantType,
        public string $clientId,
        public string $clientSecret,
        public string|null $code = null,
        public string|null $redirectUri = null,
        public PKCE|null $pkce = null,
        public string|null $refreshToken = null
    ) {
    }
}
