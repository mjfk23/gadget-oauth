<?php

declare(strict_types=1);

namespace Gadget\Oauth\Model;

class TokenResponse
{
    /**
     * @param string $tokenType
     * @param string $scope
     * @param int $expiresIn
     * @param string|null $accessToken
     * @param string|null $idToken
     * @param string|null $refreshToken
     */
    public function __construct(
        public string $tokenType,
        public string $scope,
        public int $expiresIn,
        public string|null $accessToken = null,
        public string|null $idToken = null,
        public string|null $refreshToken = null
    ) {
    }
}
