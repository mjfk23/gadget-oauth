<?php

declare(strict_types=1);

namespace Gadget\Oauth\Model;

use Gadget\Io\Cast;

class TokenResponse
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = Cast::toArray($values);
        return new self(
            tokenType: Cast::toString($values['token_type'] ?? null),
            scope: Cast::toString($values['scope'] ?? null),
            expiresIn: Cast::toInt($values['expires_in'] ?? 0),
            accessToken: Cast::toValueOrNull($values['access_token'] ?? null, Cast::toString(...)),
            idToken: Cast::toValueOrNull($values['id_token'] ?? null, Cast::toString(...)),
            refreshToken: Cast::toValueOrNull($values['refresh_token'] ?? null, Cast::toString(...))
        );
    }


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
