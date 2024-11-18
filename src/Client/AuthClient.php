<?php

declare(strict_types=1);

namespace Gadget\Oauth\Client;

use Gadget\Http\Client\Client;
use Gadget\Oauth\Message\AuthHandler;
use Gadget\Oauth\Message\TokenHandler;
use Gadget\Oauth\Model\AuthRequest;
use Gadget\Oauth\Model\AuthResponse;
use Gadget\Oauth\Model\PKCE;
use Gadget\Oauth\Model\TokenRequest;
use Gadget\Oauth\Model\TokenResponse;

class AuthClient
{
    /**
     * @param Client $client
     * @param string $authUri
     * @param string $clientId
     * @param string $redirectUri
     * @param string $scope
     */
    public function __construct(
        protected Client $client,
        protected string $authUri,
        protected string $tokenUri,
        protected string $clientId,
        protected string $clientSecret,
        protected string $redirectUri,
        protected string $scope
    ) {
    }


    /**
     * @param string|null $state
     * @param PKCE|null $pkce
     * @return AuthResponse
     */
    public function createAuthCode(
        string|null $state = null,
        PKCE|null $pkce = null
    ): AuthResponse {
        return $this->client->invoke(new AuthHandler(
            client: $this->client,
            authUri: $this->authUri,
            authRequest: new AuthRequest(
                responseType: 'code',
                clientId: $this->clientId,
                redirectUri: $this->redirectUri,
                scope: $this->scope,
                state: $state,
                pkce: $pkce
            )
        ));
    }


    /**
     * @param string $code
     * @param PKCE|null|null $pkce
     * @return TokenResponse
     */
    public function createToken(
        string $code,
        PKCE|null $pkce = null
    ): TokenResponse {
        return $this->client->invoke(new TokenHandler(
            tokenUri: $this->tokenUri,
            tokenRequest: new TokenRequest(
                grantType: 'authorization_code',
                clientId: $this->clientId,
                clientSecret: $this->clientSecret,
                code: $code,
                redirectUri: $this->redirectUri,
                pkce: $pkce
            )
        ));
    }


    /**
     * @param string $refreshToken
     * @return TokenResponse
     */
    public function refreshToken(string $refreshToken): TokenResponse
    {
        return $this->client->invoke(new TokenHandler(
            tokenUri: $this->tokenUri,
            tokenRequest: new TokenRequest(
                grantType: 'authorization_code',
                clientId: $this->clientId,
                clientSecret: $this->clientSecret,
                refreshToken: $refreshToken
            )
        ));
    }
}
