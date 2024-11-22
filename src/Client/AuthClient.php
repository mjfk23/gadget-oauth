<?php

declare(strict_types=1);

namespace Gadget\Oauth\Client;

use Gadget\Http\Client\ApiClient;
use Gadget\Oauth\Message\AuthCodeHandler;
use Gadget\Oauth\Message\TokenHandler;
use Gadget\Oauth\Model\AuthCode;
use Gadget\Oauth\Model\AuthCodeRequest;
use Gadget\Oauth\Model\PKCE;
use Gadget\Oauth\Model\Token;
use Gadget\Oauth\Model\TokenRequest;
use Gadget\Oauth\Model\TokenResponse;

class AuthClient extends ApiClient
{
    /**
     * @param string|null $state
     * @param PKCE|null $pkce
     * @return AuthCode
     */
    public function createAuthCode(
        string $authUri,
        string $clientId,
        string $redirectUri,
        string $scope,
        string|null $state = null,
        PKCE|null $pkce = null
    ): AuthCode {
        return $this->invoke(new AuthCodeHandler(new AuthCodeRequest(
            authUri: $authUri,
            responseType: 'code',
            clientId: $clientId,
            redirectUri: $redirectUri,
            scope: $scope,
            state: $state,
            pkce: $pkce
        )));
    }


    /**
     * @param string $tokenUri
     * @param string $clientId
     * @param string $clientSecret
     * @param string $redirectUri
     * @param string $code
     * @param PKCE|null $pkce
     * @return Token
     */
    public function createToken(
        string $tokenUri,
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        string $code,
        PKCE|null $pkce = null
    ): Token {
        return $this->invoke(new TokenHandler(new TokenRequest(
            tokenUri: $tokenUri,
            grantType: 'authorization_code',
            clientId: $clientId,
            clientSecret: $clientSecret,
            code: $code,
            redirectUri: $redirectUri,
            pkce: $pkce
        )));
    }


    /**
     * @param string $tokenUri
     * @param string $clientId
     * @param string $clientSecret
     * @param string $refreshToken
     * @return Token
     */
    public function refreshToken(
        string $tokenUri,
        string $clientId,
        string $clientSecret,
        string $refreshToken
    ): Token {
        return $this->invoke(new TokenHandler(new TokenRequest(
            tokenUri: $tokenUri,
            grantType: 'refresh_token',
            clientId: $clientId,
            clientSecret: $clientSecret,
            refreshToken: $refreshToken
        )));
    }
}
