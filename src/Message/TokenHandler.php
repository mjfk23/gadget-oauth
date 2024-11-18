<?php

declare(strict_types=1);

namespace Gadget\Oauth\Message;

use Gadget\Http\Message\ContentType;
use Gadget\Http\Message\MessageHandler;
use Gadget\Http\Message\RequestBuilder;
use Gadget\Http\Message\RequestMethod;
use Gadget\Oauth\Model\TokenRequest;
use Gadget\Oauth\Model\TokenResponse;
use Gadget\Io\Cast;
use Gadget\Oauth\Exception\AuthException;
use Psr\Http\Message\ResponseInterface;

/** @extends MessageHandler<TokenResponse> */
class TokenHandler extends MessageHandler
{
    /**
     * @param string $tokenUri
     * @param TokenRequest $tokenRequest
     */
    public function __construct(
        private string $tokenUri,
        private TokenRequest $tokenRequest
    ) {
    }


    /** @return RequestBuilder */
    protected function createRequestBuilder(): RequestBuilder
    {
        return parent::createRequestBuilder()
            ->setMethod(RequestMethod::POST)
            ->setUri($this->tokenUri)
            ->setBody(
                [
                    'grant_type' => $this->tokenRequest->grantType, //'authorization_code',
                    'client_id' => $this->tokenRequest->clientId,
                    'client_secret' => $this->tokenRequest->clientSecret
                ] + match ($this->tokenRequest->grantType) {
                    'authorization_code' => [
                        'redirect_uri' => $this->tokenRequest->redirectUri,
                        'code' => $this->tokenRequest->code,
                        'code_verifier' => $this->tokenRequest->pkce?->verifier
                    ],
                    'refresh_token' => [
                        'refresh_token' => $this->tokenRequest->refreshToken
                    ],
                    default => []
                },
                ContentType::FORM
            );
    }


    /**
     * @param ResponseInterface $response
     * @return TokenResponse
     */
    public function handleResponse(ResponseInterface $response): mixed
    {
        if ($response->getStatusCode() !== 200) {
            throw new AuthException();
        }

        $values = Cast::toArray($response->getBody()->getContents());

        return new TokenResponse(
            tokenType: Cast::toString($values['token_type'] ?? null),
            scope: Cast::toString($values['scope'] ?? null),
            expiresIn: Cast::toInt($values['expires_in'] ?? 0),
            accessToken: Cast::toValueOrNull($values['access_token'] ?? null, Cast::toString(...)),
            idToken: Cast::toValueOrNull($values['id_token'] ?? null, Cast::toString(...)),
            refreshToken: Cast::toValueOrNull($values['id_token'] ?? null, Cast::toString(...))
        );
    }
}
