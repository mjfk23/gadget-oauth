<?php

declare(strict_types=1);

namespace Gadget\Oauth\Message;

use Gadget\Http\Client\Client;
use Gadget\Http\Message\MessageHandler;
use Gadget\Http\Message\RequestBuilder;
use Gadget\Http\Message\RequestMethod;
use Gadget\Oauth\Exception\AuthException;
use Gadget\Oauth\Model\AuthRequest;
use Gadget\Oauth\Model\AuthResponse;
use Psr\Http\Message\ResponseInterface;

/** @extends MessageHandler<AuthResponse> */
class AuthHandler extends MessageHandler
{
    /**
     * @param Client $client
     * @param string $authUri
     * @param AuthRequest $authRequest
     */
    public function __construct(
        private Client $client,
        private string $authUri,
        private AuthRequest $authRequest
    ) {
    }


    /**
     * @return RequestBuilder
     */
    protected function createRequestBuilder(): RequestBuilder
    {
        return parent::createRequestBuilder()
            ->setMethod(RequestMethod::GET)
            ->setUri($this->authUri)
            ->setQueryParams([
                'response_type' => $this->authRequest->responseType,
                'client_id' => $this->authRequest->clientId,
                'redirect_uri' => $this->authRequest->redirectUri,
                'scope' => $this->authRequest->scope,
                'state' => $this->authRequest->state,
                'code_challenge' => $this->authRequest->pkce?->challenge,
                'code_challenge_method' => $this->authRequest->pkce?->mode,
                'response_mode' => $this->authRequest->responseMode,
                'nonce' => $this->authRequest->nonce,
                'display' => $this->authRequest->display,
                'prompt' => $this->authRequest->prompt
            ]);
    }


    /**
     * @param ResponseInterface $response
     * @return AuthResponse
     */
    public function handleResponse(ResponseInterface $response): mixed
    {
        if ($response->getStatusCode() !== 302) {
            throw new AuthException();
        }

        $url = $response->getHeader('Location')[0] ?? throw new AuthException();

        do {
            $request = $this->client->getMessageFactory()->createServerRequest('GET', $url);
            $response = $this->client->sendRequest($request);
            $url = $response->getStatusCode() === 302
                ? ($response->getHeader('Location')[0] ?? null)
                : null;
        } while ($url !== null && !str_starts_with($url, $this->authRequest->redirectUri));

        return AuthResponse::createFromUri(
            $this->authRequest,
            $response->getHeader('Location')[0] ?? throw new AuthException()
        );
    }
}
