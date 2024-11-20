<?php

declare(strict_types=1);

namespace Gadget\Oauth\Message;

use Gadget\Http\Message\MessageHandler;
use Gadget\Oauth\Exception\AuthException;
use Gadget\Oauth\Model\AuthRequest;
use Gadget\Oauth\Model\AuthResponse;
use Psr\Http\Message\ServerRequestInterface;

/** @extends MessageHandler<AuthResponse> */
class AuthHandler extends MessageHandler
{
    /**
     * @param AuthRequest $authRequest
     */
    public function __construct(private AuthRequest $authRequest)
    {
    }


    /**
     * @return ServerRequestInterface
     */
    protected function createRequest(): ServerRequestInterface
    {
        return $this->getRequestBuilder()
            ->setMethod('GET')
            ->setUri($this->authRequest->authUri)
            ->setQueryParams($this->authRequest->getQueryParams())
            ->getRequest();
    }


    /**
     * @return AuthResponse
     */
    public function handleResponse(): mixed
    {
        $client = $this->getClient();
        $messageFactory = $client->getMessageFactory();
        $response = $this->getResponse();

        do {
            $uri = $response->getStatusCode() === 302
                ? ($response->getHeader('Location')[0] ?? null)
                : null;
            if ($uri == null) {
                throw new AuthException();
            }

            if (str_starts_with($uri, $this->authRequest->redirectUri)) {
                return AuthResponse::createFromUri(
                    $this->authRequest,
                    $uri
                );
            }

            $response = $this->getClient()->sendRequest(
                $messageFactory->createServerRequest('GET', $uri)
            );
        } while (true);
    }
}
