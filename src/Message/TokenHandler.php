<?php

declare(strict_types=1);

namespace Gadget\Oauth\Message;

use Gadget\Http\Message\MessageHandler;
use Gadget\Oauth\Model\TokenRequest;
use Gadget\Oauth\Model\TokenResponse;
use Gadget\Oauth\Exception\AuthException;
use Psr\Http\Message\ServerRequestInterface;

/** @extends MessageHandler<TokenResponse> */
class TokenHandler extends MessageHandler
{
    /**
     * @param TokenRequest $tokenRequest
     */
    public function __construct(private TokenRequest $tokenRequest)
    {
    }


    /**
     * @return ServerRequestInterface
     */
    protected function createRequest(): ServerRequestInterface
    {
        return $this->getRequestBuilder()
            ->setMethod('POST')
            ->setUri($this->tokenRequest->tokenUri)
            ->setBody(
                'application/x-www-form-urlencoded',
                $this->tokenRequest->getBody()
            )
            ->getRequest();
    }


    /**
     * @return TokenResponse
     */
    public function handleResponse(): mixed
    {
        return ($this->getResponse()->getStatusCode() === 200)
            ? TokenResponse::create($this->decodeResponse())
            : throw new AuthException();
    }
}
