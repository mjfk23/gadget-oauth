<?php

declare(strict_types=1);

namespace Gadget\Oauth\Model;

use Gadget\Oauth\Exception\AuthException;
use Psr\Http\Message\UriInterface;

class AuthResponse
{
    /**
     * @param AuthRequest $authRequest
     * @param UriInterface|string $uri
     * @return self
     */
    public static function createFromUri(
        AuthRequest $authRequest,
        UriInterface|string $uri
    ): self {
        if (!is_string($uri)) {
            $uri = $uri->__toString();
        }

        list($redirectUri, $query) = [...explode("?", $uri, 2), '', ''];
        /** @var array<string,string> $queryParams */
        $queryParams = array_map(
            urldecode(...),
            array_column(array_map(fn($v) => [...explode('=', $v, 2), ''], explode("&", $query)), 1, 0)
        );

        $state = $queryParams['state'] ?? null;
        $code = $queryParams['code'] ?? null;
        $idToken = $queryParams['id_token'] ?? null;

        return new self(
            redirectUri: str_starts_with($redirectUri, $authRequest->redirectUri)
                ? $redirectUri
                : throw new AuthException([
                    "Redirect URI mismatch: Expected => %s, Actual => %s",
                    $authRequest->redirectUri,
                    $redirectUri
                ]),
            state: ($state !== null && $state === $authRequest->state)
                ? $state
                : throw new AuthException([
                    "State mismatch: Expected => %s, Actual => %s",
                    $authRequest->state,
                    $state
                ]),
            responseType: $authRequest->responseType,
            responseCode: match ($authRequest->responseType) {
                    'code' => $code,
                    'id_token' => $idToken,
                    default => null
            } ?? throw new AuthException("Missing response code"),
            nonce: $authRequest->nonce,
            pkce: $authRequest->pkce
        );
    }


    /**
     * @param string $redirectUri
     * @param string $state
     * @param string $responseType
     * @param string $responseCode
     * @param string $nonce
     * @param PKCE|null $pkce
     */
    public function __construct(
        public string $redirectUri,
        public string $state,
        public string $responseType,
        public string $responseCode,
        public string|null $nonce,
        public PKCE|null $pkce
    ) {
    }
}
