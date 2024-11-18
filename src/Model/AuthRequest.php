<?php

declare(strict_types=1);

namespace Gadget\Oauth\Model;

class AuthRequest
{
    /** @var string $state */
    public string $state;


    /**
     * @param string $responseType
     * @param string $clientId
     * @param string $redirectUri
     * @param string $scope
     * @param string|null $state
     * @param PKCE|null $pkce
     * @param string|null $responseMode
     * @param string|null $nonce
     * @param string|null $display
     * @param string|null $prompt
     */
    public function __construct(
        public string $responseType,
        public string $clientId,
        public string $redirectUri,
        public string $scope,
        string|null $state = null,
        public PKCE|null $pkce = null,
        public string|null $responseMode = null,
        public string|null $nonce = null,
        public string|null $display = null,
        public string|null $prompt = null
    ) {
        $this->state = $state ?? bin2hex(random_bytes(32));
        $this->nonce ??= $this->responseType === 'id_token'
            ? bin2hex(random_bytes(32))
            : null;
    }
}
