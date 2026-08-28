<?php

/**
 * This file is part of Milpa Auth — the runtime-native identity vocabulary of the Milpa PHP framework.
 *
 * (c) Rodrigo Vicente - TeamX Agency — https://teamx.agency <hola@teamx.agency>
 *
 * @license Apache-2.0
 *
 * @link    https://github.com/getmilpa/auth
 */

declare(strict_types=1);

namespace Milpa\Auth\WebAuthn;

/**
 * What the registration ceremony hands the house to remember about a passkey: the credential id, the
 * public key that will verify its future assertions, and the sign counter it started at.
 *
 * It is the durable half the verifier reads back (its `publicKeyPem` feeds
 * {@see WebAuthnAssertionVerifier}). What this credential is WORTH here is a separate question — the
 * enrollment answers that (greenhouse decisions/0117); registration only proves the house holds a real,
 * verifiable public key for a real authenticator.
 */
final readonly class RegisteredCredential
{
    public function __construct(
        public string $credentialId,
        public string $publicKeyPem,
        public int $signCount,
    ) {
    }
}
