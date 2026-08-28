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
 * The identity a verified WebAuthn assertion yields — the counterpart, on the HTTP/browser path, of
 * {@see \Milpa\ToolRuntime\Identity\VerifiedSigner} on the CLI/gpg path.
 *
 * It names the credential that signed (its id), nothing more: what that credential is WORTH here is a
 * separate question the enrollment answers (greenhouse decisions/0117). A verified passkey is proof of
 * POSSESSION of a registered authenticator, produced live by re-checking the signature — never a stored
 * grade.
 */
final readonly class VerifiedPasskey
{
    public function __construct(
        public string $credentialId,
        public int $signCount,
    ) {
    }

    /** The principal spelling of this credential, parallel to «key:<fingerprint>» on the gpg path. */
    public function principal(): string
    {
        return 'passkey:' . $this->credentialId;
    }
}
