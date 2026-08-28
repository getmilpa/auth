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
 * The authentication ceremony, composed safe: issue a one-time challenge, then accept an assertion only
 * when that challenge is spent exactly once, the credential is known, the signature verifies, and the
 * sign counter has not gone backwards.
 *
 * The published {@see WebAuthnAssertionVerifier} answers «did this key sign this challenge?»; this answers
 * the question that makes it a LOGIN rather than a lab check — «and was this a fresh ceremony, for a
 * credential we registered, by an authenticator that has not been cloned?» (greenhouse H-PASSKEY-3). The
 * challenge's single use is what stops replay; the counter's monotonic climb is what surfaces a clone.
 */
final class PasskeyAuthenticator
{
    public function __construct(
        private readonly ChallengeStore $challenges,
        private readonly PasskeyCredentialStore $credentials,
        private readonly WebAuthnAssertionVerifier $verifier = new WebAuthnAssertionVerifier(),
    ) {
    }

    /** Mint a fresh challenge for an authentication ceremony — the caller sends its base64url to the client. */
    public function challenge(): string
    {
        return $this->challenges->issue();
    }

    /**
     * Complete an authentication, or refuse it. Returns the recognized passkey, or null when anything —
     * replay, an unknown credential, a bad signature, a counter regression — does not hold.
     *
     * @param string $credentialId      the credential the client says answered (its own id)
     * @param string $clientDataJson    the browser's clientDataJSON bytes
     * @param string $authenticatorData the authenticatorData bytes
     * @param string $signature         the assertion signature
     */
    public function authenticate(
        string $rpId,
        string $credentialId,
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
    ): ?VerifiedPasskey {
        // The challenge the client echoes must be one we issued and have not yet spent. Reading it here
        // and consuming it BEFORE verifying means a replay is refused whether or not its signature is good.
        $clientData = json_decode($clientDataJson, true);
        $challenge = self::base64UrlDecode(\is_array($clientData) && \is_string($clientData['challenge'] ?? null) ? $clientData['challenge'] : '');
        if ($challenge === null || !$this->challenges->consume($challenge)) {
            return null;
        }

        $credential = $this->credentials->find($credentialId);
        if ($credential === null) {
            return null;
        }

        $verified = $this->verifier->verify(
            $credentialId,
            $credential->publicKeyPem,
            $challenge,
            $rpId,
            $clientDataJson,
            $authenticatorData,
            $signature,
        );
        if ($verified === null) {
            return null;
        }

        // Clone detection (WebAuthn §6.1.1): a counter that did not climb means two authenticators share
        // this credential. Both-zero is allowed — some authenticators never count.
        if (($verified->signCount !== 0 || $credential->signCount !== 0) && $verified->signCount <= $credential->signCount) {
            return null;
        }

        $this->credentials->updateSignCount($credentialId, $verified->signCount);

        return $verified;
    }

    private static function base64UrlDecode(string $value): ?string
    {
        if ($value === '') {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
