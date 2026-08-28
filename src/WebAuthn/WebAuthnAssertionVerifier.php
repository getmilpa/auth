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
 * Verifies one WebAuthn authentication assertion — the `navigator.credentials.get()` ceremony's proof —
 * against a registered credential's public key, LIVE.
 *
 * This is the crypto throat of the passkey path, kept deliberately narrow (greenhouse H-PASSKEY-1): given
 * the stored public key, the challenge the server issued, the relying-party id, and the three bytes the
 * browser returns (clientDataJSON, authenticatorData, signature), it answers one question — did the
 * holder of THIS credential sign THIS challenge? The verdict is produced here, never read from a flag.
 *
 * The registration ceremony (attestation, COSE→PEM, credential storage), the challenge lifecycle, and
 * the HTTP endpoints are OTHER slices; this one exists to prove the verification is real before they are
 * built. ES256 (ECDSA P-256 over SHA-256) only for now — the overwhelmingly common authenticator
 * algorithm; EdDSA and RS256 are deferred.
 */
final class WebAuthnAssertionVerifier
{
    /** WebAuthn authenticatorData flag bit 0: user present. */
    private const FLAG_USER_PRESENT = 0x01;

    /**
     * Verify one assertion against a registered credential's public key, or refuse it.
     *
     * @param string $publicKeyPem      the credential's public key, PEM-encoded (ES256 / P-256)
     * @param string $expectedChallenge the raw challenge bytes the server issued for this assertion
     * @param string $rpId              the relying-party id whose SHA-256 must open the authenticatorData
     * @param string $clientDataJson    the raw bytes of the browser's clientDataJSON
     * @param string $authenticatorData the raw authenticatorData bytes
     * @param string $signature         the assertion signature (DER ECDSA for ES256)
     *
     * @return VerifiedPasskey|null the credential proven to have signed this challenge, or null when the
     *                              proof does not hold — a failed verification is never a soft pass
     */
    public function verify(
        string $credentialId,
        string $publicKeyPem,
        string $expectedChallenge,
        string $rpId,
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
    ): ?VerifiedPasskey {
        // 1. The clientDataJSON must be a `get` ceremony bound to the challenge the server issued.
        $clientData = json_decode($clientDataJson, true);
        if (!\is_array($clientData)) {
            return null;
        }
        if (($clientData['type'] ?? null) !== 'webauthn.get') {
            return null;
        }
        $challenge = self::base64UrlDecode(\is_string($clientData['challenge'] ?? null) ? $clientData['challenge'] : '');
        if ($challenge === null || !hash_equals($expectedChallenge, $challenge)) {
            return null;
        }

        // 2. The authenticatorData must open for THIS relying party, with the user actually present.
        if (\strlen($authenticatorData) < 37) {
            return null;
        }
        $rpIdHash = substr($authenticatorData, 0, 32);
        if (!hash_equals(hash('sha256', $rpId, true), $rpIdHash)) {
            return null;
        }
        $flags = \ord($authenticatorData[32]);
        if (($flags & self::FLAG_USER_PRESENT) === 0) {
            return null;
        }
        $signCount = unpack('N', substr($authenticatorData, 33, 4))[1] ?? 0;

        // 3. The signature covers authenticatorData || SHA-256(clientDataJSON), verified against the
        //    registered public key. This is the step nothing else can fake.
        $signedData = $authenticatorData . hash('sha256', $clientDataJson, true);
        $ok = openssl_verify($signedData, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            return null;
        }

        return new VerifiedPasskey($credentialId, (int) $signCount);
    }

    /** Decode base64url (no padding), or null when the input is not valid base64url. */
    private static function base64UrlDecode(string $value): ?string
    {
        if ($value === '') {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
