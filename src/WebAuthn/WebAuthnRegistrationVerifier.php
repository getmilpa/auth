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
 * Verifies one WebAuthn registration — the `navigator.credentials.create()` ceremony — and extracts the
 * credential the house will remember: its id, its public key, its starting counter.
 *
 * Registration's load-bearing job is to come away with a REAL, verifiable public key bound to THIS
 * challenge and relying party — the key that {@see WebAuthnAssertionVerifier} will later check assertions
 * against. So this reads the attestationObject (CBOR), checks the create-ceremony's clientData binding and
 * the authenticatorData (rpIdHash, user-present, the attested-credential-data flag), pulls the credential
 * id and the COSE public key out of the attested credential data, and converts the key to PEM.
 *
 * ATTESTATION TRUST IS OUT OF SCOPE for v1 (greenhouse decisions/0123): this does not verify the
 * attestation STATEMENT (packed/tpm/android-key signatures, certificate chains) — it extracts the key an
 * authenticator presented, which is what a self/none attestation already amounts to. Statement trust,
 * the challenge lifecycle, and non-ES256 algorithms are later slices built ON this one.
 */
final class WebAuthnRegistrationVerifier
{
    private const FLAG_USER_PRESENT = 0x01;
    private const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    /**
     * Verify a registration and extract its credential, or return null when the proof does not hold.
     *
     * @param string $expectedChallenge the raw challenge bytes the server issued for this registration
     * @param string $rpId              the relying-party id whose SHA-256 must open the authenticatorData
     * @param string $clientDataJson    the raw bytes of the browser's clientDataJSON
     * @param string $attestationObject the raw CBOR attestationObject the browser returned
     */
    public function verify(
        string $expectedChallenge,
        string $rpId,
        string $clientDataJson,
        string $attestationObject,
    ): ?RegisteredCredential {
        // 1. A create ceremony, bound to the issued challenge.
        $clientData = json_decode($clientDataJson, true);
        if (!\is_array($clientData) || ($clientData['type'] ?? null) !== 'webauthn.create') {
            return null;
        }
        $challenge = self::base64UrlDecode(\is_string($clientData['challenge'] ?? null) ? $clientData['challenge'] : '');
        if ($challenge === null || !hash_equals($expectedChallenge, $challenge)) {
            return null;
        }

        // 2. The attestationObject is CBOR: { fmt, attStmt, authData }. The key lives in authData.
        try {
            $attestation = Cbor::decode($attestationObject);
        } catch (\Throwable) {
            return null;
        }
        if (!\is_array($attestation) || !\is_string($attestation['authData'] ?? null)) {
            return null;
        }
        $authData = $attestation['authData'];

        // 3. authenticatorData: rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖ [attested credential data].
        if (\strlen($authData) < 37) {
            return null;
        }
        if (!hash_equals(hash('sha256', $rpId, true), substr($authData, 0, 32))) {
            return null;
        }
        $flags = \ord($authData[32]);
        if (($flags & self::FLAG_USER_PRESENT) === 0 || ($flags & self::FLAG_ATTESTED_CREDENTIAL_DATA) === 0) {
            return null;
        }
        $signCount = (int) (unpack('N', substr($authData, 33, 4))[1] ?? 0);

        // 4. Attested credential data: aaguid(16) ‖ credIdLen(2) ‖ credId ‖ COSE public key.
        $offset = 37 + 16;
        if (\strlen($authData) < $offset + 2) {
            return null;
        }
        $credIdLen = (int) (unpack('n', substr($authData, $offset, 2))[1] ?? 0);
        $offset += 2;
        if ($credIdLen <= 0 || \strlen($authData) < $offset + $credIdLen) {
            return null;
        }
        $credId = substr($authData, $offset, $credIdLen);
        $offset += $credIdLen;

        // 5. The rest is the COSE public key. Decode one item, convert to PEM.
        try {
            $cose = Cbor::decodeItem($authData, $offset);
            if (!\is_array($cose)) {
                return null;
            }
            $pem = CoseKey::es256ToPem($cose);
        } catch (\Throwable) {
            return null;
        }

        return new RegisteredCredential(self::base64UrlEncode($credId), $pem, $signCount);
    }

    private static function base64UrlDecode(string $value): ?string
    {
        if ($value === '') {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
