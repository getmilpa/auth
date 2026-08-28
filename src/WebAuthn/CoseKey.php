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
 * Turns a COSE_Key (RFC 8152) into a PEM public key the rest of the world can verify against.
 *
 * An authenticator hands its public key inside the attestation as a COSE map, but {@see \openssl_verify()}
 * wants a PEM. This bridges the two for ES256 (EC2 / P-256) — the one algorithm the passkey path speaks
 * for now (greenhouse decisions/0123). It builds the uncompressed EC point (0x04 ‖ x ‖ y) and wraps it in
 * the fixed ASN.1 SubjectPublicKeyInfo for prime256v1. A COSE key of any other type is refused, not guessed.
 */
final class CoseKey
{
    // ASN.1 DER SubjectPublicKeyInfo prefix for an id-ecPublicKey over prime256v1 (P-256), up to the
    // BIT STRING that carries the 65-byte uncompressed point. Fixed for this curve.
    private const P256_SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00";

    /**
     * Convert an ES256 (EC2/P-256) COSE key map into a PEM public key.
     *
     * @param array<int|string, mixed> $cose the decoded COSE_Key map (integer labels)
     *
     * @throws \RuntimeException when the key is not an ES256 P-256 key, or a coordinate is malformed
     */
    public static function es256ToPem(array $cose): string
    {
        $kty = $cose[1] ?? null;   // 1 = kty
        $alg = $cose[3] ?? null;   // 3 = alg
        $crv = $cose[-1] ?? null;  // -1 = crv
        $x = $cose[-2] ?? null;    // -2 = x
        $y = $cose[-3] ?? null;    // -3 = y

        if ($kty !== 2 || $alg !== -7 || $crv !== 1) {
            throw new \RuntimeException('COSE: not an ES256 (EC2/P-256) key');
        }
        if (!\is_string($x) || !\is_string($y) || \strlen($x) !== 32 || \strlen($y) !== 32) {
            throw new \RuntimeException('COSE: P-256 coordinates must be 32 bytes each');
        }

        $der = self::P256_SPKI_PREFIX . "\x04" . $x . $y;
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        return $pem;
    }
}
