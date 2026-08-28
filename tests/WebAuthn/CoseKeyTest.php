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

namespace Milpa\Auth\Tests\WebAuthn;

use Milpa\Auth\WebAuthn\CoseKey;
use Milpa\Auth\WebAuthn\WebAuthnAssertionVerifier;
use PHPUnit\Framework\TestCase;

/** COSE ES256 keys become PEMs the verifier accepts; anything else is refused, not guessed. */
final class CoseKeyTest extends TestCase
{
    public function testAnEs256KeyBecomesAUsablePem(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $d = openssl_pkey_get_details($key);
        $pem = CoseKey::es256ToPem([1 => 2, 3 => -7, -1 => 1, -2 => $d['ec']['x'], -3 => $d['ec']['y']]);

        // The PEM must actually verify a signature by the matching private key — proof it is the right key.
        $challenge = random_bytes(32);
        $clientData = (string) json_encode(['type' => 'webauthn.get', 'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='), 'origin' => 'https://milpa.local']);
        $authData = hash('sha256', 'milpa.local', true) . "\x01" . pack('N', 1);
        $sig = '';
        openssl_sign($authData . hash('sha256', $clientData, true), $sig, $key, OPENSSL_ALGO_SHA256);

        self::assertNotNull((new WebAuthnAssertionVerifier())->verify('c', $pem, $challenge, 'milpa.local', $clientData, $authData, $sig));
    }

    public function testANonEs256KeyIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        CoseKey::es256ToPem([1 => 3, 3 => -257, -1 => 1, -2 => str_repeat('x', 32), -3 => str_repeat('y', 32)]); // RSA-ish
    }

    public function testMalformedCoordinatesAreRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        CoseKey::es256ToPem([1 => 2, 3 => -7, -1 => 1, -2 => 'short', -3 => str_repeat('y', 32)]);
    }
}
