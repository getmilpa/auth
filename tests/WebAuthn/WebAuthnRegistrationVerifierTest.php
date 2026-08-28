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

use Milpa\Auth\WebAuthn\RegisteredCredential;
use Milpa\Auth\WebAuthn\WebAuthnAssertionVerifier;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationVerifier;
use PHPUnit\Framework\TestCase;

/**
 * Registration extracts a real, verifiable key — proven by ROUND-TRIP: a simulated authenticator
 * registers, and the key the house pulled out then verifies an assertion that same authenticator signs
 * (greenhouse H-PASSKEY-2). The authenticator is simulated with a real P-256 key, so no browser is needed.
 */
final class WebAuthnRegistrationVerifierTest extends TestCase
{
    private const RP_ID = 'milpa.local';

    public function testRegistrationExtractsAKeyThatThenVerifiesAnAssertion(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($key);
        $regChallenge = random_bytes(32);
        $credId = random_bytes(20);

        $clientData = $this->clientData('webauthn.create', $regChallenge);
        $attObj = $this->attestationObject($key, $credId, self::RP_ID, upAt: true, counter: 5);

        $cred = (new WebAuthnRegistrationVerifier())->verify($regChallenge, self::RP_ID, $clientData, $attObj);

        self::assertInstanceOf(RegisteredCredential::class, $cred);
        self::assertSame(rtrim(strtr(base64_encode($credId), '+/', '-_'), '='), $cred->credentialId);
        self::assertSame(5, $cred->signCount);
        self::assertStringContainsString('BEGIN PUBLIC KEY', $cred->publicKeyPem);

        // THE ROUND-TRIP: the extracted key verifies an assertion signed by the same authenticator.
        $authChallenge = random_bytes(32);
        [$aClient, $aData, $sig] = $this->assertion($key, $authChallenge, self::RP_ID);
        $verified = (new WebAuthnAssertionVerifier())->verify(
            $cred->credentialId,
            $cred->publicKeyPem,
            $authChallenge,
            self::RP_ID,
            $aClient,
            $aData,
            $sig,
        );
        self::assertNotNull($verified, 'the registered key verifies its own later assertion');
        self::assertSame($cred->credentialId, $verified->credentialId);
    }

    public function testRegistrationForAnotherChallengeFails(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $clientData = $this->clientData('webauthn.create', random_bytes(32));
        $attObj = $this->attestationObject($key, random_bytes(16), self::RP_ID);

        self::assertNull((new WebAuthnRegistrationVerifier())->verify(random_bytes(32), self::RP_ID, $clientData, $attObj));
    }

    public function testRegistrationForAnotherRelyingPartyFails(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        $attObj = $this->attestationObject($key, random_bytes(16), 'evil.example');

        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, $attObj));
    }

    public function testRegistrationWithoutAttestedCredentialDataFails(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        // upAt:false => the AT flag is not set, so there is no credential to extract.
        $attObj = $this->attestationObject($key, random_bytes(16), self::RP_ID, upAt: false);

        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, $attObj));
    }

    public function testAGetCeremonyIsNotARegistration(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.get', $challenge);
        $attObj = $this->attestationObject($key, random_bytes(16), self::RP_ID);

        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, $attObj));
    }

    public function testAMalformedAttestationObjectFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);

        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, 'not-cbor'));
    }

    public function testAnAttestationThatIsNotAMapFails(): void
    {
        // A create ceremony, but the attestationObject is a bare integer, not a map.
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, hex2bin('0a')));
    }

    public function testAnAttestationWithoutAuthDataFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        $att = self::cborHead(5, 1) . self::cborText('fmt') . self::cborText('none'); // no authData key
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, $att));
    }

    public function testTooShortAuthenticatorDataFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        $att = self::cborAttestation(str_repeat("\x00", 10)); // < 37 bytes
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, $att));
    }

    public function testAttestedDataTruncatedBeforeCredentialIdLengthFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        // AT flag set, but authData stops right after the counter (no aaguid / credIdLen).
        $authData = hash('sha256', self::RP_ID, true) . "\x41" . pack('N', 0);
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, self::cborAttestation($authData)));
    }

    public function testAZeroLengthCredentialIdFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        $authData = hash('sha256', self::RP_ID, true) . "\x41" . pack('N', 0) . str_repeat("\x00", 16) . pack('n', 0);
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, self::cborAttestation($authData)));
    }

    public function testACosePortionThatIsNotAMapFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        $credId = random_bytes(4);
        // A valid header up to the credId, then a CBOR byte string where the COSE map belongs.
        $authData = hash('sha256', self::RP_ID, true) . "\x41" . pack('N', 0)
            . str_repeat("\x00", 16) . pack('n', 4) . $credId . self::cborBytes('nope');
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, self::cborAttestation($authData)));
    }

    public function testANonEs256CredentialKeyFails(): void
    {
        $challenge = random_bytes(32);
        $clientData = $this->clientData('webauthn.create', $challenge);
        $credId = random_bytes(4);
        $notEs256 = self::cborCoseMap([1 => 3, 3 => -257, -1 => 1, -2 => str_repeat('x', 32), -3 => str_repeat('y', 32)]);
        $authData = hash('sha256', self::RP_ID, true) . "\x41" . pack('N', 0)
            . str_repeat("\x00", 16) . pack('n', 4) . $credId . $notEs256;
        self::assertNull((new WebAuthnRegistrationVerifier())->verify($challenge, self::RP_ID, $clientData, self::cborAttestation($authData)));
    }

    public function testAnEmptyChallengeInClientDataFails(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $clientData = (string) json_encode(['type' => 'webauthn.create', 'challenge' => '', 'origin' => 'https://' . self::RP_ID]);
        $att = $this->attestationObject($key, random_bytes(8), self::RP_ID);
        self::assertNull((new WebAuthnRegistrationVerifier())->verify(random_bytes(32), self::RP_ID, $clientData, $att));
    }

    // --- the simulated authenticator ---

    private function clientData(string $type, string $challenge): string
    {
        return (string) json_encode([
            'type' => $type,
            'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='),
            'origin' => 'https://' . self::RP_ID,
        ]);
    }

    /** Build an attestationObject (fmt "none") wrapping authData with the key's attested credential data. */
    private function attestationObject(\OpenSSLAsymmetricKey $key, string $credId, string $rpId, bool $upAt = true, int $counter = 0): string
    {
        $details = openssl_pkey_get_details($key);
        $cose = self::cborCoseMap([
            1 => 2,          // kty EC2
            3 => -7,         // alg ES256
            -1 => 1,         // crv P-256
            -2 => $details['ec']['x'],
            -3 => $details['ec']['y'],
        ]);

        $flags = $upAt ? "\x41" : "\x00"; // UP | AT (0x40) when present
        $authData = hash('sha256', $rpId, true) . $flags . pack('N', $counter);
        if ($upAt) {
            $authData .= str_repeat("\x00", 16)          // aaguid
                . pack('n', \strlen($credId)) . $credId  // credIdLen ‖ credId
                . $cose;                                 // COSE public key
        }

        return self::cborAttestation($authData);
    }

    /** @return array{0: string, 1: string, 2: string} */
    private function assertion(\OpenSSLAsymmetricKey $key, string $challenge, string $rpId): array
    {
        $clientData = $this->clientData('webauthn.get', $challenge);
        $authData = hash('sha256', $rpId, true) . "\x01" . pack('N', 1);
        $signed = $authData . hash('sha256', $clientData, true);
        $sig = '';
        openssl_sign($signed, $sig, $key, OPENSSL_ALGO_SHA256);

        return [$clientData, $authData, $sig];
    }

    // --- a tiny CBOR encoder, only what the attestation needs ---

    /**
     * A COSE_Key map: integer labels, integer values for kty/alg/crv and byte strings for x/y.
     *
     * @param array<int, int|string> $map
     */
    private static function cborCoseMap(array $map): string
    {
        $out = self::cborHead(5, \count($map));
        foreach ($map as $k => $v) {
            $out .= self::cborInt($k);
            $out .= \is_int($v) ? self::cborInt($v) : self::cborBytes($v);
        }

        return $out;
    }

    /** The attestationObject map: text keys, with fmt a text string, attStmt an empty map, authData bytes. */
    private static function cborAttestation(string $authData): string
    {
        return self::cborHead(5, 3)
            . self::cborText('fmt') . self::cborText('none')
            . self::cborText('attStmt') . self::cborHead(5, 0)
            . self::cborText('authData') . self::cborBytes($authData);
    }

    private static function cborInt(int $n): string
    {
        return $n >= 0 ? self::cborHead(0, $n) : self::cborHead(1, -1 - $n);
    }

    private static function cborBytes(string $s): string
    {
        return self::cborHead(2, \strlen($s)) . $s;
    }

    private static function cborText(string $s): string
    {
        return self::cborHead(3, \strlen($s)) . $s;
    }

    private static function cborHead(int $major, int $value): string
    {
        $mt = $major << 5;
        if ($value < 24) {
            return \chr($mt | $value);
        }
        if ($value < 256) {
            return \chr($mt | 24) . \chr($value);
        }
        if ($value < 65536) {
            return \chr($mt | 25) . pack('n', $value);
        }

        return \chr($mt | 26) . pack('N', $value);
    }
}
