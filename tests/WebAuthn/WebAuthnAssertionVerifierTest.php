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

use Milpa\Auth\WebAuthn\VerifiedPasskey;
use Milpa\Auth\WebAuthn\WebAuthnAssertionVerifier;
use PHPUnit\Framework\TestCase;

/**
 * The crypto throat of the passkey path (greenhouse H-PASSKEY-1). The authenticator is SIMULATED here —
 * a real P-256 key signs the exact bytes a browser authenticator would — so the test proves the
 * verification is real without a browser: a genuine assertion verifies, and every tampering fails closed.
 */
final class WebAuthnAssertionVerifierTest extends TestCase
{
    private const RP_ID = 'milpa.local';
    private const CRED_ID = 'cred-abc';

    public function testAGenuineAssertionVerifies(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, upPresent: true, counter: 7);

        $result = (new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        );

        self::assertInstanceOf(VerifiedPasskey::class, $result);
        self::assertSame(self::CRED_ID, $result->credentialId);
        self::assertSame(7, $result->signCount);
        self::assertSame('passkey:' . self::CRED_ID, $result->principal());
    }

    public function testAnAssertionForAnotherChallengeFails(): void
    {
        [$priv, $pub] = $this->keypair();
        [$clientData, $authData, $sig] = $this->assertion($priv, random_bytes(32), self::RP_ID);

        $result = (new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            random_bytes(32),
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        );
        self::assertNull($result);
    }

    public function testTamperedAuthenticatorDataFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID);

        $authData[36] = \chr((\ord($authData[36]) + 1) % 256);

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testAnAssertionForAnotherRelyingPartyFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, 'evil.example');

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testUserNotPresentFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, upPresent: false);

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testAWrongKeyFails(): void
    {
        [$priv] = $this->keypair();
        [, $otherPub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID);

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $otherPub,
            $challenge,
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testANonGetCeremonyFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, type: 'webauthn.create');

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::RP_ID,
            $clientData,
            $authData,
            $sig,
        ));
    }

    // --- the simulated authenticator ---

    /** @return array{0: \OpenSSLAsymmetricKey, 1: string} */
    private function keypair(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);

        return [$key, (string) $details['key']];
    }

    /**
     * @return array{0: string, 1: string, 2: string} clientDataJSON, authenticatorData, signature
     */
    private function assertion(
        \OpenSSLAsymmetricKey $priv,
        string $challenge,
        string $rpId,
        bool $upPresent = true,
        int $counter = 1,
        string $type = 'webauthn.get',
    ): array {
        $clientData = (string) json_encode([
            'type' => $type,
            'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='),
            'origin' => 'https://' . $rpId,
        ]);

        $flags = $upPresent ? "\x01" : "\x00";
        $authData = hash('sha256', $rpId, true) . $flags . pack('N', $counter);

        $signedData = $authData . hash('sha256', $clientData, true);
        $sig = '';
        openssl_sign($signedData, $sig, $priv, OPENSSL_ALGO_SHA256);

        return [$clientData, $authData, $sig];
    }
}
