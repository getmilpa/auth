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
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\UserVerificationRequirement;
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
            self::rp(),
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
            self::rp(),
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
            self::rp(),
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testAnAssertionForAnotherRelyingPartyFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        // Our origin, so the refusal can only come from the rpId hash: the authenticator scoped it to another RP.
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, 'evil.example', origin: 'https://' . self::RP_ID);

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::rp(),
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
            self::rp(),
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
            self::rp(),
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
            self::rp(),
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testMalformedClientDataFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID);

        // clientDataJSON that is not even JSON cannot bind a ceremony.
        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::rp(),
            'not-json',
            $authData,
            $sig,
        ));
    }

    public function testTruncatedAuthenticatorDataFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, , $sig] = $this->assertion($priv, $challenge, self::RP_ID);

        // authenticatorData shorter than rpIdHash(32) + flags(1) + counter(4) cannot be read.
        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::rp(),
            $clientData,
            'too-short',
            $sig,
        ));
    }

    public function testAnEmptyChallengeInClientDataFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID);

        // A clientDataJSON carrying an empty challenge string decodes to nothing — not the issued challenge.
        $clientData = (string) json_encode(['type' => 'webauthn.get', 'challenge' => '', 'origin' => 'https://' . self::RP_ID]);
        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::rp(),
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testAnAssertionFromAForeignOriginFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        // A phishing page relaying the ceremony: right rpId hash, right challenge, a valid signature —
        // but the browser wrote the page it actually ran on into clientDataJSON.
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, origin: 'https://evil.example');

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::rp(),
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testAnAssertionWithoutUserVerificationFailsByDefault(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        // UP without UV: someone touched the key, nobody proved to be its owner (no PIN, no biometric).
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, uvVerified: false);

        self::assertNull((new WebAuthnAssertionVerifier())->verify(
            self::CRED_ID,
            $pub,
            $challenge,
            self::rp(),
            $clientData,
            $authData,
            $sig,
        ));
    }

    public function testAnAssertionWithoutAnOriginFails(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [, $authData] = $this->assertion($priv, $challenge, self::RP_ID);
        $clientData = (string) json_encode([
            'type' => 'webauthn.get',
            'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='),
        ]);
        $sig = '';
        openssl_sign($authData . hash('sha256', $clientData, true), $sig, $priv, OPENSSL_ALGO_SHA256);

        self::assertNull((new WebAuthnAssertionVerifier())->verify(self::CRED_ID, $pub, $challenge, self::rp(), $clientData, $authData, $sig));
    }

    public function testAnyAllowedOriginOfTheRelyingPartyVerifies(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, origin: 'https://app.' . self::RP_ID);
        $rp = new RelyingParty(self::RP_ID, 'Milpa', ['https://' . self::RP_ID, 'https://app.' . self::RP_ID]);

        self::assertNotNull((new WebAuthnAssertionVerifier())->verify(self::CRED_ID, $pub, $challenge, $rp, $clientData, $authData, $sig));
    }

    public function testRelaxingUserVerificationIsExplicitAndAcceptsPresenceAlone(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, uvVerified: false);

        $relaxed = new WebAuthnAssertionVerifier(UserVerificationRequirement::Preferred);

        self::assertNotNull($relaxed->verify(self::CRED_ID, $pub, $challenge, self::rp(), $clientData, $authData, $sig));
    }

    public function testRelaxingUserVerificationStillRequiresPresence(): void
    {
        [$priv, $pub] = $this->keypair();
        $challenge = random_bytes(32);
        [$clientData, $authData, $sig] = $this->assertion($priv, $challenge, self::RP_ID, upPresent: false, uvVerified: false);

        $relaxed = new WebAuthnAssertionVerifier(UserVerificationRequirement::Discouraged);

        self::assertNull($relaxed->verify(self::CRED_ID, $pub, $challenge, self::rp(), $clientData, $authData, $sig));
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
        ?string $origin = null,
        bool $uvVerified = true,
    ): array {
        $clientData = (string) json_encode([
            'type' => $type,
            'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='),
            'origin' => $origin ?? 'https://' . $rpId,
        ]);

        $flags = \chr(($upPresent ? 0x01 : 0x00) | ($uvVerified ? 0x04 : 0x00));
        $authData = hash('sha256', $rpId, true) . $flags . pack('N', $counter);

        $signedData = $authData . hash('sha256', $clientData, true);
        $sig = '';
        openssl_sign($signedData, $sig, $priv, OPENSSL_ALGO_SHA256);

        return [$clientData, $authData, $sig];
    }

    /** The relying party this suite's simulated authenticator answers for. */
    private static function rp(): RelyingParty
    {
        return new RelyingParty(self::RP_ID, 'Milpa', ['https://' . self::RP_ID]);
    }
}
