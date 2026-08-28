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

use Milpa\Auth\WebAuthn\FileChallengeStore;
use Milpa\Auth\WebAuthn\FilePasskeyCredentialStore;
use Milpa\Auth\WebAuthn\PasskeyAuthenticator;
use Milpa\Auth\WebAuthn\RegisteredCredential;
use Milpa\Auth\WebAuthn\VerifiedPasskey;
use PHPUnit\Framework\TestCase;

/**
 * The authentication ceremony composed safe (greenhouse H-PASSKEY-3): a fresh challenge is spent exactly
 * once, and only a registered credential whose counter climbs authenticates. The authenticator is
 * simulated with a real P-256 key so the whole flow runs without a browser.
 */
final class PasskeyAuthenticatorTest extends TestCase
{
    private const RP_ID = 'milpa.local';
    private const CRED = 'cred-1';

    /** @var list<string> */
    private array $files = [];

    private int $now = 1000;

    protected function tearDown(): void
    {
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    public function testAFreshCeremonyAuthenticates(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge, self::RP_ID, counter: 3);

        $result = $auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig);

        self::assertInstanceOf(VerifiedPasskey::class, $result);
        self::assertSame(self::CRED, $result->credentialId);
        self::assertSame(3, $result->signCount);
    }

    public function testAReplayIsRefusedEvenWithAValidSignature(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge, self::RP_ID, counter: 3);

        self::assertNotNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig), 'first use works');
        // Same assertion again: the challenge was spent, so the replay is refused though the signature is fine.
        self::assertNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig), 'the challenge is single-use');
    }

    public function testAnExpiredChallengeIsRefused(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0, ttl: 60);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge, self::RP_ID, counter: 3);

        $this->now += 120; // past the ttl

        self::assertNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig));
    }

    public function testANeverIssuedChallengeIsRefused(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0);
        // Sign over a challenge the store never issued.
        [$client, $data, $sig] = $this->assertion($key, random_bytes(32), self::RP_ID, counter: 3);

        self::assertNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig));
    }

    public function testAnUnknownCredentialIsRefused(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge, self::RP_ID, counter: 3);

        self::assertNull($auth->authenticate(self::RP_ID, 'someone-else', $client, $data, $sig));
    }

    public function testACounterRegressionSurfacesACloneAndIsRefused(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 10);
        $challenge = $auth->challenge();
        // Counter 5 <= stored 10 means two authenticators share this credential.
        [$client, $data, $sig] = $this->assertion($key, $challenge, self::RP_ID, counter: 5);

        self::assertNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig));
    }

    public function testABadSignatureIsRefused(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge, self::RP_ID, counter: 3);
        $sig[10] = \chr((\ord($sig[10]) + 1) % 256); // corrupt the signature after signing

        self::assertNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig));
    }

    public function testAnEmptyChallengeInClientDataIsRefused(): void
    {
        [$auth, $key] = $this->authenticator(storedCount: 0);
        $auth->challenge();
        $client = (string) json_encode(['type' => 'webauthn.get', 'challenge' => '', 'origin' => 'https://' . self::RP_ID]);
        $data = hash('sha256', self::RP_ID, true) . "\x01" . pack('N', 3);
        $sig = '';
        openssl_sign($data . hash('sha256', $client, true), $sig, $key, OPENSSL_ALGO_SHA256);

        self::assertNull($auth->authenticate(self::RP_ID, self::CRED, $client, $data, $sig));
    }

    // --- helpers ---

    /** @return array{0: PasskeyAuthenticator, 1: \OpenSSLAsymmetricKey} */
    private function authenticator(int $storedCount, int $ttl = 300): array
    {
        $dir = sys_get_temp_dir() . '/milpa-pk-' . bin2hex(random_bytes(4));
        $this->files[] = $dir . '-ch.json';
        $this->files[] = $dir . '-cr.json';

        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $pem = (string) openssl_pkey_get_details($key)['key'];

        $credentials = new FilePasskeyCredentialStore($dir . '-cr.json');
        $credentials->register(new RegisteredCredential(self::CRED, $pem, $storedCount));

        $challenges = new FileChallengeStore($dir . '-ch.json', $ttl, fn (): int => $this->now);

        return [new PasskeyAuthenticator($challenges, $credentials), $key];
    }

    /** @return array{0: string, 1: string, 2: string} */
    private function assertion(\OpenSSLAsymmetricKey $key, string $challenge, string $rpId, int $counter): array
    {
        $client = (string) json_encode([
            'type' => 'webauthn.get',
            'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='),
            'origin' => 'https://' . $rpId,
        ]);
        $data = hash('sha256', $rpId, true) . "\x01" . pack('N', $counter);
        $sig = '';
        openssl_sign($data . hash('sha256', $client, true), $sig, $key, OPENSSL_ALGO_SHA256);

        return [$client, $data, $sig];
    }
}
