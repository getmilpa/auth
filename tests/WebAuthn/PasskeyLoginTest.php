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

use Milpa\Auth\ActorType;
use Milpa\Auth\InMemorySessionStore;
use Milpa\Auth\WebAuthn\FileChallengeStore;
use Milpa\Auth\WebAuthn\FilePasskeyCredentialStore;
use Milpa\Auth\WebAuthn\PasskeyAuthenticator;
use Milpa\Auth\WebAuthn\PasskeyLogin;
use Milpa\Auth\WebAuthn\RegisteredCredential;
use Milpa\Auth\SessionRecord;
use PHPUnit\Framework\TestCase;

/**
 * A passkey login mints a session for a RECOGNIZED credential, and nothing otherwise — possession is not
 * identity, exactly as on the gpg path (greenhouse H-PASSKEY-4). The authenticator is simulated with a
 * real P-256 key so the whole HTTP-shaped flow runs without a browser.
 */
final class PasskeyLoginTest extends TestCase
{
    private const RP_ID = 'milpa.local';
    private const CRED = 'cred-1';

    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    public function testARecognizedPasskeyMintsASession(): void
    {
        $sessions = new InMemorySessionStore();
        [$login, $auth, $key] = $this->login($sessions, scopesFor: static fn (string $c): array => ['agent:read', 'agent:answer']);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge);

        $session = $login->login(self::RP_ID, self::CRED, $client, $data, $sig);

        self::assertInstanceOf(SessionRecord::class, $session);
        self::assertSame('passkey:' . self::CRED, $session->actorId);
        self::assertSame(ActorType::User, $session->actorType);
        self::assertSame(['agent:read', 'agent:answer'], $session->scopes);
        // The session is retrievable from the store — the login persisted it.
        self::assertNotNull($sessions->read($session->id));
    }

    public function testAnUnrecognizedPasskeyGetsNoSession(): void
    {
        $sessions = new InMemorySessionStore();
        // Verifies cryptographically, but the house recognizes no scopes for it: possession alone.
        [$login, $auth, $key] = $this->login($sessions, scopesFor: static fn (string $c): ?array => null);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge);

        self::assertNull($login->login(self::RP_ID, self::CRED, $client, $data, $sig));
    }

    public function testAReplayedAssertionMintsNoSession(): void
    {
        $sessions = new InMemorySessionStore();
        [$login, $auth, $key] = $this->login($sessions, scopesFor: static fn (string $c): array => ['*']);
        $challenge = $auth->challenge();
        [$client, $data, $sig] = $this->assertion($key, $challenge);

        self::assertNotNull($login->login(self::RP_ID, self::CRED, $client, $data, $sig), 'first login works');
        self::assertNull($login->login(self::RP_ID, self::CRED, $client, $data, $sig), 'the challenge is spent — no second session');
    }

    // --- helpers ---

    /**
     * @param callable(string): (list<string>|null) $scopesFor
     *
     * @return array{0: PasskeyLogin, 1: PasskeyAuthenticator, 2: \OpenSSLAsymmetricKey}
     */
    private function login(InMemorySessionStore $sessions, callable $scopesFor): array
    {
        $dir = sys_get_temp_dir() . '/milpa-login-' . bin2hex(random_bytes(4));
        $this->files[] = $dir . '-ch.json';
        $this->files[] = $dir . '-cr.json';

        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $pem = (string) openssl_pkey_get_details($key)['key'];
        $credentials = new FilePasskeyCredentialStore($dir . '-cr.json');
        $credentials->register(new RegisteredCredential(self::CRED, $pem, 0));

        $auth = new PasskeyAuthenticator(new FileChallengeStore($dir . '-ch.json'), $credentials);
        $login = new PasskeyLogin($auth, $sessions, $scopesFor);

        return [$login, $auth, $key];
    }

    /** @return array{0: string, 1: string, 2: string} */
    private function assertion(\OpenSSLAsymmetricKey $key, string $challenge): array
    {
        $client = (string) json_encode([
            'type' => 'webauthn.get',
            'challenge' => rtrim(strtr(base64_encode($challenge), '+/', '-_'), '='),
            'origin' => 'https://' . self::RP_ID,
        ]);
        $data = hash('sha256', self::RP_ID, true) . "\x01" . pack('N', 9);
        $sig = '';
        openssl_sign($data . hash('sha256', $client, true), $sig, $key, OPENSSL_ALGO_SHA256);

        return [$client, $data, $sig];
    }
}
