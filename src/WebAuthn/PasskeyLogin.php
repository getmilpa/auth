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

use Milpa\Auth\ActorType;
use Milpa\Auth\Contracts\SessionStore;
use Milpa\Auth\SessionRecord;

/**
 * Turns a passkey authentication into a session — the WEB counterpart of what a signed `session:own` is on
 * the CLI (greenhouse H-PASSKEY-4). This is where the passkey path MEANS something: a ceremony that only
 * verifies is a lab check; one that mints a session is a login.
 *
 * It holds the same discipline the gpg path does (decisions/0117): possession is not identity. A verified
 * passkey proves the holder controls a registered authenticator; whether the house RECOGNIZES that
 * credential — and with what scopes — is a separate question a resolver answers. An unrecognized passkey
 * authenticates cryptographically and still gets no session, exactly as an unenrolled gpg key gets no
 * principal. The resolver is where the passkey path meets the SAME recognition model as the key path.
 */
final class PasskeyLogin
{
    /** @var callable(string): (list<string>|null) */
    private $scopesFor;

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /**
     * @param callable(string): (list<string>|null) $scopesFor the scopes the house recognizes for a
     *                                                         credential id, or null for one it does not
     * @param (callable(): \DateTimeImmutable)|null $clock     the current time, injectable for tests
     */
    public function __construct(
        private readonly PasskeyAuthenticator $authenticator,
        private readonly SessionStore $sessions,
        callable $scopesFor,
        private readonly int $ttlSeconds = 3600,
        ?callable $clock = null,
    ) {
        $this->scopesFor = $scopesFor;
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
    }

    /**
     * Authenticate a passkey and, if the house recognizes it, mint a session — or return null.
     *
     * @param string $credentialId      the credential the client says answered
     * @param string $clientDataJson    the browser's clientDataJSON bytes
     * @param string $authenticatorData the authenticatorData bytes
     * @param string $signature         the assertion signature
     */
    public function login(
        string $rpId,
        string $credentialId,
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
    ): ?SessionRecord {
        $passkey = $this->authenticator->authenticate($rpId, $credentialId, $clientDataJson, $authenticatorData, $signature);
        if ($passkey === null) {
            return null;
        }

        // POSSESSION IS NOT IDENTITY (decisions/0117): the assertion proved control of the authenticator;
        // only the house's recognition turns that into a session. An unrecognized passkey gets nothing.
        $scopes = ($this->scopesFor)($passkey->credentialId);
        if ($scopes === null) {
            return null;
        }

        $now = ($this->clock)();
        $session = new SessionRecord(
            id: bin2hex(random_bytes(32)),
            actorId: $passkey->principal(),
            actorType: ActorType::User,
            createdAt: $now,
            expiresAt: $now->add(new \DateInterval('PT' . $this->ttlSeconds . 'S')),
            scopes: $scopes,
        );
        $this->sessions->write($session);

        return $session;
    }
}
