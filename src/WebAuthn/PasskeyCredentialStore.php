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
 * Remembers the passkeys a house has registered, so an assertion can be checked against the right key.
 *
 * Registration writes a credential here; authentication reads it back by id to find the public key, and
 * advances its sign counter afterward. The counter is the clone tripwire (§6.1.1 of WebAuthn): it must
 * only ever climb, so the store must persist the last value it saw.
 */
interface PasskeyCredentialStore
{
    /** Persist a newly registered credential, keyed by its id. */
    public function register(RegisteredCredential $credential): void;

    /** The credential with this id, or null when the house never registered it. */
    public function find(string $credentialId): ?RegisteredCredential;

    /** Advance a credential's stored sign counter after a successful assertion. */
    public function updateSignCount(string $credentialId, int $signCount): void;
}
