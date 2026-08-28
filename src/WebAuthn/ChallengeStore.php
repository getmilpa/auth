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
 * Issues and consumes the one-time challenges a WebAuthn ceremony binds to.
 *
 * A challenge is what stops a captured assertion from being replayed: the server issues a random one,
 * the authenticator signs over it, and the server accepts it EXACTLY ONCE, before it expires. Without
 * this single-use expiring state the published verifiers are only as safe as the caller's memory — so
 * the ceremony's safety lives here (greenhouse H-PASSKEY-3).
 */
interface ChallengeStore
{
    /** Mint a fresh random challenge, remember it until it expires, and return its raw bytes. */
    public function issue(): string;

    /** Accept a challenge EXACTLY ONCE: true if it was issued and unexpired, and never true again for it. */
    public function consume(string $challenge): bool;
}
