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

namespace Milpa\Auth;

use Milpa\Auth\Contracts\SessionStore;

/**
 * Array-backed {@see SessionStore}: the same contract kept entirely in process memory, for tests and
 * zero-file consumers. Nothing is written to disk and nothing survives past the instance's lifetime.
 *
 * Expiry is evaluated against an injectable clock rather than the ambient wall clock, so a test can
 * pin "now" and prove the fail-closed read: {@see self::read()} returns `null` for a record that is
 * expired or revoked as of the clock, exactly as the contract demands.
 */
final class InMemorySessionStore implements SessionStore
{
    /** @var array<string, SessionRecord> */
    private array $sessions = [];

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /**
     * @param (callable(): \DateTimeImmutable)|null $clock the clock expiry is evaluated against;
     *                                                     defaults to the wall clock. Inject it to
     *                                                     pin "now" in a test.
     */
    public function __construct(?callable $clock = null)
    {
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
    }

    /**
     * The valid session stored under `$sessionId`, or `null` when none is stored — or when the
     * stored one is expired or revoked as of the injected clock (fail-closed).
     */
    public function read(string $sessionId): ?SessionRecord
    {
        $session = $this->sessions[$sessionId] ?? null;
        if ($session === null) {
            return null;
        }

        // Fail-closed: an expired or revoked session reads as absent, never as a live actor.
        return $session->isValid(($this->clock)()) ? $session : null;
    }

    /**
     * Persists `$session` in memory, keyed by its {@see SessionRecord::$id}.
     */
    public function write(SessionRecord $session): void
    {
        $this->sessions[$session->id] = $session;
    }

    /**
     * Removes the session stored under `$sessionId`. A no-op when none is stored.
     */
    public function destroy(string $sessionId): void
    {
        unset($this->sessions[$sessionId]);
    }
}
