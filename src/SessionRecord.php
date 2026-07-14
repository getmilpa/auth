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

/**
 * A persisted session: the plain, storage-agnostic shape a {@see Contracts\SessionStore} reads and
 * writes. It records who the session belongs to ({@see self::$actorId}, {@see self::$actorType}) and
 * what it grants ({@see self::$scopes}, {@see self::$claims}), plus the lifetime facts that decide
 * whether it may still be trusted — its {@see self::$expiresAt} and its {@see self::$revoked} flag.
 * It carries no storage concern of its own; {@see self::toActor()} projects it back into the live
 * {@see Actor} the policy layer authorises against. Immutable by construction.
 */
final readonly class SessionRecord
{
    /**
     * @param string              $id        the opaque session id (the value behind the cookie/token)
     * @param string              $actorId   the {@see Actor::$id} this session belongs to
     * @param ActorType           $actorType the {@see Actor::$type} this session belongs to
     * @param \DateTimeImmutable  $createdAt when the session was issued
     * @param \DateTimeImmutable  $expiresAt when the session stops being valid
     * @param list<string>        $scopes    the permissions the session grants its actor
     * @param array<string,mixed> $claims    everything else to rehydrate onto the {@see Actor}
     * @param bool                $revoked   whether the session was explicitly revoked before expiry
     */
    public function __construct(
        public string $id,
        public string $actorId,
        public ActorType $actorType,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $expiresAt,
        public array $scopes = [],
        public array $claims = [],
        public bool $revoked = false,
    ) {
    }

    /**
     * Whether this session has expired as of `$now` — true once `$now` reaches or passes
     * {@see self::$expiresAt}. The clock is the caller's to supply, never read ambiently, so expiry
     * is deterministic and testable.
     */
    public function isExpired(\DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * Whether this session may still be trusted as of `$now`: neither expired
     * ({@see self::isExpired()}) nor {@see self::$revoked}. Fail-closed — anything that is not
     * provably still valid is invalid.
     */
    public function isValid(\DateTimeImmutable $now): bool
    {
        return !$this->revoked && !$this->isExpired($now);
    }

    /**
     * Projects this record into the live {@see Actor} the policy layer authorises against, carrying
     * the session's actor id, type, scopes, and claims. Validity is checked separately via
     * {@see self::isValid()} — projecting a record does not, on its own, assert it is still good.
     */
    public function toActor(): Actor
    {
        return new Actor($this->actorId, $this->actorType, $this->scopes, $this->claims);
    }
}
