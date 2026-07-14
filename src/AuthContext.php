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
 * The trusted answer to "who is making this request, and may we trust it?" — an {@see AuthState}
 * and, when authenticated, the {@see Actor} it resolved to. This is the *product* the whole package
 * exists to make: a credential verifier turns a raw {@see Credential} into one of these, and the
 * policy layer authorises against it. It carries the scope helpers so a caller can ask "may this
 * request do X?" without first unwrapping (and null-checking) the actor. Immutable by construction.
 */
final readonly class AuthContext
{
    /**
     * @param ?Actor              $actor    the verified identity, or `null` when there is none
     *                                      (anonymous or invalid)
     * @param AuthState           $state    how the request authenticated
     * @param array<string,mixed> $metadata out-of-band detail — e.g. the rejection `reason` on an
     *                                      invalid context, the source ip, the request id
     */
    public function __construct(
        public ?Actor $actor,
        public AuthState $state,
        public array $metadata = [],
    ) {
    }

    /**
     * A context for a request that presented no credential: no actor, state {@see AuthState::Anonymous}.
     */
    public static function anonymous(): self
    {
        return new self(null, AuthState::Anonymous);
    }

    /**
     * A context for a request whose credential verified into `$actor`: state
     * {@see AuthState::Authenticated}.
     */
    public static function authenticated(Actor $actor): self
    {
        return new self($actor, AuthState::Authenticated);
    }

    /**
     * A context for a request that presented a credential which was rejected: no actor, state
     * {@see AuthState::Invalid}, and `$reason` recorded under the `reason` metadata key. Distinct
     * from {@see self::anonymous()} on purpose — a bad credential is not the same as no credential.
     */
    public static function invalid(?string $reason = null): self
    {
        return new self(null, AuthState::Invalid, ['reason' => $reason]);
    }

    /**
     * Whether this request authenticated to an actor — true only in the {@see AuthState::Authenticated}
     * state.
     */
    public function isAuthenticated(): bool
    {
        return $this->state === AuthState::Authenticated;
    }

    /**
     * Whether the request's actor holds `$scope`. Fail-closed: with no actor (anonymous or invalid)
     * this is always false, and otherwise it delegates to {@see Actor::hasScope()}.
     */
    public function hasScope(string $scope): bool
    {
        return $this->actor?->hasScope($scope) ?? false;
    }

    /**
     * Whether the request's actor holds at least one of `$scopes`. Fail-closed: with no actor this is
     * always false; otherwise it delegates to {@see Actor::hasAnyScope()}.
     *
     * @param list<string> $scopes
     */
    public function hasAnyScope(array $scopes): bool
    {
        return $this->actor?->hasAnyScope($scopes) ?? false;
    }
}
