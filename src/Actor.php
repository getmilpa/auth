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
 * A verified identity: who is acting ({@see self::$id}, {@see self::$type}), what they are allowed to
 * do ({@see self::$scopes}), and whatever else the verifier proved about them ({@see self::$claims}).
 * It is produced by verifying a {@see Credential} — an `Actor` only ever exists because some
 * credential was checked — and it is the unit the policy layer authorises against. Immutable by
 * construction.
 */
final readonly class Actor
{
    /**
     * @param string              $id     the identity's opaque id, unique within its {@see self::$type}
     * @param ActorType           $type   whether this is a user, agent, or service
     * @param list<string>        $scopes the exact permission strings this identity holds; the only
     *                                    wildcard is the explicit `'*'`, which grants every scope
     * @param array<string,mixed> $claims everything else the verifier proved (email, name, tenant, …)
     */
    public function __construct(
        public string $id,
        public ActorType $type,
        public array $scopes = [],
        public array $claims = [],
    ) {
    }

    /**
     * Whether this actor holds `$scope`. Fail-closed: an exact string match, or the presence of the
     * explicit wildcard `'*'` in {@see self::$scopes}. Nothing else grants — no prefix, suffix, or
     * glob magic. The `'*'` is the one documented escape hatch (a superuser, a trusted stdio
     * process), never an implicit one.
     */
    public function hasScope(string $scope): bool
    {
        return in_array('*', $this->scopes, true)
            || in_array($scope, $this->scopes, true);
    }

    /**
     * Whether this actor holds at least one of `$scopes`. Fail-closed: an empty list is never
     * satisfied, and each entry is checked with the exact-match rules of {@see self::hasScope()}.
     *
     * @param list<string> $scopes
     */
    public function hasAnyScope(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($this->hasScope($scope)) {
                return true;
            }
        }

        return false;
    }
}
