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
 * The resolved authorization state for one request: the flat list of {@see GrantedPermission}s the
 * resolver produced, plus the `'*'` superuser grant if the actor held it. Answers "can this actor do
 * X?" ({@see self::can()}) and "why?" ({@see self::sourcesOf()}). It may hold the same permission from
 * more than one source (a role AND a flat scope) — that is what makes authorization explainable.
 * Immutable by construction.
 */
final readonly class PermissionSet
{
    /**
     * @param list<GrantedPermission> $granted   every permission granted, with its provenance
     * @param bool                    $grantsAll true when the actor holds the `'*'` scope (grants all)
     * @param ?PermissionSource       $allSource provenance of the `'*'` grant, when $grantsAll
     */
    public function __construct(
        private array $granted,
        private bool $grantsAll = false,
        private ?PermissionSource $allSource = null,
    ) {
        if ($this->grantsAll && $this->allSource === null) {
            throw new \InvalidArgumentException(
                'A PermissionSet that grantsAll must carry an allSource — a grant with no explainable '
                . 'provenance is not permitted (provenance is part of the authorization contract).'
            );
        }
    }

    /** Whether the actor can perform $action on $resource (optionally scoped to $namespace). See {@see self::allows()}. */
    public function can(string $resource, string $action, ?string $namespace = null): bool
    {
        return $this->allows(Permission::of($resource, $action, $namespace));
    }

    /** Whether $permission is granted — true if `'*'` was granted, else an exact key match. No glob. */
    public function allows(Permission $permission): bool
    {
        if ($this->grantsAll) {
            return true;
        }
        $key = $permission->key();
        foreach ($this->granted as $g) {
            if ($g->permission->key() === $key) {
                return true;
            }
        }

        return false;
    }

    /** @return list<GrantedPermission> */
    public function all(): array
    {
        return $this->granted;
    }

    /**
     * Every source that granted $permission (each path, not deduped), preceded by the `'*'` source when
     * this set grants all. Empty when $permission is not granted.
     *
     * @return list<PermissionSource>
     */
    public function sourcesOf(Permission $permission): array
    {
        $sources = [];
        if ($this->grantsAll && $this->allSource !== null) {
            $sources[] = $this->allSource;
        }
        $key = $permission->key();
        foreach ($this->granted as $g) {
            if ($g->permission->key() === $key) {
                $sources[] = $g->source;
            }
        }

        return $sources;
    }

    public function grantsAll(): bool
    {
        return $this->grantsAll;
    }
}
