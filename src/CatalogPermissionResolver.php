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

use Milpa\Auth\Contracts\PermissionCatalog;
use Milpa\Auth\Contracts\PermissionResolver;

/**
 * The reference {@see PermissionResolver}: lifts each flat scope into a {@see GrantedPermission} (scope
 * provenance), expands each role via the {@see PermissionCatalog} (role provenance), and preserves the
 * `'*'` grant. Fail-closed: an unknown role grants nothing, and a scope that is not a valid permission
 * key is skipped from the set (it stays checkable via {@see Actor::hasScope()}). Intentionally
 * tenant-blind — it threads {@see PermissionContext} through without interpreting it, so a tenant-aware
 * host or a {@see Contracts\Policy} can decide without a breaking change.
 */
final class CatalogPermissionResolver implements PermissionResolver
{
    public function __construct(private readonly PermissionCatalog $catalog)
    {
    }

    /**
     * Lifts $actor's flat scopes and expands its roles via the catalog into a {@see PermissionSet}.
     * $context is threaded but intentionally unused — this default resolver is tenant-blind.
     */
    public function resolve(Actor $actor, PermissionContext $context): PermissionSet
    {
        $granted = [];
        $grantsAll = false;
        $allSource = null;

        foreach ($actor->scopes as $scope) {
            if ($scope === '*') {
                $grantsAll = true;
                $allSource = new PermissionSource(PermissionSourceType::Scope, '*');
                continue;
            }
            try {
                $permission = Permission::parse($scope);
            } catch (\InvalidArgumentException) {
                continue; // a scope that is not a permission key is not liftable — stays flat-only
            }
            $granted[] = new GrantedPermission($permission, new PermissionSource(PermissionSourceType::Scope, $scope));
        }

        foreach ($actor->roles as $roleId) {
            $role = $this->catalog->role($roleId);
            if ($role === null) {
                continue; // unknown role grants nothing (fail-closed)
            }
            foreach ($role->permissions as $permission) {
                $granted[] = new GrantedPermission($permission, new PermissionSource(PermissionSourceType::Role, $roleId));
            }
        }

        return new PermissionSet($granted, $grantsAll, $allSource);
    }
}
