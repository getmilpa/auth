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

namespace Milpa\Auth\Contracts;

use Milpa\Auth\Permission;
use Milpa\Auth\Role;

/**
 * The dictionary of what CAN exist: the permissions an application declares and the roles that bundle
 * them. It is the Admin-readiness seam for browsing the matrix, and the source the resolver expands a
 * role id against. Ships with an in-memory default ({@see \Milpa\Auth\ArrayPermissionCatalog}); a host
 * may back it with anything, but the leaf never assumes a database.
 */
interface PermissionCatalog
{
    /**
     * The full permission dictionary.
     *
     * @return list<Permission> the full permission dictionary
     */
    public function permissions(): array;

    /**
     * All roles declared in this catalog.
     *
     * @return list<Role>
     */
    public function roles(): array;

    /**
     * The role with this id, or null when unknown (an unknown role grants nothing — fail-closed).
     */
    public function role(string $id): ?Role;
}
