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
 * A named bundle of {@see Permission}s. Roles are what a {@see PermissionCatalog} declares and what an
 * {@see Actor} holds by id; the resolver expands them into grants. Immutable by construction.
 */
final readonly class Role
{
    /**
     * @param list<Permission>    $permissions the permissions this role grants
     * @param array<string,mixed> $metadata    non-authoritative extra detail
     */
    public function __construct(
        public string $id,
        public string $label,
        public array $permissions,
        public array $metadata = [],
    ) {
    }
}
