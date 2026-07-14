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

/**
 * The in-memory / config {@see PermissionCatalog} — the `InMemorySessionStore` analog: a real, usable
 * catalog with no database. Build it from typed {@see Permission}/{@see Role} objects, or from a plain
 * config array via {@see self::fromArray()}.
 */
final class ArrayPermissionCatalog implements PermissionCatalog
{
    /** @var list<Permission> */
    private array $permissions;
    /** @var array<string,Role> */
    private array $roles;

    /**
     * @param array<Permission> $permissions may arrive gap-keyed (e.g. from array_filter); normalized to a list
     * @param list<Role>        $roles
     */
    public function __construct(array $permissions, array $roles)
    {
        $this->permissions = array_values($permissions);
        $map = [];
        foreach ($roles as $role) {
            $map[$role->id] = $role;
        }
        $this->roles = $map;
    }

    /**
     * Builds a catalog from a config array of permission-key strings (parsed via {@see Permission::parse}).
     *
     * @param array{permissions?: list<string>, roles?: array<string, array{label?: string, permissions: list<string>}>} $config
     */
    public static function fromArray(array $config): self
    {
        $permissions = array_map(Permission::parse(...), $config['permissions'] ?? []);
        $roles = [];
        foreach ($config['roles'] ?? [] as $id => $role) {
            $roles[] = new Role((string) $id, $role['label'] ?? (string) $id, array_map(Permission::parse(...), $role['permissions']));
        }

        return new self($permissions, $roles);
    }

    public function permissions(): array
    {
        return $this->permissions;
    }

    /**
     * All roles declared in this catalog.
     */
    public function roles(): array
    {
        return array_values($this->roles);
    }

    /**
     * The role with this id, or null when unknown (fail-closed).
     */
    public function role(string $id): ?Role
    {
        return $this->roles[$id] ?? null;
    }
}
