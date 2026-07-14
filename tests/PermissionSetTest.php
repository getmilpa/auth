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

namespace Milpa\Auth\Tests;

use Milpa\Auth\GrantedPermission;
use Milpa\Auth\Permission;
use Milpa\Auth\PermissionSet;
use Milpa\Auth\PermissionSource;
use Milpa\Auth\PermissionSourceType;
use PHPUnit\Framework\TestCase;

final class PermissionSetTest extends TestCase
{
    private function granted(string $key, PermissionSourceType $type, string $id): GrantedPermission
    {
        return new GrantedPermission(Permission::parse($key), new PermissionSource($type, $id));
    }

    public function testCanMatchesByKey(): void
    {
        $set = new PermissionSet([$this->granted('crm.contact:update', PermissionSourceType::Role, 'editor')]);
        self::assertTrue($set->can('contact', 'update', 'crm'));
        self::assertFalse($set->can('contact', 'delete', 'crm'));
        self::assertFalse($set->can('contact', 'update'));   // namespace mismatch is a miss
    }

    public function testGrantsAllShortCircuits(): void
    {
        $set = new PermissionSet([], grantsAll: true, allSource: new PermissionSource(PermissionSourceType::Scope, '*'));
        self::assertTrue($set->can('anything', 'at-all', 'any'));
        self::assertTrue($set->grantsAll());
    }

    public function testSourcesOfReturnsEveryPath(): void
    {
        $set = new PermissionSet([
            $this->granted('crm.contact:update', PermissionSourceType::Role, 'editor'),
            $this->granted('crm.contact:update', PermissionSourceType::Scope, 'crm.contact:update'),
        ]);
        $sources = $set->sourcesOf(Permission::parse('crm.contact:update'));
        self::assertCount(2, $sources);
        self::assertSame(PermissionSourceType::Role, $sources[0]->type);
        self::assertSame(PermissionSourceType::Scope, $sources[1]->type);
        self::assertSame([], $set->sourcesOf(Permission::parse('crm.contact:delete')));
    }

    public function testSourcesOfIncludesWildcard(): void
    {
        $all = new PermissionSource(PermissionSourceType::Scope, '*');
        $set = new PermissionSet([], grantsAll: true, allSource: $all);
        self::assertSame([$all], $set->sourcesOf(Permission::parse('crm.contact:update')));
    }

    public function testGrantsAllRequiresSource(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PermissionSet([], grantsAll: true); // grantsAll without allSource is forbidden
    }
}
