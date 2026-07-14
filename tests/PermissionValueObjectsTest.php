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
use Milpa\Auth\PermissionContext;
use Milpa\Auth\PermissionSource;
use Milpa\Auth\PermissionSourceType;
use Milpa\Auth\Role;
use PHPUnit\Framework\TestCase;

final class PermissionValueObjectsTest extends TestCase
{
    public function testRoleHoldsPermissions(): void
    {
        $role = new Role('editor', 'Editor', [Permission::parse('crm.contact:update')]);
        self::assertSame('editor', $role->id);
        self::assertSame('Editor', $role->label);
        self::assertCount(1, $role->permissions);
    }

    public function testPermissionContextNoneIsAllNull(): void
    {
        $c = PermissionContext::none();
        self::assertNull($c->tenantId);
        self::assertNull($c->resourceType);
        self::assertNull($c->resourceId);
    }

    public function testPermissionContextCarriesRequestFacts(): void
    {
        $c = new PermissionContext(tenantId: 't1', resourceType: 'contact', resourceId: '77');
        self::assertSame('t1', $c->tenantId);
        self::assertSame('77', $c->resourceId);
    }

    public function testProvenance(): void
    {
        $g = new GrantedPermission(
            Permission::parse('crm.contact:update'),
            new PermissionSource(PermissionSourceType::Role, 'editor'),
        );
        self::assertSame('crm.contact:update', $g->permission->key());
        self::assertSame(PermissionSourceType::Role, $g->source->type);
        self::assertSame('editor', $g->source->id);
        self::assertSame('role', PermissionSourceType::Role->value);
        self::assertSame('scope', PermissionSourceType::Scope->value);
    }
}
