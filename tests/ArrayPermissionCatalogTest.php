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

use Milpa\Auth\ArrayPermissionCatalog;
use Milpa\Auth\Contracts\PermissionCatalog;
use Milpa\Auth\Permission;
use Milpa\Auth\Role;
use PHPUnit\Framework\TestCase;

final class ArrayPermissionCatalogTest extends TestCase
{
    public function testRoleLookupAndUnknownIsNull(): void
    {
        $cat = new ArrayPermissionCatalog(
            [Permission::parse('crm.contact:update')],
            [new Role('editor', 'Editor', [Permission::parse('crm.contact:update')])],
        );
        self::assertInstanceOf(PermissionCatalog::class, $cat);
        self::assertNotNull($cat->role('editor'));
        self::assertSame('editor', $cat->role('editor')->id);
        self::assertNull($cat->role('nope'));
        self::assertCount(1, $cat->permissions());
        self::assertCount(1, $cat->roles());
    }

    public function testFromArrayParsesKeys(): void
    {
        $cat = ArrayPermissionCatalog::fromArray([
            'permissions' => ['crm.contact:read', 'crm.contact:update'],
            'roles' => [
                'editor' => ['label' => 'Editor', 'permissions' => ['crm.contact:update']],
                'viewer' => ['permissions' => ['crm.contact:read']],
            ],
        ]);
        self::assertCount(2, $cat->permissions());
        self::assertSame('Editor', $cat->role('editor')?->label);
        self::assertSame('viewer', $cat->role('viewer')?->label);   // label defaults to id
        self::assertSame('crm.contact:update', $cat->role('editor')->permissions[0]->key());
    }
}
