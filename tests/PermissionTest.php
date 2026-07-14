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

use Milpa\Auth\Permission;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PermissionTest extends TestCase
{
    /** @return list<array{string, ?string, string, string}> key, namespace, resource, action */
    public static function validKeys(): array
    {
        return [
            ['crm.contact:create', 'crm', 'contact', 'create'],
            ['loan.payment:record', 'loan', 'payment', 'record'],
            ['shoppy.cash-closing:approve', 'shoppy', 'cash-closing', 'approve'],
            ['posts:read', null, 'posts', 'read'],
            ['acme.crm.contact:delete', 'acme.crm', 'contact', 'delete'],
        ];
    }

    #[DataProvider('validKeys')]
    public function testParseExtractsSegments(string $key, ?string $ns, string $res, string $act): void
    {
        $p = Permission::parse($key);
        self::assertSame($ns, $p->namespace);
        self::assertSame($res, $p->resource);
        self::assertSame($act, $p->action);
    }

    #[DataProvider('validKeys')]
    public function testRoundTrip(string $key): void
    {
        self::assertSame($key, Permission::parse($key)->key());
    }

    public function testConstructedRoundTrip(): void
    {
        $p = Permission::of('contact', 'create', 'crm');
        self::assertEquals($p, Permission::parse($p->key()));
    }

    /** @return list<array{string}> */
    public static function malformedKeys(): array
    {
        return [['nocolon'], ['posts:'], [':read'], ['*'], ['a:b:c'], ['crm.:read'], ['.contact:read']];
    }

    #[DataProvider('malformedKeys')]
    public function testParseRejectsMalformed(string $key): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Permission::parse($key);
    }

    public function testEqualsByKey(): void
    {
        self::assertTrue(Permission::of('contact', 'read', 'crm')->equals(Permission::parse('crm.contact:read')));
        self::assertFalse(Permission::of('contact', 'read', 'crm')->equals(Permission::of('contact', 'write', 'crm')));
    }
}
