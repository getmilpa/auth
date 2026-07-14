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

namespace Milpa\Auth\Tests\Exceptions;

use Milpa\Auth\Exceptions\AuthMiddlewareNotInstalledException;
use Milpa\Auth\Exceptions\PermissionDeniedException;
use Milpa\Auth\Permission;
use PHPUnit\Framework\TestCase;

final class PermissionDeniedExceptionTest extends TestCase
{
    public function testForRequiredIs403AndNamesThePermission(): void
    {
        $e = PermissionDeniedException::forRequired(Permission::parse('crm.contact:update'));
        self::assertSame(403, $e->statusCode());
        self::assertSame('MILPA_PERMISSION_DENIED', $e->errorCode());
        self::assertStringContainsString('crm.contact:update', $e->getMessage());
        self::assertStringContainsString('academy.milpa.lat', $e->getMessage());
    }

    public function testForPermissionedOperationIs500(): void
    {
        $e = AuthMiddlewareNotInstalledException::forPermissionedOperation('crm.contact.update', 'crm.contact:update');
        self::assertSame(500, $e->statusCode());
        self::assertSame('MILPA_AUTH_MIDDLEWARE_NOT_INSTALLED', $e->errorCode());
        self::assertStringContainsString('crm.contact:update', $e->getMessage());
    }
}
