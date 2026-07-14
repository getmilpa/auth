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

use Milpa\Auth\Exceptions\AuthException;
use Milpa\Auth\Exceptions\AuthMiddlewareNotInstalledException;
use PHPUnit\Framework\TestCase;

/**
 * Pins Rod's binding architectural distinction: a scoped operation on a host with no auth chain is a
 * 500 (server misconfiguration), never a 401/403 (which would blame a blameless caller). The message
 * teaches the host how to fix it and never carries a secret.
 */
final class AuthMiddlewareNotInstalledExceptionTest extends TestCase
{
    private const ACADEMY = 'https://academy.milpa.lat/learn/fundamentos/politicas-explicitas';

    public function testItIsA500NotA401Or403(): void
    {
        $e = AuthMiddlewareNotInstalledException::forScopedOperation('create_post', ['posts:write']);

        $this->assertInstanceOf(AuthException::class, $e);
        $this->assertSame(500, $e->statusCode());
        $this->assertNotSame(401, $e->statusCode());
        $this->assertNotSame(403, $e->statusCode());
        $this->assertSame('MILPA_AUTH_MIDDLEWARE_NOT_INSTALLED', $e->errorCode());
    }

    public function testMessageNamesTheOperationScopesAndTheHostFixAndTeaches(): void
    {
        $e = AuthMiddlewareNotInstalledException::forScopedOperation('create_post', ['posts:write']);

        $this->assertStringContainsString('MILPA_AUTH_MIDDLEWARE_NOT_INSTALLED', $e->getMessage());
        $this->assertStringContainsString('create_post', $e->getMessage());
        $this->assertStringContainsString('posts:write', $e->getMessage());
        // It states this is a host/server error, not a caller error.
        $this->assertStringContainsString('CredentialVerifier', $e->getMessage());
        $this->assertStringContainsString('500', $e->getMessage());
        // Learnable links (may 404 until Academy ships).
        $this->assertStringContainsString(self::ACADEMY, $e->getMessage());
        $this->assertStringContainsString('http-scope-hole', $e->getMessage());
    }

    public function testMessageNeverLeaksASecret(): void
    {
        $leaky = 'super-visible-bearer-value-xyz';
        $e = AuthMiddlewareNotInstalledException::forScopedOperation($leaky, []);

        // The operation name is echoed (it is the developer's own label, not a secret), but there is
        // no credential surface here at all — and no credential value should ever appear.
        $this->assertStringNotContainsString('Bearer', $e->getMessage());
    }
}
