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

use Milpa\Auth\Exceptions\AuthContextMissingException;
use Milpa\Auth\Exceptions\AuthException;
use Milpa\Auth\Exceptions\CsrfDeniedException;
use Milpa\Auth\Exceptions\ScopeDeniedException;
use PHPUnit\Framework\TestCase;

final class AuthExceptionsTest extends TestCase
{
    private const ACADEMY = 'https://academy.milpa.lat/learn/fundamentos/politicas-explicitas';

    /** A secret that must never appear in any auth error surface. */
    private const LEAKY = 'super-visible-bearer-value-xyz';

    public function testEveryAuthExceptionIsThrowable(): void
    {
        foreach ($this->all() as $e) {
            $this->assertInstanceOf(AuthException::class, $e);
            $this->assertInstanceOf(\Throwable::class, $e);
        }
    }

    public function testScopeDeniedIsA403ThatTeachesWithTheRequiredScopes(): void
    {
        $e = ScopeDeniedException::forRequiredScopes(['posts:write', 'posts:admin']);

        $this->assertSame(403, $e->statusCode());
        $this->assertSame('MILPA_SCOPE_DENIED', $e->errorCode());
        $this->assertStringContainsString('MILPA_SCOPE_DENIED', $e->getMessage());
        $this->assertStringContainsString('posts:write', $e->getMessage());
        $this->assertStringContainsString(self::ACADEMY, $e->getMessage());
    }

    public function testAuthContextMissingNotAttachedIsA401ThatTeachesTheFix(): void
    {
        $e = AuthContextMissingException::notAttached();

        $this->assertSame(401, $e->statusCode());
        $this->assertSame('MILPA_AUTH_CONTEXT_MISSING', $e->errorCode());
        $this->assertStringContainsString('MILPA_AUTH_CONTEXT_MISSING', $e->getMessage());
        $this->assertStringContainsString('AuthenticateMiddleware', $e->getMessage());
        $this->assertStringContainsString(self::ACADEMY, $e->getMessage());
    }

    public function testAuthContextMissingUnauthenticatedIsA401(): void
    {
        $e = AuthContextMissingException::unauthenticated();

        $this->assertSame(401, $e->statusCode());
        $this->assertSame('MILPA_UNAUTHENTICATED', $e->errorCode());
        $this->assertStringContainsString('MILPA_UNAUTHENTICATED', $e->getMessage());
        $this->assertStringContainsString(self::ACADEMY, $e->getMessage());
    }

    public function testCsrfDeniedIsA403ThatTeachesTheFix(): void
    {
        $e = CsrfDeniedException::stateMismatch();

        $this->assertSame(403, $e->statusCode());
        $this->assertSame('MILPA_CSRF_DENIED', $e->errorCode());
        $this->assertStringContainsString('MILPA_CSRF_DENIED', $e->getMessage());
        $this->assertStringContainsString(self::ACADEMY, $e->getMessage());
    }

    public function testNoAuthExceptionEverCarriesASecret(): void
    {
        foreach ($this->all() as $e) {
            $this->assertStringNotContainsString(self::LEAKY, $e->getMessage());
            $this->assertStringNotContainsString(self::LEAKY, (string) $e);
        }
    }

    /**
     * @return list<AuthException>
     */
    private function all(): array
    {
        return [
            ScopeDeniedException::forRequiredScopes(['posts:write']),
            AuthContextMissingException::notAttached(),
            AuthContextMissingException::unauthenticated(),
            CsrfDeniedException::stateMismatch(),
        ];
    }
}
