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

namespace Milpa\Auth\Tests\Http;

use Milpa\Auth\Exceptions\CsrfDeniedException;
use Milpa\Auth\Http\CsrfGuard;
use Psr\Http\Message\ResponseInterface;

final class CsrfGuardTest extends HttpMiddlewareTestCase
{
    private const STATE = 'issued-state-token-value-abc';

    public function testAMatchingStateInTheBodyPasses(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $guard = new CsrfGuard('milpa_csrf', 'csrf');
        $handler = $this->handler($response);

        $result = $guard->process(
            $this->request([
                'method' => 'POST',
                'cookies' => ['milpa_csrf' => self::STATE],
                'parsedBody' => ['csrf' => self::STATE],
            ]),
            $handler,
        );

        $this->assertSame($response, $result);
    }

    public function testAMatchingStateInTheHeaderPasses(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $guard = new CsrfGuard('milpa_csrf', 'X-Csrf-Token');
        $handler = $this->handler($response);

        $result = $guard->process(
            $this->request([
                'method' => 'POST',
                'cookies' => ['milpa_csrf' => self::STATE],
                'headers' => ['X-Csrf-Token' => self::STATE],
            ]),
            $handler,
        );

        $this->assertSame($response, $result);
    }

    public function testAMismatchedStateIsDenied(): void
    {
        $guard = new CsrfGuard('milpa_csrf', 'csrf');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        try {
            $guard->process(
                $this->request([
                    'method' => 'POST',
                    'cookies' => ['milpa_csrf' => self::STATE],
                    'parsedBody' => ['csrf' => 'a-different-token-value'],
                ]),
                $handler,
            );
            $this->fail('expected CsrfDeniedException');
        } catch (CsrfDeniedException $e) {
            $this->assertSame(403, $e->statusCode());
            $this->assertSame('MILPA_CSRF_DENIED', $e->errorCode());
        }

        $this->assertNull($handler->received, 'a denied request must not reach the handler');
    }

    public function testAnAbsentSubmittedStateIsDenied(): void
    {
        $guard = new CsrfGuard('milpa_csrf', 'csrf');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $this->expectException(CsrfDeniedException::class);
        $guard->process(
            $this->request([
                'method' => 'POST',
                'cookies' => ['milpa_csrf' => self::STATE],
            ]),
            $handler,
        );
    }

    public function testAnAbsentStateCookieIsDenied(): void
    {
        $guard = new CsrfGuard('milpa_csrf', 'csrf');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $this->expectException(CsrfDeniedException::class);
        $guard->process(
            $this->request([
                'method' => 'POST',
                'parsedBody' => ['csrf' => self::STATE],
            ]),
            $handler,
        );
    }

    public function testASafeMethodIsNotStateChecked(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $guard = new CsrfGuard('milpa_csrf', 'csrf');
        $handler = $this->handler($response);

        $result = $guard->process(
            $this->request(['method' => 'GET']),
            $handler,
        );

        $this->assertSame($response, $result);
    }

    public function testTheComparisonIsTimingSafe(): void
    {
        $source = (string) file_get_contents(
            \dirname(__DIR__, 2) . '/src/Http/CsrfGuard.php',
        );

        $this->assertStringContainsString('hash_equals', $source);
    }
}
