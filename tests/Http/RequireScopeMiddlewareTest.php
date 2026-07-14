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

use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\AuthContext;
use Milpa\Auth\Exceptions\AuthContextMissingException;
use Milpa\Auth\Exceptions\ScopeDeniedException;
use Milpa\Auth\Http\RequireScopeMiddleware;
use Psr\Http\Message\ResponseInterface;

final class RequireScopeMiddlewareTest extends HttpMiddlewareTestCase
{
    public function testAMissingAuthContextAttributeIsA401(): void
    {
        $middleware = new RequireScopeMiddleware('posts:write');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        try {
            $middleware->process($this->request(), $handler);
            $this->fail('expected AuthContextMissingException');
        } catch (AuthContextMissingException $e) {
            $this->assertSame(401, $e->statusCode());
            $this->assertSame('MILPA_AUTH_CONTEXT_MISSING', $e->errorCode());
        }

        $this->assertNull($handler->received, 'the pipeline must not continue on a fail-closed denial');
    }

    public function testAnAnonymousContextIsA401(): void
    {
        $middleware = new RequireScopeMiddleware('posts:write');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        try {
            $middleware->process(
                $this->request(['attributes' => ['milpa.auth' => AuthContext::anonymous()]]),
                $handler,
            );
            $this->fail('expected AuthContextMissingException');
        } catch (AuthContextMissingException $e) {
            $this->assertSame(401, $e->statusCode());
            $this->assertSame('MILPA_UNAUTHENTICATED', $e->errorCode());
        }

        $this->assertNull($handler->received);
    }

    public function testAnInvalidContextIsA401(): void
    {
        $middleware = new RequireScopeMiddleware('posts:write');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $this->expectException(AuthContextMissingException::class);
        $middleware->process(
            $this->request(['attributes' => ['milpa.auth' => AuthContext::invalid('bad token')]]),
            $handler,
        );
    }

    public function testAnAuthenticatedActorWithoutTheScopeIsA403(): void
    {
        $middleware = new RequireScopeMiddleware('posts:write');
        $handler = $this->handler($this->createMock(ResponseInterface::class));
        $context = AuthContext::authenticated(new Actor('u-1', ActorType::User, ['posts:read']));

        try {
            $middleware->process(
                $this->request(['attributes' => ['milpa.auth' => $context]]),
                $handler,
            );
            $this->fail('expected ScopeDeniedException');
        } catch (ScopeDeniedException $e) {
            $this->assertSame(403, $e->statusCode());
            $this->assertSame('MILPA_SCOPE_DENIED', $e->errorCode());
        }

        $this->assertNull($handler->received);
    }

    public function testAnAuthenticatedActorHoldingAnyRequiredScopePassesThrough(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $middleware = new RequireScopeMiddleware('posts:write', 'posts:admin');
        $handler = $this->handler($response);
        $context = AuthContext::authenticated(new Actor('u-1', ActorType::User, ['posts:admin']));

        $result = $middleware->process(
            $this->request(['attributes' => ['milpa.auth' => $context]]),
            $handler,
        );

        $this->assertSame($response, $result);
        $this->assertNotNull($handler->received);
    }

    public function testTheWildcardScopeSatisfiesTheGuard(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $middleware = new RequireScopeMiddleware('posts:write');
        $handler = $this->handler($response);
        $context = AuthContext::authenticated(new Actor('svc-1', ActorType::Service, ['*']));

        $result = $middleware->process(
            $this->request(['attributes' => ['milpa.auth' => $context]]),
            $handler,
        );

        $this->assertSame($response, $result);
    }
}
