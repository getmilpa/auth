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

use Milpa\Auth\ActorType;
use Milpa\Auth\AuthContext;
use Milpa\Auth\AuthState;
use Milpa\Auth\Http\StartSession;
use Milpa\Auth\InMemorySessionStore;
use Milpa\Auth\SessionRecord;
use Psr\Http\Message\ResponseInterface;

final class StartSessionTest extends HttpMiddlewareTestCase
{
    private const NOW = '2026-07-14T12:00:00+00:00';

    public function testAValidSessionCookieAttachesTheActorsAuthenticatedContext(): void
    {
        $store = $this->storeAt(self::NOW);
        $store->write($this->record('sess-1', expiresAt: '2026-07-14T13:00:00+00:00', scopes: ['posts:read']));
        $middleware = new StartSession($store);
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['cookies' => ['milpa_session' => 'sess-1']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertTrue($context->isAuthenticated());
        $this->assertSame('u-1', $context->actor?->id);
        $this->assertTrue($context->hasScope('posts:read'));
    }

    public function testNoSessionCookieLeavesAnAnonymousContext(): void
    {
        $middleware = new StartSession($this->storeAt(self::NOW));
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process($this->request(), $handler);

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Anonymous, $context->state);
    }

    public function testAnExpiredSessionLeavesAnAnonymousContext(): void
    {
        $store = $this->storeAt(self::NOW);
        $store->write($this->record('sess-1', expiresAt: '2026-07-14T11:00:00+00:00'));
        $middleware = new StartSession($store);
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['cookies' => ['milpa_session' => 'sess-1']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Anonymous, $context->state);
    }

    public function testARevokedSessionLeavesAnAnonymousContext(): void
    {
        $store = $this->storeAt(self::NOW);
        $store->write($this->record('sess-1', expiresAt: '2026-07-14T13:00:00+00:00', revoked: true));
        $middleware = new StartSession($store);
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['cookies' => ['milpa_session' => 'sess-1']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Anonymous, $context->state);
    }

    public function testAnUnknownSessionIdLeavesAnAnonymousContext(): void
    {
        $middleware = new StartSession($this->storeAt(self::NOW));
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['cookies' => ['milpa_session' => 'does-not-exist']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Anonymous, $context->state);
    }

    public function testTheCookieNameIsConfigurable(): void
    {
        $store = $this->storeAt(self::NOW);
        $store->write($this->record('sess-1', expiresAt: '2026-07-14T13:00:00+00:00'));
        $middleware = new StartSession($store, 'my_app_sid');
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['cookies' => ['my_app_sid' => 'sess-1']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertTrue($context->isAuthenticated());
    }

    private function storeAt(string $now): InMemorySessionStore
    {
        return new InMemorySessionStore(
            static fn (): \DateTimeImmutable => new \DateTimeImmutable($now),
        );
    }

    /**
     * @param list<string> $scopes
     */
    private function record(
        string $id,
        string $expiresAt,
        array $scopes = [],
        bool $revoked = false,
    ): SessionRecord {
        return new SessionRecord(
            $id,
            'u-1',
            ActorType::User,
            new \DateTimeImmutable('2026-07-14T10:00:00+00:00'),
            new \DateTimeImmutable($expiresAt),
            $scopes,
            [],
            $revoked,
        );
    }
}
