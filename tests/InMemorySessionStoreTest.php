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

use Milpa\Auth\ActorType;
use Milpa\Auth\InMemorySessionStore;
use Milpa\Auth\SessionRecord;
use PHPUnit\Framework\TestCase;

final class InMemorySessionStoreTest extends TestCase
{
    private function store(string $now = '2026-01-01 00:00:00'): InMemorySessionStore
    {
        $clock = new \DateTimeImmutable($now);

        return new InMemorySessionStore(static fn (): \DateTimeImmutable => $clock);
    }

    private function record(string $id, string $expiresAt, bool $revoked = false): SessionRecord
    {
        return new SessionRecord(
            id: $id,
            actorId: 'u-1',
            actorType: ActorType::User,
            createdAt: new \DateTimeImmutable('2026-01-01 00:00:00'),
            expiresAt: new \DateTimeImmutable($expiresAt),
            scopes: ['posts:read'],
            revoked: $revoked,
        );
    }

    public function testWriteThenReadRoundTrips(): void
    {
        $store = $this->store();
        $store->write($this->record('sess-1', '2026-01-01 01:00:00'));

        $read = $store->read('sess-1');

        $this->assertNotNull($read);
        $this->assertSame('sess-1', $read->id);
        $this->assertSame('u-1', $read->actorId);
        $this->assertSame(ActorType::User, $read->actorType);
        $this->assertSame(['posts:read'], $read->scopes);
    }

    public function testReadOfAnAbsentSessionReturnsNull(): void
    {
        $this->assertNull($this->store()->read('nope'));
    }

    public function testReadFailsClosedForAnExpiredSession(): void
    {
        // The clock is at 02:00 — the record expired at 01:00.
        $store = $this->store('2026-01-01 02:00:00');
        $store->write($this->record('sess-1', '2026-01-01 01:00:00'));

        $this->assertNull($store->read('sess-1'));
    }

    public function testReadFailsClosedForARevokedSession(): void
    {
        $store = $this->store();
        $store->write($this->record('sess-1', '2026-01-01 01:00:00', revoked: true));

        $this->assertNull($store->read('sess-1'));
    }

    public function testDestroyRemovesTheSession(): void
    {
        $store = $this->store();
        $store->write($this->record('sess-1', '2026-01-01 01:00:00'));
        $this->assertNotNull($store->read('sess-1'));

        $store->destroy('sess-1');

        $this->assertNull($store->read('sess-1'));
    }

    public function testDestroyOfAnAbsentSessionIsANoOp(): void
    {
        $store = $this->store();

        $store->destroy('nope'); // must not throw

        $this->assertNull($store->read('nope'));
    }

    public function testTheDefaultClockUsesWallTimeWhenNoneIsInjected(): void
    {
        $store = new InMemorySessionStore();
        // Expires far in the future, so it is readable regardless of the wall clock.
        $store->write($this->record('sess-1', '2999-01-01 00:00:00'));

        $this->assertNotNull($store->read('sess-1'));
    }
}
