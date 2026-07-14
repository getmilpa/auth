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

use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\SessionRecord;
use PHPUnit\Framework\TestCase;

final class SessionRecordTest extends TestCase
{
    private function record(bool $revoked = false): SessionRecord
    {
        return new SessionRecord(
            id: 'sess-1',
            actorId: 'u-1',
            actorType: ActorType::User,
            createdAt: new \DateTimeImmutable('2026-01-01 00:00:00'),
            expiresAt: new \DateTimeImmutable('2026-01-01 01:00:00'),
            scopes: ['posts:read'],
            claims: ['email' => 'a@b.co'],
            revoked: $revoked,
        );
    }

    public function testIsExpiredWhenNowIsPastExpiry(): void
    {
        $this->assertTrue($this->record()->isExpired(new \DateTimeImmutable('2026-01-01 02:00:00')));
    }

    public function testIsNotExpiredBeforeExpiry(): void
    {
        $this->assertFalse($this->record()->isExpired(new \DateTimeImmutable('2026-01-01 00:30:00')));
    }

    public function testIsValidWhenNotExpiredAndNotRevoked(): void
    {
        $this->assertTrue($this->record()->isValid(new \DateTimeImmutable('2026-01-01 00:30:00')));
    }

    public function testIsInvalidWhenExpired(): void
    {
        $this->assertFalse($this->record()->isValid(new \DateTimeImmutable('2026-01-01 02:00:00')));
    }

    public function testIsInvalidWhenRevokedEvenBeforeExpiry(): void
    {
        $this->assertFalse($this->record(revoked: true)->isValid(new \DateTimeImmutable('2026-01-01 00:30:00')));
    }

    public function testToActorProjectsIdentityScopesAndClaims(): void
    {
        $actor = $this->record()->toActor();

        $this->assertInstanceOf(Actor::class, $actor);
        $this->assertSame('u-1', $actor->id);
        $this->assertSame(ActorType::User, $actor->type);
        $this->assertSame(['posts:read'], $actor->scopes);
        $this->assertSame(['email' => 'a@b.co'], $actor->claims);
        $this->assertTrue($actor->hasScope('posts:read'));
    }
}
