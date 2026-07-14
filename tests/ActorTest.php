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
use PHPUnit\Framework\TestCase;

final class ActorTest extends TestCase
{
    public function testCarriesItsIdentityVocabulary(): void
    {
        $actor = new Actor('u-1', ActorType::User, ['posts:read'], ['email' => 'a@b.co']);

        $this->assertSame('u-1', $actor->id);
        $this->assertSame(ActorType::User, $actor->type);
        $this->assertSame(['posts:read'], $actor->scopes);
        $this->assertSame(['email' => 'a@b.co'], $actor->claims);
    }

    public function testDefaultsToNoScopesAndNoClaims(): void
    {
        $actor = new Actor('svc-1', ActorType::Service);

        $this->assertSame([], $actor->scopes);
        $this->assertSame([], $actor->claims);
    }

    public function testHasScopeIsExactMatch(): void
    {
        $actor = new Actor('u-1', ActorType::User, ['posts:read', 'posts:write']);

        $this->assertTrue($actor->hasScope('posts:read'));
        $this->assertTrue($actor->hasScope('posts:write'));
    }

    public function testHasScopeFailsClosedForAnAbsentScope(): void
    {
        $actor = new Actor('u-1', ActorType::User, ['posts:read']);

        $this->assertFalse($actor->hasScope('posts:write'));
        $this->assertFalse($actor->hasScope('posts'));         // no prefix magic
        $this->assertFalse($actor->hasScope('posts:read:more')); // no suffix magic
    }

    public function testHasScopeWithNoScopesDeniesEverything(): void
    {
        $actor = new Actor('u-1', ActorType::User);

        $this->assertFalse($actor->hasScope('anything'));
    }

    public function testTheExplicitWildcardGrantsEveryScope(): void
    {
        $actor = new Actor('agent-1', ActorType::Agent, ['*']);

        $this->assertTrue($actor->hasScope('posts:read'));
        $this->assertTrue($actor->hasScope('literally-anything'));
    }

    public function testWildcardIsTheLiteralStarNotAPattern(): void
    {
        // 'posts:*' is NOT the wildcard — only the bare '*' is. No glob magic.
        $actor = new Actor('u-1', ActorType::User, ['posts:*']);

        $this->assertFalse($actor->hasScope('posts:read'));
        $this->assertTrue($actor->hasScope('posts:*')); // exact match still works
    }

    public function testHasAnyScopeIsTrueWhenAtLeastOneIsPresent(): void
    {
        $actor = new Actor('u-1', ActorType::User, ['posts:read']);

        $this->assertTrue($actor->hasAnyScope(['posts:write', 'posts:read']));
    }

    public function testHasAnyScopeFailsClosedWhenNonePresent(): void
    {
        $actor = new Actor('u-1', ActorType::User, ['posts:read']);

        $this->assertFalse($actor->hasAnyScope(['posts:write', 'posts:delete']));
    }

    public function testHasAnyScopeOfAnEmptyListDenies(): void
    {
        // Even a wildcarded actor is denied when asked for none of anything.
        $actor = new Actor('u-1', ActorType::User, ['*']);

        $this->assertFalse($actor->hasAnyScope([]));
    }

    public function testActorTypeBackingValues(): void
    {
        $this->assertSame('user', ActorType::User->value);
        $this->assertSame('agent', ActorType::Agent->value);
        $this->assertSame('service', ActorType::Service->value);
    }

    public function testRolesDefaultEmptyAndAppendedForBc(): void
    {
        $legacy = new Actor('u1', ActorType::User, ['posts:read'], ['email' => 'a@b.c']);
        self::assertSame([], $legacy->roles);                    // BC: existing 4-arg call still valid
        self::assertTrue($legacy->hasScope('posts:read'));       // BC: scopes untouched
    }

    public function testHasRoleExactMatch(): void
    {
        $actor = new Actor('u1', ActorType::User, roles: ['editor', 'viewer']);
        self::assertTrue($actor->hasRole('editor'));
        self::assertFalse($actor->hasRole('admin'));
    }
}
