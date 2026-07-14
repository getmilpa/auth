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
use Milpa\Auth\AuthContext;
use Milpa\Auth\AuthState;
use PHPUnit\Framework\TestCase;

final class AuthContextTest extends TestCase
{
    public function testAnonymousHasNoActorAndTheAnonymousState(): void
    {
        $ctx = AuthContext::anonymous();

        $this->assertNull($ctx->actor);
        $this->assertSame(AuthState::Anonymous, $ctx->state);
        $this->assertFalse($ctx->isAuthenticated());
        $this->assertSame([], $ctx->metadata);
    }

    public function testAuthenticatedCarriesTheActorAndTheAuthenticatedState(): void
    {
        $actor = new Actor('u-1', ActorType::User, ['posts:read']);

        $ctx = AuthContext::authenticated($actor);

        $this->assertSame($actor, $ctx->actor);
        $this->assertSame(AuthState::Authenticated, $ctx->state);
        $this->assertTrue($ctx->isAuthenticated());
    }

    public function testInvalidHasNoActorTheInvalidStateAndTheReasonInMetadata(): void
    {
        $ctx = AuthContext::invalid('expired credential');

        $this->assertNull($ctx->actor);
        $this->assertSame(AuthState::Invalid, $ctx->state);
        $this->assertFalse($ctx->isAuthenticated());
        $this->assertSame('expired credential', $ctx->metadata['reason']);
    }

    public function testInvalidWithoutAReasonStillDeniesAndCarriesNoActor(): void
    {
        $ctx = AuthContext::invalid();

        $this->assertNull($ctx->actor);
        $this->assertSame(AuthState::Invalid, $ctx->state);
        $this->assertFalse($ctx->isAuthenticated());
    }

    public function testHasScopeDelegatesToTheActor(): void
    {
        $ctx = AuthContext::authenticated(new Actor('u-1', ActorType::User, ['posts:read']));

        $this->assertTrue($ctx->hasScope('posts:read'));
        $this->assertFalse($ctx->hasScope('posts:write'));
    }

    public function testHasScopeFailsClosedWhenThereIsNoActor(): void
    {
        $this->assertFalse(AuthContext::anonymous()->hasScope('posts:read'));
        $this->assertFalse(AuthContext::anonymous()->hasScope('*'));
        $this->assertFalse(AuthContext::invalid('nope')->hasScope('posts:read'));
    }

    public function testHasAnyScopeDelegatesAndFailsClosedWithoutAnActor(): void
    {
        $ctx = AuthContext::authenticated(new Actor('u-1', ActorType::User, ['posts:read']));

        $this->assertTrue($ctx->hasAnyScope(['nope', 'posts:read']));
        $this->assertFalse($ctx->hasAnyScope(['nope', 'nada']));
        $this->assertFalse(AuthContext::anonymous()->hasAnyScope(['posts:read']));
    }

    public function testMetadataIsCarriedWhenBuiltDirectly(): void
    {
        $ctx = new AuthContext(null, AuthState::Anonymous, ['ip' => '10.0.0.1']);

        $this->assertSame(['ip' => '10.0.0.1'], $ctx->metadata);
    }

    public function testAuthStateBackingValues(): void
    {
        $this->assertSame('anonymous', AuthState::Anonymous->value);
        $this->assertSame('authenticated', AuthState::Authenticated->value);
        $this->assertSame('invalid', AuthState::Invalid->value);
    }
}
