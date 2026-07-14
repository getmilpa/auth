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
use Milpa\Auth\AuthState;
use Milpa\Auth\Contracts\CredentialVerifier;
use Milpa\Auth\Credential;
use Milpa\Auth\Http\AuthenticateMiddleware;
use Psr\Http\Message\ResponseInterface;

final class AuthenticateMiddlewareTest extends HttpMiddlewareTestCase
{
    private const RAW_BEARER = 'visible-bearer-value-abc123';

    public function testAValidBearerTokenAttachesTheAuthenticatedContext(): void
    {
        $middleware = new AuthenticateMiddleware($this->verifierAccepting(self::RAW_BEARER));
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['headers' => ['Authorization' => 'Bearer ' . self::RAW_BEARER]]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertTrue($context->isAuthenticated());
    }

    public function testAMissingCredentialLeavesAnAnonymousContextAndNeverThrows(): void
    {
        $middleware = new AuthenticateMiddleware($this->verifierThatMustNotBeCalled());
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process($this->request(), $handler);

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Anonymous, $context->state);
    }

    public function testARejectedCredentialAttachesTheInvalidContext(): void
    {
        $middleware = new AuthenticateMiddleware($this->verifierRejecting());
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['headers' => ['Authorization' => 'Bearer whatever-token-value']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Invalid, $context->state);
        $this->assertFalse($context->isAuthenticated());
    }

    public function testABlankBearerHeaderIsTreatedAsNoCredential(): void
    {
        $middleware = new AuthenticateMiddleware($this->verifierThatMustNotBeCalled());
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['headers' => ['Authorization' => 'Bearer ']]),
            $handler,
        );

        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertSame(AuthState::Anonymous, $context->state);
    }

    public function testTheMiddlewareWrapsTheSecretAndNeverLeaksItRaw(): void
    {
        $spy = new class () implements CredentialVerifier {
            public ?Credential $seen = null;

            public function verify(Credential $credential): AuthContext
            {
                $this->seen = $credential;

                return AuthContext::authenticated(new Actor('u-1', ActorType::User, ['*']));
            }
        };

        $middleware = new AuthenticateMiddleware($spy);
        $handler = $this->handler($this->createMock(ResponseInterface::class));

        $middleware->process(
            $this->request(['headers' => ['Authorization' => 'Bearer ' . self::RAW_BEARER]]),
            $handler,
        );

        // The middleware handed the verifier a Credential (never a raw string) ...
        $this->assertInstanceOf(Credential::class, $spy->seen);
        $this->assertSame(self::RAW_BEARER, $spy->seen->value());
        // ... and that Credential redacts itself, so a dump of it cannot leak the secret.
        $this->assertStringNotContainsString(self::RAW_BEARER, print_r($spy->seen, true));

        // The context the middleware attaches carries no trace of the raw token either.
        $context = $handler->received?->getAttribute('milpa.auth');
        $this->assertInstanceOf(AuthContext::class, $context);
        $this->assertStringNotContainsString(self::RAW_BEARER, (string) json_encode($context->metadata));
    }

    private function verifierAccepting(string $expected): CredentialVerifier
    {
        return new class ($expected) implements CredentialVerifier {
            public function __construct(private readonly string $expected)
            {
            }

            public function verify(Credential $credential): AuthContext
            {
                return $credential->value() === $this->expected
                    ? AuthContext::authenticated(new Actor('u-1', ActorType::User, ['*']))
                    : AuthContext::invalid('unexpected credential');
            }
        };
    }

    private function verifierRejecting(): CredentialVerifier
    {
        return new class () implements CredentialVerifier {
            public function verify(Credential $credential): AuthContext
            {
                return AuthContext::invalid('rejected');
            }
        };
    }

    private function verifierThatMustNotBeCalled(): CredentialVerifier
    {
        return new class () implements CredentialVerifier {
            public function verify(Credential $credential): AuthContext
            {
                throw new \LogicException('the verifier must not be called without a Bearer credential');
            }
        };
    }
}
