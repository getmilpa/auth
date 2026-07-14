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
use Milpa\Auth\Contracts\AuthContextFactory;
use Milpa\Auth\Contracts\CredentialVerifier;
use Milpa\Auth\Credential;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class ContractsTest extends TestCase
{
    public function testACredentialVerifierProducesAnAuthContext(): void
    {
        $verifier = new class () implements CredentialVerifier {
            public function verify(Credential $credential): AuthContext
            {
                return $credential->value() === 'good'
                    ? AuthContext::authenticated(new Actor('u-1', ActorType::User, ['*']))
                    : AuthContext::invalid('bad credential');
            }
        };

        $this->assertTrue($verifier->verify(Credential::bearer('good'))->isAuthenticated());
        $this->assertFalse($verifier->verify(Credential::bearer('bad'))->isAuthenticated());
    }

    public function testAnAuthContextFactoryReadsAServerRequest(): void
    {
        $factory = new class () implements AuthContextFactory {
            public function fromRequest(ServerRequestInterface $request): AuthContext
            {
                $header = $request->getHeaderLine('Authorization');
                if (!str_starts_with($header, 'Bearer ')) {
                    return AuthContext::anonymous();
                }

                return AuthContext::authenticated(new Actor('u-1', ActorType::User));
            }
        };

        $anonymous = $this->createMock(ServerRequestInterface::class);
        $anonymous->method('getHeaderLine')->willReturn('');
        $this->assertFalse($factory->fromRequest($anonymous)->isAuthenticated());

        $authenticated = $this->createMock(ServerRequestInterface::class);
        $authenticated->method('getHeaderLine')->willReturn('Bearer xyz');
        $this->assertTrue($factory->fromRequest($authenticated)->isAuthenticated());
    }
}
