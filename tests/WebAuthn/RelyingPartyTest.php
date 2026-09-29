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

namespace Milpa\Auth\Tests\WebAuthn;

use Milpa\Auth\WebAuthn\CeremonyType;
use Milpa\Auth\WebAuthn\RelyingParty;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RelyingPartyTest extends TestCase
{
    public function testHoldsIdNameOrigins(): void
    {
        $rp = new RelyingParty('acme.example', 'Acme', ['https://app.acme.example']);
        self::assertSame('acme.example', $rp->id);
        self::assertSame('Acme', $rp->name);
        self::assertContains('https://app.acme.example', $rp->allowedOrigins);
    }

    public function testAnOriginIsAllowedOnlyByExactMatch(): void
    {
        $rp = new RelyingParty('acme.example', 'Acme', ['https://app.acme.example']);

        self::assertTrue($rp->allowsOrigin('https://app.acme.example'));
        self::assertFalse($rp->allowsOrigin('https://acme.example'), 'another origin of the same rpId is not implied');
        self::assertFalse($rp->allowsOrigin('https://app.acme.example.evil.example'));
        self::assertFalse($rp->allowsOrigin('http://app.acme.example'));
        self::assertFalse($rp->allowsOrigin('https://app.acme.example/'));
    }

    public function testLoopbackMayBeServedOverHttp(): void
    {
        $rp = new RelyingParty('localhost', 'Dev', ['http://localhost:8080']);

        self::assertTrue($rp->allowsOrigin('http://localhost:8080'));
    }

    /**
     * A relying party that cannot name where its ceremonies run must not be constructible: a verifier
     * handed one would otherwise have no origin to hold the ceremony to.
     *
     * @param list<string> $origins
     */
    #[DataProvider('misconfigurations')]
    public function testAMisconfiguredRelyingPartyRefusesToExist(string $id, array $origins, string $because): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches($because);

        new RelyingParty($id, 'Acme', $origins);
    }

    /** @return iterable<string, array{0: string, 1: list<string>, 2: string}> */
    public static function misconfigurations(): iterable
    {
        yield 'no rpId' => ['', ['https://acme.example'], '/id/'];
        yield 'no origins' => ['acme.example', [], '/allowedOrigins/'];
        yield 'plain http' => ['acme.example', ['http://acme.example'], '/https/'];
        yield 'a path' => ['acme.example', ['https://acme.example/login'], '/origin/'];
        yield 'a trailing slash' => ['acme.example', ['https://acme.example/'], '/origin/'];
        yield 'a wildcard' => ['acme.example', ['https://*.acme.example'], '/origin/'];
        yield 'another site' => ['acme.example', ['https://evil.example'], '/acme\\.example/'];
        yield 'a suffix that is not a subdomain' => ['acme.example', ['https://notacme.example'], '/acme\\.example/'];
        yield 'not a string' => ['acme.example', [42], '/origin/'];
    }

    public function testCeremonyType(): void
    {
        self::assertSame('registration', CeremonyType::Registration->value);
        self::assertSame('authentication', CeremonyType::Authentication->value);
    }
}
